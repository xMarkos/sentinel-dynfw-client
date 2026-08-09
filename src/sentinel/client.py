import logging
import os
import time
import typing
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum

import msgspec
import zmq
import zmq.auth
from zmq.utils.monitor import recv_monitor_message

SENTINEL_PUB_CERT_URL = "https://repo.turris.cz/sentinel/dynfw.pub"
SENTINEL_SERVER_ADDRESS = 'sentinel.turris.cz'
SENTINEL_SERVER_PORT = 7087

TYPE_MSG_DELTA = 'dynfw/delta'
TYPE_MSG_FULL = 'dynfw/list'

_logger = logging.getLogger(__name__)


def create_zmq_certificate(dir_path: str) -> tuple[bytes, bytes]:
	if not os.path.exists(dir_path):
		os.mkdir(dir_path, mode=0o750)
	_, secret_file = zmq.auth.create_certificates(dir_path, "client")
	public_key, secret_key = zmq.auth.load_certificate(secret_file)
	return public_key, typing.cast(bytes, secret_key)


def download_server_certificate(cert_url: str, dir_path: str):
	#notify_systemd_status('Downloading server certificate...')
	delay = 1
	cert_file = None
	while True:
		try:
			with urllib.request.urlopen(cert_url, timeout=10) as req:
				cert_file = os.path.join(dir_path, os.path.basename(req.url))
				with open(cert_file, 'wb') as f:
					f.write(req.read())
			break
		except urllib.error.URLError as ex:
			delay = min(delay * 2, 120)    # At maximum we wait for two minutes to try again
			_logger.warning('Unable to download server certificate (%s), retrying in %d seconds...', ex.reason, delay)

			time.sleep(delay)

	_logger.debug('Server certificate was downloaded')

	return zmq.auth.load_certificate(cert_file)


def parse_msg(data: list[bytes]):
	try:
		msg_type = str(data[0], encoding="UTF-8")
		payload = data[1]

		if msg_type == TYPE_MSG_DELTA:
			return msg_type, _msg_decoder_delta.decode(payload)
		elif msg_type == TYPE_MSG_FULL:
			return msg_type, _msg_decoder_full.decode(payload)
		else:
			return msg_type, _msg_decoder_unknown.decode(payload)

	except IndexError:
		raise InvalidMsgError("Not enough parts in message")
	except Exception as ex:
		raise InvalidMsgError("Parse error") from ex


class InvalidMsgError(Exception):
	pass


class DeltaDirection(Enum):
	Positive = 'positive'
	Negative = 'negative'


@dataclass
class DynfwListBase:
	ts: int
	serial: int


@dataclass
class DynfwDelta(DynfwListBase):
	delta: DeltaDirection
	ip: str


@dataclass
class DynfwFullList(DynfwListBase):
	version: int
	list: list[str]


_msg_decoder_delta = msgspec.msgpack.Decoder(DynfwDelta)
_msg_decoder_full = msgspec.msgpack.Decoder(DynfwFullList)
_msg_decoder_unknown = msgspec.msgpack.Decoder()


class ZmqSentinelClient:
	__logger = logging.getLogger(__qualname__)

	def __init__(self, uri: str, server_public_key: bytes, client_public_key: bytes, client_secret_key: bytes) -> None:
		self._uri = uri
		self._socket, self._ctx = self._create_socket(server_public_key, client_public_key, client_secret_key)

	def _create_socket(self, server_public_key: bytes, client_public_key: bytes, client_secret_key: bytes):
		ctx = zmq.Context()
		ctx.setsockopt(zmq.CONNECT_TIMEOUT, 1000 * 5)    # Milliseconds (5 seconds)
		ctx.setsockopt(zmq.RECONNECT_IVL, 100)
		ctx.setsockopt(zmq.RECONNECT_IVL_MAX, 1000 * 60)    # Reduces reconnect spam on connection drop
		ctx.setsockopt(zmq.HEARTBEAT_IVL, 1000 * 60)    # 1 minute
		ctx.setsockopt(zmq.HEARTBEAT_TIMEOUT, 1000 * 15)    # 15 seconds
		ctx.setsockopt(zmq.IPV6, True)
		ctx.setsockopt(zmq.LINGER, 0)
		ctx.setsockopt(zmq.RCVHWM, 0)
		ctx.setsockopt(zmq.TCP_KEEPALIVE, True)
		ctx.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 120)    # Seconds (2 minutes)
		ctx.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)    # 3 retries
		ctx.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 5)    # 5 seconds

		socket = ctx.socket(zmq.SUB)
		socket.curve_secretkey = client_secret_key
		socket.curve_publickey = client_public_key
		socket.curve_serverkey = server_public_key
		return socket, ctx

	def start(self):
		monitor_socket = self._socket.get_monitor_socket()

		zmq_event_types = {value: name for name, value in vars(zmq).items() if name.startswith('EVENT_')}

		poller = zmq.Poller()
		poller.register(self._socket, zmq.POLLIN)
		poller.register(monitor_socket, zmq.POLLIN)

		ctx = self._socket.connect(self._uri)

		try:
			ctx.socket.subscribe(TYPE_MSG_DELTA)

			need_full_list = False
			serial = 0

			while True:
				events = dict(poller.poll(0))
				if not len(events):
					yield None, None
					continue

				if monitor_socket in events:
					m = recv_monitor_message(monitor_socket, zmq.NOBLOCK)
					event_name = zmq_event_types.get(m['event'], None) or f"UNKNOWN_EVENT_{m['event']}"
					self.__logger.info('Monitor: %s: %s', event_name, m['value'])
					continue

				try:
					if ctx.socket in events:
						msg = ctx.socket.recv_multipart()
						msg_type, payload = parse_msg(msg)

						if not need_full_list and isinstance(payload, DynfwListBase) and payload.serial != serial + 1:
							# There are missing updates -> get full list
							need_full_list = True
							self.__logger.info('Subscribing to %s; serial: %d -> %d', TYPE_MSG_FULL, serial, payload.serial)
							ctx.socket.subscribe(TYPE_MSG_FULL)

						# Read 1 full message and then only deltas
						if (need_full_list and msg_type == TYPE_MSG_DELTA) or (not need_full_list and msg_type == TYPE_MSG_FULL):
							continue

						if msg_type == TYPE_MSG_FULL:
							need_full_list = False
							self.__logger.info('Received full update -> unsubscribing %s', TYPE_MSG_FULL)
							ctx.socket.unsubscribe(TYPE_MSG_FULL)

						if isinstance(payload, DynfwListBase):
							serial = payload.serial

						yield msg_type, payload
				except InvalidMsgError:
					self.__logger.error('Incoming message error', exc_info=True)
					continue
		except GeneratorExit:
			self.__logger.info('Exiting receiver loop')
			pass
		finally:
			monitor_socket.close()
			ctx.socket.disable_monitor()
			ctx.socket.close()
			self._ctx.term()
