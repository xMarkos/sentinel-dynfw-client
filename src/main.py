import logging
import logging.handlers
import time
from typing import Iterable

from net import DummyFirewallProxy, FirewallProxy, parse_address
from net.nftables import NftablesFirewallProxy
from sentinel.client import (SENTINEL_PUB_CERT_URL, SENTINEL_SERVER_ADDRESS, SENTINEL_SERVER_PORT, DeltaDirection, DynfwDelta, DynfwFullList, DynfwListBase,
                             ZmqSentinelClient, create_zmq_certificate, download_server_certificate)


def parse_addresses(addresses: Iterable[str], expand_v6_prefix: int | None = None):
	for address in addresses:
		_, _, a = parse_address(address, expand_v6_prefix=expand_v6_prefix)
		if a is not None:
			yield a


def main(client: ZmqSentinelClient, fw: FirewallProxy, *, keep_on_exit=False, expand_ipv6_prefix: int | None = None):
	fw.init_firewall(drop_existing=True)

	g = client.start()
	try:
		while True:
			msg_type, payload = next(g)
			if msg_type is None:
				#_logger.debug('No message -> retry')
				time.sleep(0.25)
				continue

			if isinstance(payload, DynfwListBase):
				if isinstance(payload, DynfwFullList):
					fw.set_entries(parse_addresses(payload.list, expand_ipv6_prefix))
				elif isinstance(payload, DynfwDelta):
					if payload.delta == DeltaDirection.Positive:
						fw.add_entries(parse_addresses([payload.ip], expand_ipv6_prefix))
					elif payload.delta == DeltaDirection.Negative:
						fw.remove_entries(parse_addresses([payload.ip], expand_ipv6_prefix))
			else:
				logging.debug('Unhandled message type=%s pytype=%s payload=%s', msg_type, type(payload), payload)

	except KeyboardInterrupt:
		logging.info('Received CTRL+C -> cleaning-up')
	finally:
		# Note that clean-up happens only on SIGINT, so make sure that systemd service uses it to stop the service.
		# It's possible to use signal handlers to catch others, but there doesn't seem to be a reason to justify it.
		g.close()

		if not keep_on_exit:
			fw.cleanup()


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
	    description='Turris::Sentinel Dynamic Firewall Client',
	    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)
	parser.add_argument('-s', '--server', default=SENTINEL_SERVER_ADDRESS, help='Server address')
	parser.add_argument('-p', '--port', type=int, default=SENTINEL_SERVER_PORT, help='Server port')
	parser.add_argument('--cache-dir', default='/run/sentinel-fw', help='Path to the directory where certificates are stored', metavar='PATH')
	parser.add_argument('--cert-url', default=SENTINEL_PUB_CERT_URL, help='URL to retrieve server certificate from', metavar='URL')
	parser.add_argument('--backend', choices=['nftables', 'dummy'], default='nftables', help='Firewall backend')
	parser.add_argument('--nft-table', default='inet sentinel', help='Table name (<type> <name>) [nftables only]', metavar='TABLE')
	parser.add_argument('--ipset4', default='dynfw-block-v4', help='IP set name to push blocked IPv4s to', metavar='NAME')
	parser.add_argument('--ipset6', default='dynfw-block-v6', help='IP set name to push blocked IPv6s to', metavar='NAME')
	parser.add_argument('--expand-ipv6-prefix', type=int, default=64, help='Expand prefix of IPv6 addresses to block larger scale', metavar='LENGTH')
	parser.add_argument('--syslog', action='store_true', help='Send log message to syslog')
	parser.add_argument('--keep-on-exit', action='store_true', help='Keeps entries when this program exits')
	parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
	args = parser.parse_args()

	if args.syslog:
		handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_DAEMON)
		handler.ident = 'sentinel-fw: '
		format_str = '%(name)s: %(message)s'
	else:
		handler = logging.StreamHandler()
		format_str = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'

	logging.basicConfig(
	    level=logging.DEBUG if args.verbose else logging.INFO,
	    format=format_str,
	    handlers=(handler, ),
	)

	client_pub, client_secret = create_zmq_certificate(args.cache_dir)
	server_pub, _ = download_server_certificate(args.cert_url, args.cache_dir)

	client = ZmqSentinelClient(f'tcp://{args.server}:{args.port}', server_pub, client_pub, client_secret)

	if args.backend == 'nftables':
		fw = NftablesFirewallProxy(table=args.nft_table, ipset_v4=args.ipset4, ipset_v6=args.ipset6)
	elif args.backend == 'dummy':
		fw = DummyFirewallProxy()
	else:
		raise ValueError(f'Invalid firewall backend: {args.backend}')

	main(client, fw, keep_on_exit=args.keep_on_exit, expand_ipv6_prefix=args.expand_ipv6_prefix)
