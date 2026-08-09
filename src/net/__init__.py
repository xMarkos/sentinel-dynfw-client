import enum
import logging
import typing
import warnings
from ipaddress import (IPv4Network, IPv6Network, _BaseAddress, _BaseV4, _BaseV6, _IPAddressBase)


class IpAddressVersion(enum.Enum):
	Unknown = 0
	IPv4 = 4
	IPv6 = 6


class IpAddressType(enum.Enum):
	Unknown = enum.auto()
	Address = enum.auto()
	Network = enum.auto()


def classify_address(address: _IPAddressBase) -> typing.Tuple[IpAddressVersion, IpAddressType, _IPAddressBase]:
	v = IpAddressVersion(address.version) if isinstance(address, (_BaseV4, _BaseV6)) else IpAddressVersion.Unknown
	t = IpAddressType.Address if isinstance(address, _BaseAddress) else IpAddressType.Network
	return v, t, address


def parse_address(
    address: str | bytes | int,
    *,
    expand_v6_prefix: int | None = None,
) -> typing.Tuple[IpAddressVersion, IpAddressType, _IPAddressBase | None]:

	try:
		result = IPv6Network(address, False)
		if expand_v6_prefix and expand_v6_prefix < result.prefixlen:
			result = IPv6Network((result.network_address.compressed, expand_v6_prefix), False)
		elif result.prefixlen == result.max_prefixlen:
			result = result.network_address

		return classify_address(result)
	except:
		pass

	try:
		result = IPv4Network(address, False)
		if result.prefixlen == result.max_prefixlen:
			result = result.network_address

		return classify_address(result)
	except:
		pass

	return IpAddressVersion.Unknown, IpAddressType.Unknown, None


class FirewallProxy(typing.Protocol):

	def init_firewall(self, **kwargs):
		...

	def cleanup(self):
		...

	def add_entries(self, entries: typing.Iterable[_IPAddressBase]):
		...

	def remove_entries(self, entries: typing.Iterable[_IPAddressBase]):
		...

	def set_entries(self, entries: typing.Iterable[_IPAddressBase]):
		...


class DummyFirewallProxy:

	__logger = logging.getLogger(__qualname__)

	def init_firewall(self, **kwargs):
		if len(kwargs):
			warnings.warn(f'Unknown kwargs: {', '.join(kwargs.keys())}', stacklevel=2)

		self.__logger.info('init_firewall()')

	def cleanup(self):
		self.__logger.info('cleanup()')

	def add_entries(self, entries: typing.Iterable[_IPAddressBase]):
		self.__logger.info('add_entries(%d)', len([*entries]))

	def remove_entries(self, entries: typing.Iterable[_IPAddressBase]):
		self.__logger.info('remove_entries(%d)', len([*entries]))

	def set_entries(self, entries: typing.Iterable[_IPAddressBase]):
		self.__logger.info('set_entries(%d)', len([*entries]))
