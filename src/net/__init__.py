import enum
import ipaddress
import logging
import typing
import warnings

__all__ = ['IpAddressVersion', 'IpAddressType', 'is_v4_address', 'is_v6_address', 'classify_address', 'parse_address', 'FirewallProxy', 'DummyFirewallProxy']


class IpAddressVersion(enum.Enum):
	Unknown = 0
	IPv4 = 4
	IPv6 = 6


class IpAddressType(enum.Enum):
	Unknown = enum.auto()
	Address = enum.auto()
	Network = enum.auto()


def is_v4_address(address: ipaddress._IPAddressBase) -> typing.TypeGuard[ipaddress.IPv4Address | ipaddress.IPv4Network]:
	return isinstance(address, ipaddress._BaseV4)


def is_v6_address(address: ipaddress._IPAddressBase) -> typing.TypeGuard[ipaddress.IPv6Address | ipaddress.IPv6Network]:
	return isinstance(address, ipaddress._BaseV6)


def classify_address(address: ipaddress._IPAddressBase) -> tuple[IpAddressVersion, IpAddressType, ipaddress._IPAddressBase]:
	v = IpAddressVersion(address.version) if isinstance(address, (ipaddress._BaseV4, ipaddress._BaseV6)) else IpAddressVersion.Unknown
	t = IpAddressType.Address if isinstance(address, ipaddress._BaseAddress) else IpAddressType.Network
	return v, t, address


def parse_address(
    address: str | bytes | int,
    *,
    expand_v6_prefix: int | None = None,
) -> ipaddress.IPv4Address | ipaddress.IPv4Network | ipaddress.IPv6Address | ipaddress.IPv6Network | None:

	try:
		result = ipaddress.IPv6Network(address, False)
		if expand_v6_prefix and expand_v6_prefix < result.prefixlen:
			result = ipaddress.IPv6Network((result.network_address.compressed, expand_v6_prefix), False)
		elif result.prefixlen == result.max_prefixlen:
			result = result.network_address

		return result
	except:
		pass

	try:
		result = ipaddress.IPv4Network(address, False)
		if result.prefixlen == result.max_prefixlen:
			result = result.network_address

		return result
	except:
		pass

	return None


class FirewallProxy(typing.Protocol):

	def init_firewall(self, **kwargs):
		...

	def cleanup(self):
		...

	def add_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		...

	def remove_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		...

	def set_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		...


class DummyFirewallProxy:

	__logger = logging.getLogger(__qualname__)

	def init_firewall(self, **kwargs):
		if len(kwargs):
			warnings.warn(f'Unknown kwargs: {', '.join(kwargs.keys())}', stacklevel=2)

		self.__logger.info('init_firewall()')

	def cleanup(self):
		self.__logger.info('cleanup()')

	def add_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		self.__logger.info('add_entries(%d)', len([*entries]))

	def remove_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		self.__logger.info('remove_entries(%d)', len([*entries]))

	def set_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		self.__logger.info('set_entries(%d)', len([*entries]))
