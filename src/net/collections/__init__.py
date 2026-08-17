from ipaddress import IPv6Address, IPv6Network

__all__ = ['IPv6Counter']


class IPv6Counter(dict[int, int]):

	def __init__(self) -> None:
		pass

	def increment(self, addr: IPv6Address | IPv6Network):
		key = self._get_key(addr)
		value = self.get(key, 0) + 1
		self[key] = value

		return value

	def decrement(self, addr: IPv6Address | IPv6Network):
		key = self._get_key(addr)
		value = self.get(key, 0) - 1

		if value <= 0:
			del self[key]
		else:
			self[key] = value

		return value if value >= 0 else 0

	def count(self, addr: IPv6Address | IPv6Network):
		key = self._get_key(addr)
		return self.get(key, 0)

	def _get_key(self, addr: IPv6Address | IPv6Network):
		if isinstance(addr, IPv6Network):
			addr = addr.network_address

		return int(addr) >> 64
