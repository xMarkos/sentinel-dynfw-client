import ipaddress
import json
import logging
import typing
import warnings

import nftables

import net

__all__ = ['NftablesFirewallProxy']


class NftablesFirewallProxy:

	__logger = logging.getLogger(__qualname__)

	def __init__(self, table: str = 'inet filter', ipset_v4: str = 'input-deny-v4', ipset_v6: str = 'input-deny-v6') -> None:
		words = table.split()
		self._family = words[0]
		self._table = words[1]

		self._ipset_v4 = ipset_v4
		self._ipset_v6 = ipset_v6

		self._nft = nftables.Nftables()
		self._nft.set_json_output(True)

	def init_firewall(self, *, drop_existing=False, **kwargs):
		if len(kwargs):
			warnings.warn(f'Unknown kwargs: {', '.join(kwargs.keys())}', stacklevel=2)

		self.__logger.info('Initializing tables')

		self._exec([
		    self._make_table('add'),
		# Note: Flushing old table seems to be safer than dropping and recreating it, because adding is noop when existing -> no errors
		    {
		        'flush': {
		            'table': {
		                'family': self._family,
		                'name': self._table
		            }
		        }
		    } if drop_existing else None,
		    {
		        'add': {
		            'chain': {
		                'family': self._family,
		                'table': self._table,
		                'name': 'input',
		                'type': 'filter',
		                'hook': 'input',
		                'prio': -10,
		                'policy': 'accept'
		            }
		        }
		    },
		    {
		        'add': {
		            'set': {
		                'family': self._family,
		                'table': self._table,
		                'name': self._ipset_v4,
		                'type': 'ipv4_addr'
		            }
		        }
		    },
		    {
		        'add': {
		            'set': {
		                'family': self._family,
		                'table': self._table,
		                'name': self._ipset_v6,
		                'type': 'ipv6_addr',
		                'flags': ['interval']
		            }
		        }
		    },
		    self._make_drop_rule('insert', 'ip', self._ipset_v4),
		    self._make_drop_rule('insert', 'ip6', self._ipset_v6),
		])

	def cleanup(self):
		self.__logger.info('Dropping tables')
		self._exec([self._make_table('delete')])

	def add_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		ipv4_addresses, ipv6_addresses = self._split_ip_addresses(entries)

		self.__logger.debug('Adding %d IPv4 entries, %d IPv6 entries', len(ipv4_addresses), len(ipv6_addresses))

		self._exec([
		    self._make_elements(self._ipset_v4, 'add', ipv4_addresses),
		    self._make_elements(self._ipset_v6, 'add', ipv6_addresses),
		])

	def remove_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		ipv4_addresses, ipv6_addresses = self._split_ip_addresses(entries)

		self.__logger.debug('Removing %d IPv4 entries, %d IPv6 entries', len(ipv4_addresses), len(ipv6_addresses))

		self._exec([
		    self._make_elements(self._ipset_v4, 'delete', ipv4_addresses),
		    self._make_elements(self._ipset_v6, 'delete', ipv6_addresses),
		])

	def set_entries(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		ipv4_addresses, ipv6_addresses = self._split_ip_addresses(entries)

		self.__logger.info('Installing %d IPv4 entries and %d IPv6 entries', len(ipv4_addresses), len(ipv6_addresses))

		self._exec([
		    self._make_flush_set(self._ipset_v4),
		    self._make_flush_set(self._ipset_v6),
		    self._make_elements(self._ipset_v4, 'add', ipv4_addresses),
		    self._make_elements(self._ipset_v6, 'add', ipv6_addresses),
		])

	def _exec(self, actions: list):
		actions = [x for x in actions if x is not None]
		if not len(actions):
			self.__logger.debug('_exec(): no actions')
			return None, None, None

		rc, output, error = self._nft.cmd(json.dumps({'nftables': actions}))

		if rc != 0:
			self.__logger.error('rc: %s, output: %s, error: %s\ninput: %s', rc, output, error, actions)

		return rc, output, error

	def _split_ip_addresses(self, entries: typing.Iterable[ipaddress._IPAddressBase]):
		ipv4_addresses: list[ipaddress.IPv4Address | ipaddress.IPv4Network] = []
		ipv6_addresses: list[ipaddress.IPv6Address | ipaddress.IPv6Network] = []

		for entry in entries:
			if net.is_v4_address(entry):
				ipv4_addresses.append(entry)
			elif net.is_v6_address(entry):
				ipv6_addresses.append(entry)

		return ipv4_addresses, ipv6_addresses

	def _make_elements_impl(self, addresses: typing.Collection[ipaddress._IPAddressBase]):
		for address in addresses:
			if isinstance(address, ipaddress._BaseAddress):
				yield address.compressed
			elif isinstance(address, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
				yield {
				    'prefix': {
				        'addr': address.network_address.compressed,
				        'len': address.prefixlen,
				    }
				}

	def _make_elements(self,
	                   set_name: str,
	                   op: typing.Literal['add', 'delete'],
	                   elements: typing.Collection[ipaddress._IPAddressBase],
	                   *,
	                   skip_when_empty=True):
		return None if skip_when_empty and (elements is None or not len(elements)) else {
		    op: {
		        'element': {
		            'family': self._family,
		            'table': self._table,
		            'name': set_name,
		            'elem': [*self._make_elements_impl(elements)],
		        }
		    }
		}

	def _make_table(self, op: typing.Literal['add', 'delete']):
		return {
		    op: {
		        'table': {
		            'family': self._family,
		            'name': self._table
		        }
		    },
		}

	def _make_drop_rule(self, op: typing.Literal['add', 'insert'], protocol: typing.Literal['ip', 'ip6'], set_name: str):
		return {
		    op: {
		        'rule': {
		            'family':
		            self._family,
		            'table':
		            self._table,
		            'chain':
		            'input',
		            'expr': [
		                {
		                    'match': {
		                        'op': '==',
		                        'left': {
		                            'payload': {
		                                'protocol': protocol,
		                                'field': 'saddr'
		                            }
		                        },
		                        'right': f'@{set_name}'
		                    }
		                },
		                {
		                    'counter': None
		                },
		                {
		                    'drop': None
		                },
		            ]
		        }
		    }
		}

	def _make_flush_set(self, set_name: str):
		return {
		    'flush': {
		        'set': {
		            'family': self._family,
		            'table': self._table,
		            'name': set_name,
		        }
		    }
		}
