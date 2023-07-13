from abc import ABCMeta, abstractmethod
from ipaddress import ip_interface, _IPAddressBase, _BaseAddress
from typing import Optional, Sequence, Mapping


class ProcessProvider(metaclass=ABCMeta):
    @abstractmethod
    def pid2exe(self, pid: int):
        """Get the path to the executable running as a given PID."""

    @abstractmethod
    def pid(self):
        """Get the PID of the current process."""

    @abstractmethod
    def ppid_of(self, pid: int=None):
        """Get the PID of the parent of the process with the given PID,
        or of the current process if None."""

    @abstractmethod
    def kill(self, pid: int):
        """Kill the process with the given PID."""


class RouteProvider(metaclass=ABCMeta):
    @abstractmethod
    def add_route(self, destination: _IPAddressBase, *,
                  via: Optional[_BaseAddress]=None,
                  dev: Optional[str]=None,
                  src: Optional[_BaseAddress]=None,
                  mtu: Optional[int]=None):
        """Add a route to a destination.

        You must specify a device or gateway saying where to route to.
        If both are specified, they must agree.

        Implementations may fail if a route that already exists is
        added again.

        """

    @abstractmethod
    def replace_route(self, destination: _IPAddressBase, *,
                      via: Optional[_BaseAddress]=None,
                      dev: Optional[str]=None,
                      src: Optional[_BaseAddress]=None,
                      mtu: Optional[int]=None):
        """Add or replace a route to a destination.

        You must specify a device or gateway saying where to route to.
        If both are specified, they must agree.

        Implementations should not fail if a route that already exists
        is added again.

        """

    @abstractmethod
    def remove_route(self, destination: _IPAddressBase):
        """Remove a route to a destination."""

    @abstractmethod
    def get_route(self, destination: _IPAddressBase):
        """Return the gateway to a destination.

        Return a dict with these keys containing the information,
        or None if it is unavailable:

        * via
        * dev
        * src
        * mtu

        """

    @abstractmethod
    def flush_cache(self):
        """Flush the routing cache (if necessary)."""

    @abstractmethod
    def get_link_info(self, device: str):
        """Get the MTU and state for a device.

        Return a dict with these keys containing the information,
        or None if it is unavailable:

        * mtu
        * state

        """

    @abstractmethod
    def set_link_info(self, device: str, state: str, mtu: Optional[int]=None):
        """Set the MTU and state of a device."""

    @abstractmethod
    def add_address(self, device: str, address: _IPAddressBase):
        """Add an address to an interface."""


class FirewallProvider(metaclass=ABCMeta):
    @abstractmethod
    def configure_firewall(self, device: str):
        """Configure the firewall to prevent inbound traffic on the device."""

    @abstractmethod
    def deconfigure_firewall(self, device: str):
        """Remove the firewall configuration for a device."""


class DNSProvider(metaclass=ABCMeta):
    def configure(self, dns_servers: Sequence[_IPAddressBase], *,
                  bind_addresses: Optional[Sequence[_IPAddressBase]]=None,
                  search_domains: Sequence[str]=()):
        """Configure provider to use the specified DNS servers, bind addresses, and search domains."""
        self.dns_servers = dns_servers
        self.bind_addresses = [ip_interface(a).ip for a in bind_addresses] if bind_addresses else []
        self.search_domains = search_domains

    @abstractmethod
    def lookup_host(self, hostname: str, keep_going: bool=True):
        """Look up the address(es) of a host using configured servers.

        If keep_going is True, it will continue until all possible
        combinations of address family (IPv4/6) and search domain are
        exhausted; if False, it will return as soon as it has found
        any valid records.
        """

    @abstractmethod
    def lookup_srv(self, query: str):
        """Query SRV records using configured servers.

        The resulting hostnames will be returned in order of
        (priority, weight), with the trailing '.' stripped from each
        hostname. See https://en.wikipedia.org/wiki/SRV_record for the
        interpretation of these results.
        """

class HostsProvider(metaclass=ABCMeta):
    @abstractmethod
    def write_hosts(self, host_map: Mapping[str, _IPAddressBase], name: str):
        """Write information to the hosts file.

        Lines include a tag so we can identify which lines to remove.
        The tag is derived from the name.

        host_map maps IP addresses to host names, like the hosts file expects.

        """

class TunnelPrepProvider:
    def create_tunnel(self):
        """Create tunnel device.

        Base class behavior is to do nothing.

        """

    def prepare_tunnel(self):
        """Prepare operating system to create tunnel devices.

        Base class behavior is to do nothing.

        """

class SplitDNSProvider:
    def configure_domain_vpn_dns(self, domains: Sequence[str], nameservers: Sequence[_IPAddressBase], tundev: str):
        """Configure domain vpn dns.

        Base class behavior is to do nothing.

        """

    def deconfigure_domain_vpn_dns(self, domains: Sequence[str], nameservers: Sequence[_IPAddressBase], tundev: str):
        """Remove domain vpn dns.

        Base class behavior is to do nothing.

        """
