from ipaddress import ip_address
from itertools import chain
from sys import stderr

from dns.name import from_text, root
from dns.resolver import NXDOMAIN, NoAnswer, Resolver, Timeout

from .provider import DNSProvider


class DNSPythonProvider(DNSProvider):
    def configure(self, dns_servers, *, bind_addresses=None, search_domains=()):
        super().configure(dns_servers, bind_addresses=bind_addresses, search_domains=search_domains)

        self.resolver = Resolver(configure=False)
        self.resolver.domain = root
        self.resolver.search = [from_text(d) for d in search_domains]

        self.rectypes = []
        if self.bind_addresses is None or any(a.version == 4 for a in self.bind_addresses):
            self.rectypes.append('A')
        if self.bind_addresses is None or any(a.version == 6 for a in self.bind_addresses):
            self.rectypes.append('AAAA')

    def reverse_lookup_ip(self, ip, keep_going=True):
        result = set()

        for source in self.bind_addresses or [None]:
            if source is None:
                self.resolver.nameservers = self.dns_servers
            else:
                self.resolver.nameservers = [str(dns) for dns in self.dns_servers if dns.version == source.version]
                if not self.resolver.nameservers:
                    continue

            if ip.version == 4:
                arpa = '%d.%d.%d.%d.in-addr.arpa' % tuple(reversed(ip.packed))
            else:
                arpa = ''.join('%x.%x.' % ((x & 15), (x >> 4)) for x in reversed(ip.packed)) + 'ip6.arpa'

            try:
                print("Issuing query for hostname %r, rectype PTR, class IN, source %r, search %r, nameservers %r" % (
                    arpa, source, self.resolver.search, self.resolver.nameservers), file=stderr)
                a = self.resolver.query(arpa, 'PTR', 'IN', source=None if source is None else str(source))
                print("Got results: %r" % list(a), file=stderr)
            except (NXDOMAIN, NoAnswer, Timeout):
                pass
            else:
                result.update(str(r.target).rstrip('.') for r in a)
            if result and not keep_going:
                return result

        return result or None

    def lookup_host(self, hostname, keep_going=True):
        result = set()

        for source in self.bind_addresses or [None]:
            if source is None:
                self.resolver.nameservers = self.dns_servers
            else:
                self.resolver.nameservers = [str(dns) for dns in self.dns_servers if dns.version == source.version]
                if not self.resolver.nameservers:
                    continue

            for rectype in self.rectypes:
                try:
                    # print("Issuing query for hostname %r, rectype %r, source %r, search %r, nameservers %r" % (
                    #     hostname, rectype, source, self.resolver.search, self.resolver.nameservers), file=stderr)
                    a = self.resolver.query(hostname, rectype, source=None if source is None else str(source))
                    print("Got results: %r" % list(a), file=stderr)
                except (NXDOMAIN, NoAnswer):
                    pass
                except Timeout:
                    # No point in retrying with a different rectype if these DNS server(s) are not responding
                    break
                else:
                    result.update(ip_address(r.address) for r in a)
                if result and not keep_going:
                    return result

        return result or None
