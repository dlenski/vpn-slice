from ipaddress import ip_address
from dns.resolver import Resolver, NXDOMAIN, NoAnswer
from dns.name import root, from_text

from .provider import DNSProvider

class DNSPythonProvider(DNSProvider):
    def configure(self, dns_servers, *, bind_addresses=None, search_domains=()):
        super().configure(dns_servers, bind_addresses=bind_addresses, search_domains=search_domains)

        self.resolver = Resolver(configure=False)
        self.resolver.domain = root
        self.resolver.search_domains = [from_text(d) for d in search_domains]

        self.rectypes = []
        if self.bind_addresses is None or any(a.version == 4 for a in self.bind_addresses):
            self.rectypes.append('A')
        if self.bind_addresses is None or any(a.version == 6 for a in self.bind_addresses):
            self.rectypes.append('AAAA')

    def lookup_host(self, hostname, keep_going=True):
        result = set()

        for source in self.bind_addresses or [None]:
            if source is None:
                self.resolver.nameservers = self.nameservers
            else:
                self.resolver.nameservers = [str(dns) for dns in self.dns_servers if dns.version == source.version]
                if not self.resolver.nameservers:
                    continue

            for rectype in self.rectypes:
                try:
                    a = self.resolver.query(hostname, rectype, source=str(source))
                except (NXDOMAIN, NoAnswer):
                    pass
                else:
                    result.update(ip_address(r.address) for r in a)
                if result and not keep_going:
                    return result

        return result or None
