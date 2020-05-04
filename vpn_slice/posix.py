import fcntl
import os
import subprocess
from ipaddress import ip_address
from signal import SIGTERM

from .provider import DNSProvider, HostsProvider, ProcessProvider
from .util import get_executable


class DigProvider(DNSProvider):
    def __init__(self):
        self.dig = get_executable('/usr/bin/dig')
        self.base_cl = [self.dig, '+short', '+noedns']

    def lookup_host(self, hostname, keep_going=True):
        dns_servers = self.dns_servers
        bind_addresses = self.bind_addresses
        search_domains = self.search_domains

        if not bind_addresses:
            some_cls = [ self.base_cl + ['@{!s}'.format(dns) for dns in dns_servers] ]
            field_requests = [hostname, 'A', hostname, 'AAAA']
        else:
            some_cls = []
            field_requests = []
            for bind in bind_addresses:
                # We only do lookups for protocols of which we have bind addresses.
                # (For example, if we have only an IPv4 bind address, we don't lookup AAAA/IPv6
                # DNS records because we won't be able to route traffic to them.)
                field_requests.extend([hostname, ('AAAA' if bind.version == 6 else 'A')])

                # We can only do a lookup via DNS-over-IPv[X] if we have an IPv[X] address to bind to.
                matching_dns = ['@{!s}'.format(dns) for dns in dns_servers if dns.version == bind.version]
                if matching_dns:
                    some_cls.append(self.base_cl + ['-b', str(bind)] + matching_dns)

        # N.B.: dig does not correctly handle the specification of multiple
        # +domain arguments, discarding all but the last one. Therefore
        # we need to run it multiple times and combine the results
        # if multiple search_domains are specified.
        all_cls = []
        if search_domains:
            for cl in some_cls:
                all_cls.extend(cl + ['+domain={!s}'.format(sd)] + field_requests for sd in search_domains)
        else:
            for cl in some_cls:
                all_cls.extend([cl + field_requests])

        # actually fetch results
        result = set()
        for cl in all_cls:
            p = subprocess.Popen(cl, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            output, stderr = p.communicate()
            if p.returncode != 0:
                raise subprocess.CalledProcessError(p.returncode, cl, output=output, stderr=stderr)
            for line in output.splitlines():
                try:
                    result.add(ip_address(line.strip()))
                except ValueError:
                    # dig sometimes returns extra domain names instead of IP addresses
                    pass
            if result and not keep_going:
                return result

        return result or None


class HostsFileProvider(HostsProvider):
    def __init__(self, path):
        self.path = path
        if not os.access(path, os.R_OK | os.W_OK):
            raise OSError('Cannot read/write {}'.format(path))

    def write_hosts(self, host_map, name):
        tag = 'vpn-slice-{} AUTOCREATED'.format(name)
        with open(self.path, 'r+') as hostf:
            fcntl.flock(hostf, fcntl.LOCK_EX)  # POSIX only, obviously
            lines = hostf.readlines()
            keeplines = [l for l in lines if not l.endswith('# %s\n' % tag)]
            hostf.seek(0, 0)
            hostf.writelines(keeplines)
            for ip, names in host_map:
                print('%s %s\t\t# %s' % (ip, ' '.join(names), tag), file=hostf)
            hostf.truncate()
        return len(host_map) or len(lines) - len(keeplines)


class PosixHostsFileProvider(HostsFileProvider):
    def __init__(self):
        super().__init__('/etc/hosts')


class PosixProcessProvider(ProcessProvider):
    def kill(self, pid, signal=SIGTERM):
        os.kill(pid, signal)

    def pid(self):
        return os.getpid()

    def is_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
