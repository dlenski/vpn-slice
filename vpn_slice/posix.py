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

    def lookup_host(self, hostname, dns_servers, *, bind_addresses=None, search_domains=()):
        cl = [self.dig, '+short', '+noedns']

        if not bind_addresses:
            some_cls = [ cl + ['@{!s}'.format(dns) for dns in dns_servers] ]
            field_requests = [hostname, 'A', hostname, 'AAAA']
        else:
            # We only do lookups for protocols of which we have bind addresses
            some_cls = []
            field_requests = []
            for bind in bind_addresses:
                if bind.version == 4:
                    field_requests.extend([hostname, 'A'])
                elif bind.version == 6:
                    field_requests.extend([hostname, 'AAAA'])

                bind_cl = cl + ['-b', str(bind)]
                bind_cl.extend('@{!s}'.format(dns) for dns in dns_servers if dns.version == bind.version)
                some_cls.append(bind_cl)

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
            p = subprocess.Popen(cl, stdout=subprocess.PIPE)
            output, _ = p.communicate()
            if p.returncode != 0:
                return None
            for line in output.decode().splitlines():
                try:
                    result.add(ip_address(line.strip()))
                except ValueError:
                    # dig sometimes returns extra domain names instead of IP addresses
                    pass

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
