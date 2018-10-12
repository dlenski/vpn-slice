import fcntl
import os
import subprocess
from ipaddress import ip_address

from .provider import DNSProvider, HostsProvider
from .util import get_executable


class DigProvider(DNSProvider):
    def __init__(self):
        self.dig = get_executable('/usr/bin/dig')

    def lookup_host(
        self, hostname, dns_servers, *, bind_address=None, search_domains=()
    ):
        cl = [self.dig, '+short', '+noedns']
        if bind_address:
            cl.extend(('-b', str(bind_address)))
        cl.extend('@{!s}'.format(s) for s in dns_servers)
        cl.extend('+domain={!s}'.format(s) for s in search_domains)
        cl.append(str(hostname))

        result = set()
        p = subprocess.Popen(cl, stdout=subprocess.PIPE)
        output, _ = p.communicate()
        if p.returncode != 0:
            return None
        for line in output.decode().splitlines():
            try:
                result.add(ip_address(line.strip()))
            except ValueError:
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
