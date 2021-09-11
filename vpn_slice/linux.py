import os
import stat
import subprocess

from .posix import PosixProcessProvider
from .provider import FirewallProvider, RouteProvider, TunnelPrepProvider
from .util import MAX_UINT32, get_executable


class ProcfsProvider(PosixProcessProvider):
    def pid2exe(self, pid):
        try:
            return os.readlink('/proc/%d/exe' % pid)
        except (OSError, IOError):
            return None

    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        try:
            return int(next(open('/proc/%d/stat' % pid)).split()[3])
        except (OSError, ValueError, IOError):
            return None


class Iproute2Provider(RouteProvider):
    def __init__(self):
        self.iproute = get_executable('/sbin/ip')

    def _iproute(self, *args, **kwargs):
        cl = [self.iproute]
        cl.extend(str(v) for v in args if v is not None)
        for k, v in kwargs.items():
            if v is not None:
                cl.extend((k, str(v)))
        skip = next((ii for ii, v in enumerate(args) if not v.startswith('-')), len(args))
        args = args[skip:]

        output_start = multi = route_junk = None
        if args[:2] == ('route', 'get'):
            output_start, keys = 1, ('via', 'dev', 'src', 'mtu', 'metric')
            route_junk = True
        elif args[:2] == ('route', 'show'):
            output_start, keys = 1, ('via', 'dev', 'src', 'mtu', 'metric')
            multi = route_junk = True
        elif args[:2] == ('link', 'show'):
            output_start, keys = 3, ('state', 'mtu')

        # FIXME/rant: parsing the output of 'ip route {get,show}' is a bit of a nightmare.
        # Per https://linux.die.net/man/8/ip, the output ...
        #   1) Can include 'mtu' followed by either 1 parameter ('mtu X') or two ('mtu lock X')
        #   2) Can include 'onlink' followed by 0 parameters, but only in 'ip show' output
        #      (https://gitlab.com/openconnect/vpnc-scripts/-/issues/20#note_542783676)
        #
        # We get both of the above cases wrong currently.
        # Possibly it'd be saner/stabler to parse /proc/net/route.

        if output_start is not None:
            if not multi:
                words = subprocess.check_output(cl, universal_newlines=True).split()
                if route_junk and words[0] in ('broadcast', 'multicast', 'local', 'unreachable'):
                    output_start += 1
                results = {words[i]: words[i + 1] for i in range(output_start, len(words), 2) if words[i] in keys}
            else:
                results = []
                for line in subprocess.check_output(cl, universal_newlines=True).splitlines():
                    words = line.split()
                    if route_junk and words[0] in ('broadcast', 'multicast', 'local', 'unreachable'):
                        output_start += 1
                    results.append({words[i]: words[i + 1] for i in range(output_start, len(words), 2) if words[i] in keys})
            return results
        else:
            subprocess.check_call(cl)

    def add_route(self, destination, *, via=None, dev=None, src=None, mtu=None, metric=None):
        self._iproute('route', 'add', destination, via=via, dev=dev, src=src, mtu=mtu, metric=metric)

    def replace_route(self, destination, *, via=None, dev=None, src=None, mtu=None, metric=None):
        self._iproute('route', 'replace', destination, via=via, dev=dev, src=src, mtu=mtu, metric=metric)

    def remove_route(self, destination):
        self._iproute('route', 'del', destination)

    def get_route(self, destination):
        r = self._iproute('route', 'get', destination)
        # Ignore localhost or incomplete routes
        if r.get('dev') == 'lo':
            del r['dev']
        if 'dev' in r or 'via' in r:
            return r

    def get_all_routes(self, destination):
        if destination.version == 4:
            flag, root = '-4', '0/0'
        else:
            flag, root = '-6', '::/0'
        # Ignore localhost or incomplete routes
        rs = [r for r in self._iproute(flag, 'route', 'show', 'to', destination, 'root', root) if r.get('dev') != 'lo' and ('dev' in r or 'via' in r)]
        return sorted(rs, key=lambda r: int(r.get('metric', MAX_UINT32)))

    def flush_cache(self):
        # IPv4 route cache is obsolete as of Linux 3.6 (https://gitlab.com/openconnect/vpnc-scripts/-/merge_requests/30)
        self._iproute('route', 'flush', 'cache')
        self._iproute('-6', 'route', 'flush', 'cache')

    def get_link_info(self, device):
        return self._iproute('link', 'show', device)

    def set_link_info(self, device, state, mtu=None):
        self._iproute('link', 'set', state, dev=device, mtu=mtu)

    def add_address(self, device, address):
        flag = '-6' if address.version == 6 else '-4'
        self._iproute(flag, 'address', 'add', address, dev=device)


class IptablesProvider(FirewallProvider):
    def __init__(self):
        self.iptables = get_executable('/sbin/iptables')

    def _iptables(self, *args):
        cl = [self.iptables]
        cl.extend(args)
        subprocess.check_call(cl)

    def configure_firewall(self, device):
        self._iptables('-A', 'INPUT', '-i', device, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')
        self._iptables('-A', 'INPUT', '-i', device, '-j', 'DROP')

    def deconfigure_firewall(self, device):
        self._iptables('-D', 'INPUT', '-i', device, '-j', 'DROP')
        self._iptables('-D', 'INPUT', '-i', device, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')


class CheckTunDevProvider(TunnelPrepProvider):
    def create_tunnel(self):
        node = '/dev/net/tun'
        if not os.path.exists(node):
            os.makedirs(os.path.dirname(node), exist_ok=True)
            os.mknod(node, mode=0o640 | stat.S_IFCHR, device=os.makedev(10, 200))

    def prepare_tunnel(self):
        if not os.access('/dev/net/tun', os.R_OK | os.W_OK):
            raise OSError("can't read and write /dev/net/tun")
