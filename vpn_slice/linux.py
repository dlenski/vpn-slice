import os
import subprocess
import stat

from .posix import PosixProcessProvider
from .provider import FirewallProvider, RouteProvider, TunnelPrepProvider
from .util import get_executable


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

        if args[:2]==('route','get'):
            output_start, keys = 1, ('via', 'dev', 'src', 'mtu')
        elif args[:2]==('link','show'):
            output_start, keys = 3, ('state', 'mtu')
        else:
            output_start = None

        if output_start is not None:
            words = subprocess.check_output(cl, universal_newlines=True).split()
            return {words[i]: words[i + 1] for i in range(output_start, len(words), 2) if words[i] in keys}
        else:
            subprocess.check_call(cl)

    def add_route(self, destination, *, via=None, dev=None, src=None, mtu=None):
        self._iproute('route', 'add', destination, via=via, dev=dev, src=src, mtu=mtu)

    def replace_route(self, destination, *, via=None, dev=None, src=None, mtu=None):
        self._iproute('route', 'replace', destination, via=via, dev=dev, src=src, mtu=mtu)

    def remove_route(self, destination):
        self._iproute('route', 'del', destination)

    def get_route(self, destination):
        return self._iproute('route', 'get', destination)

    def flush_cache(self):
        self._iproute('route', 'flush', 'cache')

    def get_link_info(self, device):
        return self._iproute('link', 'show', device)

    def set_link_info(self, device, state, mtu=None):
        self._iproute('link', 'set', state, dev=device, mtu=mtu)

    def add_address(self, device, address):
        self._iproute('address', 'add', address, dev=device)


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
            os.mknod(node, mode=0o640 | stat.S_IFCHR, device = os.makedev(10, 200))
    def prepare_tunnel(self):
        if not os.access('/dev/net/tun', os.R_OK | os.W_OK):
            raise OSError("can't read and write /dev/net/tun")
