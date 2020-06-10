import os
import re
import subprocess
from ipaddress import ip_network, ip_interface

from .posix import PosixProcessProvider
from .provider import RouteProvider
from .util import get_executable


class PsProvider(PosixProcessProvider):
    def __init__(self):
        self.lsof = get_executable('/usr/sbin/lsof')
        self.ps = get_executable('/bin/ps')

    def pid2exe(self, pid):
        info = subprocess.check_output([self.lsof, '-p', str(pid)], universal_newlines=True)
        for line in info.splitlines():
            parts = line.split()
            if parts[3] == 'txt':
                return parts[8]

    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        try:
            return int(subprocess.check_output([self.ps, '-p', str(pid), '-o', 'ppid=']))
        except ValueError:
            return None


class BSDRouteProvider(RouteProvider):
    def __init__(self):
        self.route = get_executable('/sbin/route')
        self.ifconfig = get_executable('/sbin/ifconfig')

    def _route(self, *args):
        return subprocess.check_output([self.route, '-n'] + list(map(str, args)), universal_newlines=True)

    def _ifconfig(self, *args):
        return subprocess.check_output([self.ifconfig] + list(map(str, args)), universal_newlines=True)

    def _family_option(self, destination):
        return '-inet6' if destination.version == 6 else '-inet'

    def add_route(self, destination, *, via=None, dev=None, src=None, mtu=None):
        args = ['add', self._family_option(destination)]
        if mtu is not None:
            args.extend(('-mtu', str(mtu)))
        if via is not None:
            args.extend((destination, via))
        elif dev is not None:
            args.extend(('-interface', destination, dev))
        self._route(*args)

    replace_route = add_route

    def remove_route(self, destination):
        self._route('delete', self._family_option(destination), destination)

    def get_route(self, destination):
        info = self._route('get', self._family_option(destination), destination)
        lines = iter(info.splitlines())
        info_d = {}
        for line in lines:
            if ':' not in line:
                break
            key, _, val = line.partition(':')
            info_d[key.strip()] = val.strip()
        keys = line.split()
        vals = next(lines).split()
        info_d.update(zip(keys, vals))
        return {
            'via': info_d['gateway'],
            'dev': info_d['interface'],
            'mtu': info_d['mtu'],
        }

    def flush_cache(self):
        pass

    _LINK_INFO_RE = re.compile(r'flags=\d<(.*?)>\smtu\s(\d+)$')

    def get_link_info(self, device):
        info = self._ifconfig(device)
        match = self._LINK_INFO_RE.search(info)
        if match:
            flags = match.group(1).split(',')
            mtu = int(match.group(2))
            return {
                'state': 'UP' if 'UP' in flags else 'DOWN',
                'mtu': mtu,
            }
        return None

    def set_link_info(self, device, state, mtu=None):
        args = [device]
        if state is not None:
            args.append(state)
        if mtu is not None:
            args.extend(('mtu', str(mtu)))
        self._ifconfig(*args)

    def add_address(self, device, address):
        address = ip_interface(address)
        if address.version == 6:
            self._ifconfig(device, 'inet6', address)
        else:
            self._ifconfig(device, 'inet', address.ip, address.ip, 'netmask', '255.255.255.255')
