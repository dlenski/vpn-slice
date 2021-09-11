import os
import re
import subprocess
from ipaddress import ip_interface

from .posix import PosixProcessProvider
from .provider import FirewallProvider, RouteProvider, SplitDNSProvider
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
        # Format of BSD route get output: https://unix.stackexchange.com/questions/53446
        info = self._route('get', self._family_option(destination), destination)
        lines = iter(info.splitlines())
        info_d = {}
        for line in lines:
            if ':' not in line:
                keys = line.split()
                vals = next(lines).split()
                info_d.update(zip(keys, vals))
                break
            key, val = line.split(':', 1)
            info_d[key.strip()] = val.strip()
        if 'gateway' in info_d or 'interface' in info_d:
            return {
                'via': info_d.get('gateway', None),
                'dev': info_d.get('interface', None),
                'mtu': info_d.get('mtu', None),
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
            # Repetition of the IP address is the correct syntax for a point-to-point interface
            # with BSD ifconfig. See example in default vpnc-script:
            #   https://gitlab.com/openconnect/vpnc-scripts/blob/https://gitlab.com/openconnect/vpnc-scripts/blob/921e8760/vpnc-script#L193
            self._ifconfig(device, 'inet', address.ip, address.ip, 'netmask', '255.255.255.255')


class MacSplitDNSProvider(SplitDNSProvider):
    def configure_domain_vpn_dns(self, domains, nameservers):
        if not os.path.exists('/etc/resolver'):
            os.makedirs('/etc/resolver')
        for domain in domains:
            resolver_file_name = "/etc/resolver/{0}".format(domain)
            with open(resolver_file_name, "w") as resolver_file:
                for nameserver in nameservers:
                    resolver_file.write("nameserver {}\n".format(nameserver))

    def deconfigure_domain_vpn_dns(self, domains, nameservers):
        for domain in domains:
            resolver_file_name = "/etc/resolver/{0}".format(domain)
            if os.path.exists(resolver_file_name):
                os.remove(resolver_file_name)
        if not len(os.listdir('/etc/resolver')):
            os.removedirs('/etc/resolver')


class PfFirewallProvider(FirewallProvider):
    def __init__(self):
        self.pfctl = get_executable('/sbin/pfctl')

    _PF_TOKEN_RE = re.compile(r'Token : (\d+)')
    _PF_ANCHOR = 'vpn_slice'
    _PF_CONF_FILE = '/etc/pf.conf'

    def _reload_conf(self):
        cmd = [self.pfctl, '-f', self._PF_CONF_FILE]
        p = subprocess.Popen(cmd, universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        output, stderr = p.communicate()
        if p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cmd, output=output, stderr=stderr)

    def configure_firewall(self, device):
        # Enabled Packet Filter - increments a reference counter for processes that need packet filter enabled
        cl = [self.pfctl, '-E']
        p = subprocess.Popen(cl, universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        output, stderr = p.communicate()
        if p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cl, output=output, stderr=stderr)

        # store token returned to later be able to decrement the reference counter correctly
        enable_token = None

        for line in stderr.splitlines():
            match = self._PF_TOKEN_RE.search(line)
            if match:
                enable_token = match.group(1)

        if not enable_token:
            print("WARNING: failed to get pf enable reference token, packet filter might not shutdown correctly")

        anchor = '{}/{}'.format(self._PF_ANCHOR, device)
        # add anchor to generate rules with
        with open(self._PF_CONF_FILE, 'a') as file:
            file.write('anchor "{}" # vpn-slice-{} AUTOCREATED {}\n'.format(anchor, device, enable_token))

        # reload config file
        self._reload_conf()

        p = subprocess.Popen([self.pfctl, '-a', anchor, '-f', '-'],
                             universal_newlines=True,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE)

        rules = '''pass out on {0} all keep state
        block drop in on {0} all
        '''.format(device)

        output, stderr = p.communicate(rules)
        if p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cl, output=output, stderr=stderr)

    def deconfigure_firewall(self, device):
        # disable anchor
        anchor = '{}/{}'.format(self._PF_ANCHOR, device)
        subprocess.check_call([self.pfctl, '-a', anchor, '-F', 'all'])

        with open(self._PF_CONF_FILE, 'r') as file:
            lines = file.readlines()

        enable_tokens = []
        rule_re = re.compile(r'vpn-slice-{} AUTOCREATED (\d+)'.format(device))
        with open(self._PF_CONF_FILE, 'w') as file:
            for line in lines:
                match = rule_re.search(line)
                if match:
                    enable_tokens.append(match.group(1))
                else:
                    file.write(line)

        # decrement pf enable reference counter
        for token in enable_tokens:
            cl = [self.pfctl, '-X', token]
            p = subprocess.Popen(cl, universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            output, stderr = p.communicate()
            if p.returncode != 0:
                raise subprocess.CalledProcessError(p.returncode, cl, output=output, stderr=stderr)

        if not enable_tokens:
            print("WARNING: failed to get pf enable reference token, packet filter might not have shutdown correctly")

        self._reload_conf()
