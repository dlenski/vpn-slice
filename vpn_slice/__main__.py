#!/usr/bin/env python3

import argparse
import os
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Interface, IPv6Network, ip_address, ip_network
from itertools import chain, zip_longest
from random import choice, randint, shuffle
from subprocess import CalledProcessError
from sys import platform, stderr
from time import sleep

try:
    from setproctitle import setproctitle
except ImportError:
    def setproctitle(title):
        pass

def tagged(iter, tag):
    return zip_longest(iter, (), fillvalue=tag)

from .util import slurpy
from .version import __version__


def get_default_providers():
    try:
        from .dnspython import DNSPythonProvider
    except ImportError:
        DNSPythonProvider = None

    if platform.startswith('linux'):
        from .linux import CheckTunDevProvider, Iproute2Provider, IptablesProvider, ProcfsProvider
        from .posix import DigProvider, PosixHostsFileProvider
        return dict(
            process = ProcfsProvider,
            route = Iproute2Provider,
            firewall = IptablesProvider,
            dns = DNSPythonProvider or DigProvider,
            hosts = PosixHostsFileProvider,
            prep = CheckTunDevProvider,
        )
    elif platform.startswith('darwin'):
        from platform import release

        from .mac import BSDRouteProvider, MacSplitDNSProvider, PfFirewallProvider, PsProvider
        from .posix import DigProvider, PosixHostsFileProvider
        parsed_release = tuple(int(d) if d.isdigit() else 0 for d in release().split("."))
        return dict(
            process=PsProvider,
            route=BSDRouteProvider,
            dns=DNSPythonProvider or DigProvider,
            hosts=PosixHostsFileProvider,
            domain_vpn_dns=MacSplitDNSProvider,
            # PF firewall was released with MacOS 10.6 Snow Leopard (= Darwin kernel 10.0)
            # https://en.wikipedia.org/wiki/Mac_OS_X_Snow_Leopard#Release_history
            firewall = PfFirewallProvider if parsed_release >= (10, 0) else None,
        )
    elif platform.startswith('freebsd'):
        from .freebsd import ProcfsProvider
        from .mac import BSDRouteProvider
        from .posix import DigProvider, PosixHostsFileProvider
        return dict(
            process = ProcfsProvider,
            route = BSDRouteProvider,
            dns = DNSPythonProvider or DigProvider,
            hosts = PosixHostsFileProvider,
        )
    else:
        return dict(
            platform = OSError(f'Your platform, {platform}, is unsupported')
        )


def net_or_host_param(s):
    if '=' in s:
        hosts = s.split('=')
        ip = hosts.pop()
        return hosts, ip_address(ip)
    else:
        if s.lstrip().startswith('%'):
            include = False
            s = s.lstrip()[1:]
        else:
            include = True

        try:
            return include, ip_network(s, strict=False)
        except ValueError:
            return s

def file_path_param(path):
    if isinstance(path, str) and os.path.exists(path):
        return path
    else:
        raise ValueError("path not valid")

def names_for(host, domains, short=True, long=True):
    if '.' in host: first, rest = host.split('.', 1)
    else: first, rest = host, None
    if isinstance(domains, str): domains = (domains,)

    names = []
    if long:
        if rest: names.append(host)
        elif domains: names.append(host+'.'+domains[0])
    if short:
        if not rest: names.append(host)
        elif rest in domains: names.append(first)
    return names

def read_routes_file(filename):
    hosts = []
    with open(filename) as f:
        lines = [x.strip() for x in f.readlines()]
        for line in lines:
            # ignore empty lines
            if not len(line.strip()):
                continue
            # ignore comment lines
            if line.strip().startswith('#'):
                continue
            # ignore comments at the end of the line
            host = line.split('#', 1)[0].strip()
            hosts.append(host)
    return hosts

########################################

def do_pre_init(env, args):
    global providers
    if 'prep' in providers:
        providers.prep.create_tunnel()
        providers.prep.prepare_tunnel()

def do_disconnect(env, args):
    global providers
    for pidfile in args.kill:
        try:
            pid = int(open(pidfile).read())
        except (OSError, ValueError):
            print(f"WARNING: could not read pid from {pidfile}", file=stderr)
        else:
            try: providers.process.kill(pid)
            except OSError as e:
                print(f"WARNING: could not kill pid {pid} from {pidfile}: {e!s}", file=stderr)
            else:
                if args.verbose:
                    print(f"Killed pid {pid} from {pidfile}", file=stderr)

    if 'hosts' in providers:
        removed = providers.hosts.write_hosts((), args.name)
        if args.verbose:
            print(f"Removed {removed} hosts from /etc/hosts", file=stderr)

    # delete all explicitly created routes:
    #   1. Explicit route to gateway (won't get deleted automatically because
    #      it's via an interface other than the one being disabled)
    #   2. Explicit split-exclude routes (same)
    #   3. Normal (split-)include routes (might already be deleted if the
    #      interface is being disabled; platform-dependent)
    for dest, desc in chain(tagged([env.gateway], "route to VPN gateway"),
                            tagged(args.exc_subnets, "split-exclude route"),
                            tagged(args.subnets, "route")):
        try:
            providers.route.remove_route(dest)
        except CalledProcessError:
            print(f"WARNING: could not delete {desc} ({dest})", file=stderr)
    else:
        providers.route.flush_cache()

    # remove firewall rule blocking incoming traffic
    if 'firewall' in providers and not args.incoming:
        try:
            providers.firewall.deconfigure_firewall(env.tundev)
        except CalledProcessError:
            print(f"WARNING: failed to deconfigure firewall for VPN interface ({env.tundev})", file=stderr)

    if args.vpn_domains is not None:
        try:
            providers.domain_vpn_dns.deconfigure_domain_vpn_dns(args.vpn_domains, env.dns)
        except OSError:
            print("WARNING: failed to deconfigure domains vpn dns", file=stderr)


def do_connect(env, args):
    global providers
    if args.banner and env.banner:
        print("Connect Banner:")
        for l in env.banner.splitlines(): print("| "+l)

    # set explicit route to gateway
    if env.gateway.is_loopback:
        print("WARNING: Gateway address is loopback (%s); probably a local proxy.", file=stderr)
    else:
        gwr = providers.route.get_route(env.gateway)
        if gwr:
            providers.route.replace_route(env.gateway, **gwr)
            if args.verbose > 1:
                print("Set explicit route to VPN gateway %s (%s)" % (env.gateway, ', '.join('%s %s' % kv for kv in gwr.items())), file=stderr)
        else:
            print(f"WARNING: no route to VPN gateway found {env.gateway}; cannot set explicit route to it.")

    # drop incoming traffic from VPN
    if not args.incoming:
        if 'firewall' not in providers:
            print("WARNING: no firewall provider available; can't block incoming traffic", file=stderr)
        else:
            try:
                providers.firewall.configure_firewall(env.tundev)
                if args.verbose:
                    print("Blocked incoming traffic from VPN interface with iptables.", file=stderr)
            except CalledProcessError:
                try:
                    providers.firewall.deconfigure_firewall(env.tundev)
                except CalledProcessError:
                    pass
                print("WARNING: failed to block incoming traffic", file=stderr)

    # configure MTU
    mtu = env.mtu
    if mtu is None:
        dev = gwr.get('dev')
        if dev:
            dev_mtu = providers.route.get_link_info(dev).get('mtu')
            if dev_mtu:
                mtu = int(dev_mtu) - 88
        if mtu:
            print(f"WARNING: guessing MTU is {mtu} (the MTU of {dev} - 88)", file=stderr)
        else:
            mtu = 1412
            print(f"WARNING: guessing default MTU of {mtu} (couldn't determine MTU of {dev})", file=stderr)
    providers.route.set_link_info(env.tundev, state='up', mtu=mtu)

    # set IPv4, IPv6 addresses for tunnel device
    if env.myaddr:
        providers.route.add_address(env.tundev, env.myaddr)
    if env.myaddr6:
        providers.route.add_address(env.tundev, env.myaddr6)

    # save routes for excluded subnets
    exc_subnets = []
    for dest in args.exc_subnets:
        r = providers.route.get_route(dest)
        if r:
            exc_subnets.append((dest, r))
        else:
            print(f"WARNING: Ignoring unroutable split-exclude {dest}", file=stderr)

    # set up routes to the DNS and Windows name servers, subnets, and local aliases
    ns = env.dns + env.dns6 + (env.nbns if args.nbns else [])
    for dest, tag in chain(tagged(ns, "nameserver"), tagged(args.subnets, "subnet"), tagged(args.aliases, "alias")):
        if args.verbose > 1:
            print(f"Adding route to {tag} {dest} through {env.tundev}.", file=stderr)
        providers.route.replace_route(dest, dev=env.tundev)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print(f"Added routes for {len(ns)} nameservers, {len(args.subnets)} subnets, {len(args.aliases)} aliases.", file=stderr)

    # restore routes to excluded subnets
    for dest, exc_route in exc_subnets:
        providers.route.replace_route(dest, **exc_route)
        if args.verbose > 1:
            print("Restoring split-exclude route to %s (%s)" % (dest, ', '.join('%s %s' % kv for kv in exc_route.items())), file=stderr)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print(f"Restored routes for {len(exc_subnets)} excluded subnets.", file=stderr)

    # Use vpn dns for provided domains
    if args.vpn_domains is not None:
        if 'domain_vpn_dns' not in providers:
            print("WARNING: no split dns provider available; can't split dns", file=stderr)
        else:
            providers.domain_vpn_dns.configure_domain_vpn_dns(args.vpn_domains, env.dns)


def do_post_connect(env, args):
    global providers
    # lookup named hosts for which we need routes and/or host_map entries
    # (the DNS/NBNS servers already have their routes)
    ip_routes = set()
    host_map = []

    if args.ns_hosts:
        ns_names = [ (ip, (f'dns{ii}.{args.name}',)) for ii, ip in enumerate(env.dns + env.dns6) ]
        if args.nbns:
            ns_names += [ (ip, (f'nbns{ii}.{args.name}',)) for ii, ip in enumerate(env.nbns) ]
        host_map += ns_names
        if args.verbose:
            print(f"Adding /etc/hosts entries for {len(ns_names)} nameservers...", file=stderr)
            for ip, names in ns_names:
                print(f"  {ip} = {', '.join(map(str, names))}", file=stderr)

    if args.hosts or args.prevent_idle_timeout or args.kerberos_dc:
        providers.dns.configure(dns_servers=(env.dns + env.dns6), search_domains=args.domain, bind_addresses=env.myaddrs)

    kdc_hosts = []
    if args.kerberos_dc:
        if args.verbose:
            print(f"Looking up Kerberos5 DC hosts for realm {args.kerberos_dc!r} using VPN DNS servers...", file=stderr)
        try:
            kdc_hosts = providers.dns.lookup_srv(f'_kerberos._tcp.{args.kerberos_dc}')
        except Exception as e:
            print(f"WARNING: Lookup for Kerberos5 DC hosts for realm {args.kerberos_dc!r} on VPN DNS servers failed:\n\t{e}", file=stderr)
        else:
            if args.verbose:
                print(f"Got {len(kdc_hosts)} Kerberos5 DC hosts.", file=stderr)

    hosts_to_lookup = list(chain(tagged(args.hosts, 'host'), tagged(kdc_hosts, 'kdc')))
    if hosts_to_lookup:
        if args.verbose:
            print(f"Looking up {len(hosts_to_lookup)} hosts using VPN DNS servers...", file=stderr)
        for host, why in hosts_to_lookup:
            try:
                ips = providers.dns.lookup_host(host)
            except Exception as e:
                print(f"WARNING: Lookup for {host} on VPN DNS servers failed:\n\t{e}", file=stderr)
            else:
                if ips is None:
                    print(f"WARNING: Lookup for {host} on VPN DNS servers returned nothing.", file=stderr)
                else:
                    if args.verbose:
                        print(f"  {host} = {', '.join(map(str, ips))}", file=stderr)
                    ip_routes.update(ips)
                    if why == 'kdc':
                        host_map.extend((ip, [host]) for ip in ips)
                    elif args.host_names:
                        names = names_for(host, args.domain, args.short_names)
                        host_map.extend((ip, names) for ip in ips)
    for ip, aliases in args.aliases.items():
        host_map.append((ip, aliases))

    # add them to /etc/hosts
    if host_map:
        providers.hosts.write_hosts(host_map, args.name)
        if args.verbose:
            print(f"Added hostnames and aliases for {len(host_map)} addresses to /etc/hosts.", file=stderr)

    # add routes to hosts
    for ip in ip_routes:
        if args.verbose > 1:
            print(f"Adding route to {ip} (for named hosts) through {env.tundev}.", file=stderr)
        providers.route.replace_route(ip, dev=env.tundev)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print(f"Added {len(ip_routes)} routes for named hosts.", file=stderr)

    # run DNS queries in background to prevent idle timeout
    if args.prevent_idle_timeout:
        dns = env.dns + env.dns6
        idle_timeout = env.idle_timeout
        setproctitle(f'vpn-slice --prevent-idle-timeout --name {args.name}')
        if args.verbose:
            print(f"Continuing in background as PID {providers.process.pid()}, attempting to prevent idle timeout every {idle_timeout} seconds.")

        while True:
            delay = randint(2 * idle_timeout // 3, 9 * idle_timeout // 10)
            if args.verbose > 1:
                print(f"Sleeping {delay} seconds until we issue a DNS query to prevent idle timeout...", file=stderr)
            sleep(delay)

            # FIXME: netlink(7) may be a much better way to poll here
            if not providers.process.is_alive(args.ppid):
                print(f"Caller (PID {args.ppid}) has terminated; idle preventer exiting.", file=stderr)
                break

            # pick random host or IP to look up without leaking any new information
            # about what we do/don't access within the VPN
            pool = args.hosts
            pool += map(str, chain(env.dns, env.dns6, env.nbns, ((r.network_address) for r in args.subnets if r.prefixlen == r.max_prefixlen)))
            dummy = choice(pool)
            shuffle(dns)
            if args.verbose > 1:
                print(f"Issuing DNS lookup of {dummy} to prevent idle timeout...", file=stderr)
            providers.dns.lookup_host(dummy, keep_going=False)

    elif args.verbose:
        print(f"Connection setup done, child process {providers.process.pid()} exiting.")

########################################

# Translate environment variables which may be passed by our caller
# into a more Pythonic form (these are take from vpnc-script)
reasons = Enum('reasons', 'pre_init connect disconnect reconnect attempt_reconnect')
vpncenv = [
    ('reason', 'reason', lambda x: reasons[x.replace('-', '_')]),
    ('vpnfd', 'VPNFD', int),  # set if OpenConnect invoked in --script-tun/ocproxy mode
    ('gateway', 'VPNGATEWAY', ip_address),
    ('tundev', 'TUNDEV', str),
    ('domain', 'CISCO_DEF_DOMAIN', lambda x: x.split(), []),
    ('splitdns', 'CISCO_SPLIT_DNS', lambda x: x.split(','), []),
    ('banner', 'CISCO_BANNER', str),
    ('myaddr', 'INTERNAL_IP4_ADDRESS', IPv4Address),      # a.b.c.d
    ('mtu', 'INTERNAL_IP4_MTU', int),
    ('netmask', 'INTERNAL_IP4_NETMASK', IPv4Address),     # a.b.c.d
    ('netmasklen', 'INTERNAL_IP4_NETMASKLEN', int),
    ('network', 'INTERNAL_IP4_NETADDR', IPv4Address),     # a.b.c.d
    ('dns', 'INTERNAL_IP4_DNS', lambda x: [ip_address(x) for x in x.split()], []),
    ('nbns', 'INTERNAL_IP4_NBNS', lambda x: [IPv4Address(x) for x in x.split()], []),
    ('myaddr6', 'INTERNAL_IP6_ADDRESS', IPv6Interface),   # x:y::z or x:y::z/p
    ('netmask6', 'INTERNAL_IP6_NETMASK', IPv6Interface),  # x:y:z:: or x:y::z/p
    ('dns6', 'INTERNAL_IP6_DNS', lambda x: [ip_address(x) for x in x.split()], []),
    ('nsplitinc', 'CISCO_SPLIT_INC', int, 0),
    ('nsplitexc', 'CISCO_SPLIT_EXC', int, 0),
    ('nsplitinc6', 'CISCO_IPV6_SPLIT_INC', int, 0),
    ('nsplitexc6', 'CISCO_IPV6_SPLIT_EXC', int, 0),
    ('idle_timeout', 'IDLE_TIMEOUT', int, 600),           # OpenConnect v8.06+
    ('vpnpid', 'VPNPID', int),                            # OpenConnect v9.0+
]

def parse_env(environ=os.environ):
    global vpncenv
    env = slurpy()
    for var, envar, maker, *default in vpncenv:
        if envar in environ:
            try: val = maker(environ[envar])
            except Exception as e:
                print(f'Exception while setting {var} from environment variable {envar}={environ[envar]!r}', file=stderr)
                raise
        elif default: val, = default
        else: val = None
        if var is not None: env[var] = val

    # IPv4 network is the combination of the network address (e.g. 192.168.0.0) and the netmask (e.g. 255.255.0.0)
    if env.network:
        orig_netaddr = env.network
        env.network = IPv4Network(env.network).supernet(new_prefix=env.netmasklen)
        if env.network.network_address != orig_netaddr:
            print(f"WARNING: IPv4 network {orig_netaddr}/{env.netmasklen} has host bits set, replacing with {env.network}", file=stderr)
        assert env.network.netmask == env.netmask, \
            "IPv4 network (INTERNAL_IP4_{{NETADDR,NETMASK}}) {ad}/{nm} does not match INTERNAL_IP4_NETMASKLEN={nml} (implies /{nmi})".format(
                ad=orig_netaddr, nm=env.netmask, nml=env.netmasklen, nmi=env.network.netmask)
        assert env.network.netmask == env.netmask

    # Need to match behavior of original vpnc-script here
    # Examples:
    #   1) INTERNAL_IP6_ADDRESS=fe80::1, INTERNAL_IP6_NETMASK=fe80::/64  => interface of fe80::1/64,  network of fe80::/64
    #   2) INTERNAL_IP6_ADDRESS=unset,   INTERNAL_IP6_NETMASK=fe80::1/64 => interface of fe80::1/64,  network of fe80::/64
    #   3) INTERNAL_IP6_ADDRESS=2000::1, INTERNAL_IP6_NETMASK=unset      => interface of 2000::1/128, network of 2000::1/128
    if env.myaddr6 or env.netmask6:
        if not env.netmask6:
            env.netmask6 = IPv6Network(env.myaddr6)  # case 3 above, /128
        env.myaddr6 = IPv6Interface(env.netmask6)
        env.network6 = env.myaddr6.network
    else:
        env.myaddr6 = None
        env.network6 = None

    env.myaddrs = list(filter(None, (env.myaddr, env.myaddr6)))

    # Handle splits
    env.splitinc = []
    env.splitexc = []
    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc)),
                        (('EXC', n) for n in range(env.nsplitexc))):
        ad = IPv4Address(environ[f'CISCO_SPLIT_{pfx}_{n}_ADDR'])
        nm = IPv4Address(environ[f'CISCO_SPLIT_{pfx}_{n}_MASK'])
        nml = int(environ[f'CISCO_SPLIT_{pfx}_{n}_MASKLEN'])
        net = IPv4Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            print("WARNING: IPv4 split network (CISCO_SPLIT_%s_%d_{ADDR,MASK}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net), file=stderr)
        assert net.netmask == nm, \
            "IPv4 split network (CISCO_SPLIT_{pfx}_{n}_{{ADDR,MASK}}) {ad}/{nm} does not match CISCO_SPLIT_{pfx}_{n}_MASKLEN={nml} (implies /{nmi})".format(
                pfx=pfx, n=n, ad=ad, nm=nm, nml=nml, nmi=net.netmask)
        env['split' + pfx.lower()].append(net)

    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc6)),
                        (('EXC', n) for n in range(env.nsplitexc6))):
        ad = IPv6Address(environ[f'CISCO_IPV6_SPLIT_{pfx}_{n}_ADDR'])
        nml = int(environ[f'CISCO_IPV6_SPLIT_{pfx}_{n}_MASKLEN'])
        net = IPv6Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            print("WARNING: IPv6 split network (CISCO_IPV6_SPLIT_%s_%d_{ADDR,MASKLEN}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net), file=stderr)
        env['split' + pfx.lower()].append(net)

    return env

# Parse command-line arguments and environment
def parse_args_and_env(args=None, environ=os.environ):
    p = argparse.ArgumentParser()
    p.add_argument('routes', nargs='*', type=net_or_host_param, help='List of VPN-internal hostnames, included subnets (e.g. 192.168.0.0/24), excluded subnets (e.g. %%8.0.0.0/8), or aliases (e.g. host1=192.168.1.2) to add to routing and /etc/hosts.')
    g = p.add_argument_group('Subprocess options')
    p.add_argument('-f', '--routes-file', default=None, type=file_path_param, help='Path to List of VPN-internal hostnames, subnets (e.g. 192.168.0.0/24), or aliases (e.g. host1=192.168.1.2) to add to routing and /etc/hosts.')
    g.add_argument('-k', '--kill', default=[], action='append', help='File containing PID to kill before disconnect (may be specified multiple times)')
    g.add_argument('-K', '--prevent-idle-timeout', action='store_true', help='Prevent idle timeout by doing random DNS lookups (interval set by $IDLE_TIMEOUT, defaulting to 10 minutes)')
    g = p.add_argument_group('Informational options')
    g.add_argument('--banner', action='store_true', help='Print banner message (default is to suppress it)')
    g = p.add_argument_group('Routing and hostname options')
    g.add_argument('-i', '--incoming', action='store_true', help='Allow incoming traffic from VPN (default is to block)')
    g.add_argument('-n', '--name', default=None, help='Name of this VPN (default is $TUNDEV)')
    g.add_argument('-d', '--domain', action='append', help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
    g.add_argument('-I', '--route-internal', action='store_true', help="Add route for VPN's default subnet (passed in as $INTERNAL_IP*_NET*")
    g.add_argument('-S', '--route-splits', action='store_true', help="Add route for VPN's split-tunnel subnets (passed in via $CISCO_SPLIT_*)")
    g.add_argument('--no-host-names', action='store_false', dest='host_names', default=True, help='Do not add either short or long hostnames to /etc/hosts')
    g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True, help="Only add long/fully-qualified domain names to /etc/hosts")
    g = p.add_argument_group('Nameserver options')
    g.add_argument('--no-ns-hosts', action='store_false', dest='ns_hosts', default=True, help='Do not add nameserver aliases to /etc/hosts (default is to name them dns0.tun0, etc.)')
    g.add_argument('--nbns', action='store_true', dest='nbns', help='Include NBNS (Windows/NetBIOS nameservers) as well as DNS nameservers')
    g.add_argument('--domains-vpn-dns', dest='vpn_domains', default=None, help="comma separated domains to query with vpn dns")
    g.add_argument('--kerberos-dc', metavar='REALM', help='Lookup Kerberos5 domain controller (DC) hosts for the given realm, and add routes and /etc/hosts entries for them.')
    g = p.add_argument_group('Debugging options')
    g.add_argument('--self-test', action='store_true', help='Stop after verifying that environment variables and providers are configured properly.')
    g.add_argument('-v', '--verbose', default=0, action='count', help="Explain what %(prog)s is doing. Specify repeatedly to increase the level of detail.")
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    g.add_argument('-D', '--dump', action='store_true', help='Dump environment variables passed by caller')
    g.add_argument('--no-fork', action='store_false', dest='fork', help="Don't fork and continue in background on connect")
    g.add_argument('--ppid', type=int, help='PID of calling process (normally autodetected, when using openconnect or vpnc)')
    args = p.parse_args(args)
    env = parse_env(environ)

    # use the tunnel device as the VPN name if unspecified
    if args.name is None:
        args.name = env.tundev

    # use the PID provided by the caller if unspecified
    if args.ppid is None:
        args.ppid = env.vpnpid

    # use the list from the env if --domain wasn't specified, but start with an
    # empty list if it was specified; hence can't use 'default' here:
    if args.domain is None:
        args.domain = env.domain

    args.subnets = []
    args.exc_subnets = []
    args.hosts = []
    args.aliases = {}

    # read routes from a file
    if args.routes_file:
        args.routes.extend([
            net_or_host_param(x)
            for x in read_routes_file(args.routes_file)
            ])

    for x in args.routes:
        if isinstance(x, str):
            args.hosts.append(x)
        elif x[0] in (True, False):
            include, net = x
            if include: args.subnets.append(net)
            else: args.exc_subnets.append(net)
        else:
            hosts, ip = x
            args.aliases.setdefault(ip, []).extend(hosts)
    if args.route_internal:
        if env.network: args.subnets.append(env.network)
        if env.network6: args.subnets.append(env.network6)
    if args.route_splits:
        args.subnets.extend(env.splitinc)
        args.exc_subnets.extend(env.splitexc)
    if args.vpn_domains is not None:
        args.vpn_domains = str.split(args.vpn_domains, ',')

    return p, args, env

def finalize_args_and_env(args, env):
    global providers

    # autodetect parent or grandparent process (skipping intermediary shell)
    if args.ppid is None:
        args.ppid = providers.process.ppid_of(None)
        exe = providers.process.pid2exe(args.ppid)
        if exe and os.path.basename(exe) in ('dash', 'bash', 'sh', 'tcsh', 'csh', 'ksh', 'zsh'):
            args.ppid = providers.process.ppid_of(args.ppid)


def main(args=None, environ=os.environ):
    global providers

    self_test = False
    try:
        p, args, env = parse_args_and_env(args, environ)
        self_test = args.self_test

        # Set platform-specific providers
        providers = slurpy()
        for pn, pv in get_default_providers().items():
            try:
                if isinstance(pv, Exception):
                    raise pv
                providers[pn] = pv()
            except Exception as e:
                print(f"WARNING: Couldn't configure {pn} provider: {e}", file=stderr)

        # Fail if necessary providers are missing
        required = {'route', 'process'}
        # The hosts provider is required unless:
        #   1) '--no-ns-hosts --no-host-names' specified, '--kerberos-dc' unspecified or
        #   2) '--no-ns-hosts' specified, and '--kerberos-dc' unspecified, and neither hosts nor aliases specified
        if not args.ns_hosts and not args.host_names and not args.kerberos_dc:
            pass
        elif not args.ns_hosts and not args.kerberos_dc and not args.hosts and not args.aliases:
            pass
        else:
            required.add('hosts')
        # The DNS provider is required if:
        #   1) Any hosts are specified
        #   2) '--prevent-idle-timeout' is specified
        if args.hosts or args.prevent_idle_timeout:
            required.add('dns')
        missing_required = {p for p in required if p not in providers}
        if missing_required:
            raise RuntimeError(f"Aborting because providers for {' '.join(missing_required)} are required; use --help for more information")

        # Finalize arguments that depend on providers
        finalize_args_and_env(args, env)

    except Exception as e:
        if self_test:
            print('******************************************************************************************', file=stderr)
            print('*** Self-test did not pass. Double-check that you are running as root (e.g. with sudo) ***', file=stderr)
            print('******************************************************************************************', file=stderr)
        raise SystemExit(*e.args)

    else:
        if self_test:
            print('***************************************************************************', file=stderr)
            print('*** Self-test passed. Try using vpn-slice with openconnect or vpnc now. ***', file=stderr)
            print('***************************************************************************', file=stderr)
            raise SystemExit()

    if env.myaddr6 or env.netmask6:
        print(f'WARNING: IPv6 address or netmask set. Support for IPv6 in {p.prog} should be considered BETA-QUALITY.', file=stderr)
    if args.dump:
        exe = providers.process.pid2exe(args.ppid)
        caller = f'{exe} (PID {args.ppid})' if exe else f'PID {args.ppid}'

        print(f'Called by {caller} with environment variables for vpnc-script:', file=stderr)
        width = max((len(envar) for var, envar, *rest in vpncenv if envar in environ), default=0)
        for var, envar, *rest in vpncenv:
            if envar in environ:
                pyvar = var + '=' + repr(env[var]) if var else 'IGNORED'
                print('  %-*s => %s' % (width, envar, pyvar), file=stderr)
        if env.splitinc:
            print('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_INC_*', 'splitinc', env.splitinc), file=stderr)
        if env.splitexc:
            print('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_EXC_*', 'splitexc', env.splitexc), file=stderr)
        if args.subnets:
            print('Complete set of subnets to include in VPN routes:', file=stderr)
            print('  ' + '\n  '.join(map(str, args.subnets)))
        if args.exc_subnets:
            print('Complete set of subnets to exclude from VPN routes:', file=stderr)
            print('  ' + '\n  '.join(map(str, args.exc_subnets)))
        if args.aliases:
            print('Complete set of host aliases to add /etc/hosts entries for:', file=stderr)
            print('  ' + '\n  '.join('%s -> %s' % (ip, ', '.join(a)) for (ip, a) in args.aliases.items()))
        if args.hosts:
            print('Complete set of host names to include in VPN routes after DNS lookup%s:' % (' (and add /etc/hosts entries for)' if args.host_names else ''), file=stderr)
            print('  ' + '\n  '.join(args.hosts))

    if env.reason is None:
        if env.vpnfd is not None:
            raise SystemExit("Called by openconnect in --script-tun mode; you need a different script. See https://www.infradead.org/openconnect/nonroot.html")
        else:
            raise SystemExit("Must be called as vpnc-script, with $reason set; use --help for more information")
    elif env.reason == reasons.pre_init:
        do_pre_init(env, args)
    elif env.reason == reasons.disconnect:
        do_disconnect(env, args)
    elif env.reason in (reasons.reconnect, reasons.attempt_reconnect):
        # FIXME: is there anything that reconnect or attempt_reconnect /should/ do
        # on a modern system (Linux) which automatically removes routes to
        # a tunnel interface that has been removed? I am not clear on whether
        # any other behavior is potentially useful.
        #
        # See these issue comments for some relevant discussion:
        #   https://gitlab.com/openconnect/openconnect/issues/17#note_131764677
        #   https://github.com/dlenski/vpn-slice/pull/14#issuecomment-488129621

        if args.verbose:
            print(f'WARNING: {p.prog} ignores reason={env.reason.name}', file=stderr)
    elif env.reason == reasons.connect:
        do_connect(env, args)

        # we continue running in a new child process, so the VPN can actually
        # start in the background, because we need to actually send traffic to it
        if args.fork and os.fork():
            raise SystemExit

        do_post_connect(env, args)


if __name__ == '__main__':
    main()
