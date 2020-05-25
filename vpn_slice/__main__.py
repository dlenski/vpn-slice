#!/usr/bin/env python3

from __future__ import print_function
from sys import stderr, platform
import os, subprocess as sp
import argparse
from enum import Enum
from itertools import chain, zip_longest
from ipaddress import ip_network, ip_address, IPv4Address, IPv4Network, IPv6Address, IPv6Network, IPv6Interface
from time import sleep
from random import randint, choice, shuffle

try:
    from setproctitle import setproctitle
except ImportError:
    def setproctitle(title):
        pass

def tagged(iter, tag):
    return zip_longest(iter, (), fillvalue=tag)

from .version import __version__
from .util import slurpy


def get_default_providers():
    global platform
    try:
        from .dnspython import DNSPythonProvider
    except ImportError:
        DNSPythonProvider = None

    if platform.startswith('linux'):
        from .linux import ProcfsProvider, Iproute2Provider, IptablesProvider, CheckTunDevProvider
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
        from .mac import PsProvider, BSDRouteProvider
        from .posix import PosixHostsFileProvider
        from .dnspython import DNSPythonProvider
        return dict(
            process = PsProvider,
            route = BSDRouteProvider,
            dns = DNSPythonProvider or DigProvider,
            hosts = PosixHostsFileProvider,
        )
    else:
        return dict(
            platform = OSError('Your platform, {}, is unsupported'.format(platform))
        )


def net_or_host_param(s):
    if '=' in s:
        hosts = s.split('=')
        ip = hosts.pop()
        return hosts, ip_address(ip)
    else:
        try:
            return ip_network(s, strict=False)
        except ValueError:
            return s


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
        except (IOError, ValueError):
            print("WARNING: could not read pid from %s" % pidfile, file=stderr)
        else:
            try: providers.process.kill(pid)
            except OSError as e:
                print("WARNING: could not kill pid %d from %s: %s" % (pid, pidfile, str(e)), file=stderr)
            else:
                if args.verbose:
                    print("Killed pid %d from %s" % (pid, pidfile), file=stderr)

    removed = providers.hosts.write_hosts({}, args.name)
    if args.verbose:
        print("Removed %d hosts from /etc/hosts" % removed, file=stderr)

    # delete explicit route to gateway
    try:
        providers.route.remove_route(env.gateway)
    except sp.CalledProcessError:
        print("WARNING: could not delete route to VPN gateway (%s)" % env.gateway, file=stderr)

    # remove firewall rule blocking incoming traffic
    if 'firewall' in providers and not args.incoming:
        try:
            providers.firewall.deconfigure_firewall(env.tundev)
        except sp.CalledProcessError:
            print("WARNING: failed to deconfigure firewall for VPN interface (%s)" % env.tundev, file=stderr)

def do_connect(env, args):
    global providers
    if args.banner and env.banner:
        print("Connect Banner:")
        for l in env.banner.splitlines(): print("| "+l)

    # set explicit route to gateway
    gwr = providers.route.get_route(env.gateway)
    providers.route.replace_route(env.gateway, **gwr)
    if args.verbose > 1:
        print("Set explicit route to VPN gateway %s (%s)" % (env.gateway, ', '.join('%s %s' % kv for kv in gwr.items())), file=stderr)

    # drop incoming traffic from VPN
    if not args.incoming:
        if 'firewall' not in providers:
            print("WARNING: no firewall provider available; can't block incoming traffic", file=stderr)
        else:
            try:
                providers.firewall.configure_firewall(env.tundev)
                if args.verbose:
                    print("Blocked incoming traffic from VPN interface with iptables.", file=stderr)
            except sp.CalledProcessError:
                try:
                    providers.firewall.deconfigure_firewall(env.tundev)
                except sp.CalledProcessError:
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
            print("WARNING: guessing MTU is %d (the MTU of %s - 88)" % (mtu, dev), file=stderr)
        else:
            mtu = 1412
            print("WARNING: guessing default MTU of %d (couldn't determine MTU of %s)" % (mtu, dev), file=stderr)
    providers.route.set_link_info(env.tundev, state='up', mtu=mtu)

    # set IPv4, IPv6 addresses for tunnel device
    if env.myaddr:
        providers.route.add_address(env.tundev, env.myaddr)
    if env.myaddr6:
        providers.route.add_address(env.tundev, env.myaddr6)

    # save routes for excluded subnets
    exc_subnets = [(dest, providers.route.get_route(dest)) for dest in args.exc_subnets]

    # set up routes to the DNS and Windows name servers, subnets, and local aliases
    ns = env.dns + env.dns6 + (env.nbns if args.nbns else [])
    for dest, tag in chain(tagged(ns, "nameserver"), tagged(args.subnets, "subnet"), tagged(args.aliases, "alias")):
        if args.verbose > 1:
            print("Adding route to %s %s through %s." % (tag, dest, env.tundev), file=stderr)
        providers.route.replace_route(dest, dev=env.tundev)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print("Added routes for %d nameservers, %d subnets, %d aliases." % (len(ns), len(args.subnets), len(args.aliases)), file=stderr)

    # restore routes to excluded subnets
    for dest, exc_route in exc_subnets:
        providers.route.replace_route(dest, **exc_route)
        if args.verbose > 1:
            print("Restoring split-exclude route to %s (%s)" % (dest, ', '.join('%s %s' % kv for kv in exc_route.items())), file=stderr)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print("Restored routes for %d excluded subnets." % len(exc_subnets), exc_subnets, file=stderr)

def do_post_connect(env, args):
    global providers
    # lookup named hosts for which we need routes and/or host_map entries
    # (the DNS/NBNS servers already have their routes)
    ip_routes = set()
    host_map = []

    if args.ns_hosts:
        ns_names = [ (ip, ('dns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.dns + env.dns6) ]
        if args.nbns:
            ns_names += [ (ip, ('nbns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.nbns) ]
        host_map += ns_names
        if args.verbose:
            print("Adding /etc/hosts entries for %d nameservers..." % len(ns_names), file=stderr)
            for ip, names in ns_names:
                print("  %s = %s" % (ip, ', '.join(map(str, names))), file=stderr)

    if args.verbose:
        print("Looking up %d hosts using VPN DNS servers..." % len(args.hosts), file=stderr)
    providers.dns.configure(dns_servers=(env.dns + env.dns6), search_domains=args.domain, bind_addresses=env.myaddrs)
    for host in args.hosts:
        try:
           ips = providers.dns.lookup_host(host)
        except Exception as e:
            print("WARNING: Lookup for %s on VPN DNS servers failed:\n\t%s" % (host, e), file=stderr)
        else:
            if ips is None:
                print("WARNING: Lookup for %s on VPN DNS servers returned nothing." % host, file=stderr)
            else:
                if args.verbose:
                    print("  %s = %s" % (host, ', '.join(map(str, ips))), file=stderr)
                ip_routes.update(ips)
                if args.host_names:
                    names = names_for(host, args.domain, args.short_names)
                    host_map.extend((ip, names) for ip in ips)
    for ip, aliases in args.aliases.items():
        host_map.append((ip, aliases))

    # add them to /etc/hosts
    if host_map:
        providers.hosts.write_hosts(host_map, args.name)
        if args.verbose:
            print("Added hostnames and aliases for %d addresses to /etc/hosts." % len(host_map), file=stderr)

    # add routes to hosts
    for ip in ip_routes:
        if args.verbose > 1:
            print("Adding route to %s (for named hosts) through %s." % (ip, env.tundev), file=stderr)
        providers.route.replace_route(ip, dev=env.tundev)
    else:
        providers.route.flush_cache()
        if args.verbose:
            print("Added %d routes for named hosts." % len(ip_routes), file=stderr)

    # run DNS queries in background to prevent idle timeout
    if args.prevent_idle_timeout:
        dev = env.tundev
        dns = (env.dns + env.dns6)
        idle_timeout = env.idle_timeout
        setproctitle('vpn-slice --prevent-idle-timeout --name %s' % args.name)
        if args.verbose:
            print("Continuing in background as PID %d, attempting to prevent idle timeout every %d seconds." % (providers.process.pid(), idle_timeout))

        while True:
            delay = randint(2 * idle_timeout // 3, 9 * idle_timeout // 10)
            if args.verbose > 1:
                print("Sleeping %d seconds until we issue a DNS query to prevent idle timeout..." % delay, file=stderr)
            sleep(delay)

            # FIXME: netlink(7) may be a much better way to poll here
            if not providers.process.is_alive(args.ppid):
                print("Caller (PID %d) has terminated; idle preventer exiting." % args.ppid, file=stderr)
                break

            # pick random host or IP to look up without leaking any new information
            # about what we do/don't access within the VPN
            pool = args.hosts
            pool += map(str, chain(env.dns, env.dns6, env.nbns, ((r.network_address) for r in args.subnets if r.prefixlen==r.max_prefixlen)))
            dummy = choice(pool)
            shuffle(dns)
            if args.verbose > 1:
                print("Issuing DNS lookup of %s to prevent idle timeout..." % dummy, file=stderr)
            providers.dns.lookup_host(dummy, keep_going=False)

    elif args.verbose:
        print("Connection setup done, child process %d exiting." % providers.process.pid())

########################################

# Translate environment variables which may be passed by our caller
# into a more Pythonic form (these are take from vpnc-script)
reasons = Enum('reasons', 'pre_init connect disconnect reconnect attempt_reconnect')
vpncenv = [
    ('reason','reason',lambda x: reasons[x.replace('-','_')]),
    ('gateway','VPNGATEWAY',ip_address),
    ('tundev','TUNDEV',str),
    ('domain','CISCO_DEF_DOMAIN',lambda x: x.split(),[]),
    ('banner','CISCO_BANNER',str),
    ('myaddr','INTERNAL_IP4_ADDRESS',IPv4Address), # a.b.c.d
    ('mtu','INTERNAL_IP4_MTU',int),
    ('netmask','INTERNAL_IP4_NETMASK',IPv4Address), # a.b.c.d
    ('netmasklen','INTERNAL_IP4_NETMASKLEN',int),
    ('network','INTERNAL_IP4_NETADDR',IPv4Address), # a.b.c.d
    ('dns','INTERNAL_IP4_DNS',lambda x: [ip_address(x) for x in x.split()],[]),
    ('nbns','INTERNAL_IP4_NBNS',lambda x: [IPv4Address(x) for x in x.split()],[]),
    ('myaddr6','INTERNAL_IP6_ADDRESS',IPv6Interface), # x:y::z or x:y::z/p
    ('netmask6','INTERNAL_IP6_NETMASK',IPv6Interface), # x:y:z:: or x:y::z/p
    ('dns6','INTERNAL_IP6_DNS',lambda x: [ip_address(x) for x in x.split()],[]),
    ('nsplitinc','CISCO_SPLIT_INC',int,0),
    ('nsplitexc','CISCO_SPLIT_EXC',int,0),
    ('nsplitinc6','CISCO_IPV6_SPLIT_INC',int,0),
    ('nsplitexc6','CISCO_IPV6_SPLIT_EXC',int,0),
    ('idle_timeout','IDLE_TIMEOUT',int,600),
]

def parse_env(environ=os.environ):
    global vpncenv
    env = slurpy()
    for var, envar, maker, *default in vpncenv:
        if envar in environ:
            try: val = maker(environ[envar])
            except Exception as e:
                print('Exception while setting %s from environment variable %s=%r' % (var, envar, environ[envar]), file=stderr)
                raise
        elif default: val, = default
        else: val = None
        if var is not None: env[var] = val

    # IPv4 network is the combination of the network address (e.g. 192.168.0.0) and the netmask (e.g. 255.255.0.0)
    if env.network:
        orig_netaddr = env.network
        env.network = IPv4Network(env.network).supernet(new_prefix=env.netmasklen)
        if env.network.network_address != orig_netaddr:
            print("WARNING: IPv4 network %s/%d has host bits set, replacing with %s" % (orig_netaddr, env.netmasklen, env.network), file=stderr)
        if env.network.netmask!=env.netmask:
            raise AssertionError("IPv4 network (INTERNAL_IP4_{{NETADDR,NETMASK}}) {ad}/{nm} does not match INTERNAL_IP4_NETMASKLEN={nml} (implies /{nmi})".format(
                ad=orig_netaddr, nm=env.netmask, nml=env.netmasklen, nmi=env.network.netmask))
        assert env.network.netmask==env.netmask

    # Need to match behavior of original vpnc-script here
    # Examples:
    #   1) INTERNAL_IP6_ADDRESS=fe80::1, INTERNAL_IP6_NETMASK=fe80::/64  => interface of fe80::1/64,  network of fe80::/64
    #   2) INTERNAL_IP6_ADDRESS=unset,   INTERNAL_IP6_NETMASK=fe80::1/64 => interface of fe80::1/64,  network of fe80::/64
    #   3) INTERNAL_IP6_ADDRESS=2000::1, INTERNAL_IP6_NETMASK=unset      => interface of 2000::1/128, network of 2000::1/128
    if env.myaddr6 or env.netmask6:
        if not env.netmask6:
            env.netmask6 = IPv6Network(env.myaddr6) # case 3 above, /128
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
        ad = IPv4Address(environ['CISCO_SPLIT_%s_%d_ADDR' % (pfx, n)])
        nm = IPv4Address(environ['CISCO_SPLIT_%s_%d_MASK' % (pfx, n)])
        nml = int(environ['CISCO_SPLIT_%s_%d_MASKLEN' % (pfx, n)])
        net = IPv4Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            print("WARNING: IPv4 split network (CISCO_SPLIT_%s_%d_{ADDR,MASK}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net), file=stderr)
        if net.netmask!=nm:
            raise AssertionError("IPv4 split network (CISCO_SPLIT_{pfx}_{n}_{{ADDR,MASK}}) {ad}/{nm} does not match CISCO_SPLIT_{pfx}_{n}_MASKLEN={nml} (implies /{nmi})".format(
                pfx=pfx, n=n, ad=ad, nm=nm, nml=nml, nmi=net.netmask))
        env['split'+pfx.lower()].append(net)

    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc6)),
                        (('EXC', n) for n in range(env.nsplitexc6))):
        ad = IPv6Address(environ['CISCO_IPV6_SPLIT_%s_%d_ADDR' % (pfx, n)])
        nml = int(environ['CISCO_IPV6_SPLIT_%s_%d_MASKLEN' % (pfx, n)])
        net = IPv6Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            print("WARNING: IPv6 split network (CISCO_IPV6_SPLIT_%s_%d_{ADDR,MASKLEN}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net), file=stderr)
        env['split'+pfx.lower()].append(net)

    return env

# Parse command-line arguments and environment
def parse_args_and_env(args=None, environ=os.environ):
    p = argparse.ArgumentParser()
    p.add_argument('routes', nargs='*', type=net_or_host_param, help='List of VPN-internal hostnames, subnets (e.g. 192.168.0.0/24), or aliases (e.g. host1=192.168.1.2) to add to routing and /etc/hosts.')
    g = p.add_argument_group('Subprocess options')
    p.add_argument('-k','--kill', default=[], action='append', help='File containing PID to kill before disconnect (may be specified multiple times)')
    p.add_argument('-K','--prevent-idle-timeout', action='store_true', help='Prevent idle timeout by doing random DNS lookups (interval set by $IDLE_TIMEOUT, defaulting to 10 minutes)')
    g = p.add_argument_group('Informational options')
    g.add_argument('--banner', action='store_true', help='Print banner message (default is to suppress it)')
    g = p.add_argument_group('Routing and hostname options')
    g.add_argument('-i','--incoming', action='store_true', help='Allow incoming traffic from VPN (default is to block)')
    g.add_argument('-n','--name', default=None, help='Name of this VPN (default is $TUNDEV)')
    g.add_argument('-d','--domain', action='append', help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
    g.add_argument('-I','--route-internal', action='store_true', help="Add route for VPN's default subnet (passed in as $INTERNAL_IP*_NET*")
    g.add_argument('-S','--route-splits', action='store_true', help="Add route for VPN's split-tunnel subnets (passed in via $CISCO_SPLIT_*)")
    g.add_argument('--no-host-names', action='store_false', dest='host_names', default=True, help='Do not add either short or long hostnames to /etc/hosts')
    g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True, help="Only add long/fully-qualified domain names to /etc/hosts")
    g = p.add_argument_group('Nameserver options')
    g.add_argument('--no-ns-hosts', action='store_false', dest='ns_hosts', default=True, help='Do not add nameserver aliases to /etc/hosts (default is to name them dns0.tun0, etc.)')
    g.add_argument('--nbns', action='store_true', dest='nbns', help='Include NBNS (Windows/NetBIOS nameservers) as well as DNS nameservers')
    g = p.add_argument_group('Debugging options')
    g.add_argument('--self-test', action='store_true', help='Stop after verifying that environment variables and providers are configured properly.')
    g.add_argument('-v','--verbose', default=0, action='count', help="Explain what %(prog)s is doing")
    p.add_argument('-V','--version', action='version', version='%(prog)s ' + __version__)
    g.add_argument('-D','--dump', action='store_true', help='Dump environment variables passed by caller')
    g.add_argument('--no-fork', action='store_false', dest='fork', help="Don't fork and continue in background on connect")
    g.add_argument('--ppid', type=int, help='PID of calling process (normally autodetected, when using openconnect or vpnc)')
    args = p.parse_args(args)
    env = parse_env(environ)
    return p, args, env

def finalize_args_and_env(args, env):
    global providers

    # use the tunnel device as the VPN name if unspecified
    if args.name is None:
        args.name = env.tundev

    # autodetect parent or grandparent process (skipping intermediary shell)
    if args.ppid is None:
        args.ppid = providers.process.ppid_of(None)
        exe = providers.process.pid2exe(args.ppid)
        if exe and os.path.basename(exe) in ('dash','bash','sh','tcsh','csh','ksh','zsh'):
            args.ppid = providers.process.ppid_of(args.ppid)

    # use the list from the env if --domain wasn't specified, but start with an
    # empty list if it was specified; hence can't use 'default' here:
    if args.domain is None:
        args.domain = env.domain

    args.subnets = []
    args.exc_subnets = []
    args.hosts = []
    args.aliases = {}
    for x in args.routes:
        if isinstance(x, (IPv4Network, IPv6Network)):
            args.subnets.append(x)
        elif isinstance(x, str):
            args.hosts.append(x)
        else:
            hosts, ip = x
            args.aliases.setdefault(ip, []).extend(hosts)
    if args.route_internal:
        if env.network: args.subnets.append(env.network)
        if env.network6: args.subnets.append(env.network6)
    if args.route_splits:
        args.subnets.extend(env.splitinc)
        args.exc_subnets.extend(env.splitexc)

def main(args=None, environ=os.environ):
    global providers

    try:
        p, args, env = parse_args_and_env(args, environ)

        providers = slurpy()
        for pn, pv in get_default_providers().items():
            try:
                if isinstance(pv, Exception):
                    raise pv
                providers[pn] = pv()
            except Exception as e:
                print("WARNING: Couldn't configure {} provider: {}".format(pn, e), file=stderr)
        missing_required = {p for p in ('route', 'process', 'hosts', 'dns') if p not in providers}
        if missing_required:
            raise RuntimeError("Aborting because providers for %s are required; use --help for more information" % ' '.join(missing_required))

        finalize_args_and_env(args, env)

        if env.myaddr6 or env.netmask6:
            print('WARNING: IPv6 address or netmask set. Support for IPv6 in %s should be considered BETA-QUALITY.' % p.prog, file=stderr)
        if args.dump:
            exe = providers.process.pid2exe(args.ppid)
            caller = '%s (PID %d)'%(exe, args.ppid) if exe else 'PID %d' % args.ppid

            print('Called by %s with environment variables for vpnc-script:' % caller, file=stderr)
            width = max((len(envar) for var, envar, *rest in vpncenv if envar in environ), default=0)
            for var, envar, *rest in vpncenv:
                if envar in environ:
                    pyvar = var+'='+repr(env[var]) if var else 'IGNORED'
                    print('  %-*s => %s' % (width, envar, pyvar), file=stderr)
            if env.splitinc:
                print('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_INC_*', 'splitinc', env.splitinc), file=stderr)
            if env.splitexc:
                print('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_EXC_*', 'splitexc', env.splitexc), file=stderr)

    except Exception as e:
        if args.self_test:
            print('******************************************************************************************', file=stderr)
            print('*** Self-test did not pass. Double-check that you are running as root (e.g. with sudo) ***', file=stderr)
            print('******************************************************************************************', file=stderr)
        raise SystemExit(*e.args)

    else:
        if args.self_test:
            print('***************************************************************************', file=stderr)
            print('*** Self-test passed. Try using vpn-slice with openconnect or vpnc now. ***', file=stderr)
            print('***************************************************************************', file=stderr)
            raise SystemExit()

    if env.reason is None:
        raise SystemExit("Must be called as vpnc-script, with $reason set; use --help for more information")
    elif env.reason==reasons.pre_init:
        do_pre_init(env, args)
    elif env.reason==reasons.disconnect:
        do_disconnect(env, args)
    elif env.reason in (reasons.reconnect, reasons.attempt_reconnect):
        # FIXME: is there anything that reconnect or attempt_reconnect /should/ do
        # on a modern system (Linux) which automatically removes routes to
        # a tunnel adapter that has been removed? I am not clear on whether
        # any other behavior is potentially useful.
        #
        # See these issue comments for some relevant discussion:
        #   https://gitlab.com/openconnect/openconnect/issues/17#note_131764677
        #   https://github.com/dlenski/vpn-slice/pull/14#issuecomment-488129621

        if args.verbose:
            print('WARNING: %s ignores reason=%s' % (p.prog, env.reason.name), file=stderr)
    elif env.reason==reasons.connect:
        do_connect(env, args)

        # we continue running in a new child process, so the VPN can actually
        # start in the background, because we need to actually send traffic to it
        if args.fork and os.fork():
            raise SystemExit

        do_post_connect(env, args)

if __name__=='__main__':
    main()
