#!/usr/bin/env python3

from __future__ import print_function
from sys import stderr, argv
import signal
from collections import OrderedDict
import os, subprocess as sp
import argparse
from enum import Enum
from itertools import chain
from ipaddress import ip_network, ip_address, IPv4Address, IPv4Network, IPv6Address, IPv6Network, IPv6Interface

from .version import __version__
if os.uname().sysname=='Linux':
    from .linux import pid2exe, ppidof, check_tun, write_hosts, dig, iproute, iptables, find_paths
else:
    raise OSError('non-Linux operating system is unsupported')

# Quacks like a dict and an object
class slurpy(dict):
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError as e:
            raise AttributeError(*e.args)
    def __setattr__(self, k, v):
        self[k]=v

def net_or_host_param(s):
    if '=' in s:
        hosts = s.split('=')
        ip = hosts.pop()
        return hosts, ip_address(ip)
    else:
        try:
            return ip_network(s)
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
    check_tun()

def do_disconnect(env, args):
    for pidfile in args.kill:
        try:
            pid = int(open(pidfile).read())
            os.kill(pid, signal.SIGTERM)
            if args.verbose:
                print("Killed pid %d from %s" % (pid, pidfile), file=stderr)
        except (IOError, ValueError, OSError):
            pass

    removed = write_hosts({}, 'vpn-slice-%s AUTOCREATED' % args.name)
    if args.verbose:
        print("Removed %d hosts from /etc/hosts" % removed, file=stderr)

    # delete explicit route to gateway
    try:
        iproute('route', 'del', env.gateway)
    except sp.CalledProcessError:
        print("WARNING: could not delete route to VPN gateway (%s)" % env.gateway, file=stderr)

    # remove iptables rules for incoming traffic
    if not args.incoming:
        try:
            iptables('-D','INPUT','-i',env.tundev,'-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT')
            iptables('-D','INPUT','-i',env.tundev,'-j','DROP')
        except sp.CalledProcessError:
            print("WARNING: failed to remove iptables rules for VPN interface (%s); check iptables -S" % env.tundev, file=stderr)

def do_connect(env, args):
    if args.banner and env.banner:
        print("Connect Banner:")
        for l in env.banner.splitlines(): print("| "+l)

    # set explicit route to gateway
    gwr = iproute('route', 'get', env.gateway)
    iproute('route', 'replace', env.gateway, gwr)

    # drop incoming traffic from VPN
    if not args.incoming:
        try:
            iptables('-A','INPUT','-i',env.tundev,'-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT')
            try:
                iptables('-A','INPUT','-i',env.tundev,'-j','DROP')
            except sp.CalledProcessError:
                iptables('-D','INPUT','-i',env.tundev,'-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT')
                raise
            if args.verbose:
                print("Blocked incoming traffic from VPN interface with iptables.", file=stderr)
        except sp.CalledProcessError:
            print("WARNING: failed to block incoming traffic", file=stderr)

    # configure MTU
    mtu = env.mtu
    if mtu is None:
        dev = gwr.get('dev')
        mtudev = dev and iproute('link', 'show', dev).get('mtu')
        mtu = mtudev and int(mtudev) - 88
        if mtu:
            print("WARNING: guessing MTU is %d (the MTU of %s - 88)" % (mtu, dev), file=stderr)
        else:
            mtu = 1412
            print("WARNING: guessing default MTU of %d (couldn't determine MTU of %s)" % (mtu, dev), file=stderr)
    iproute('link', 'set', 'dev', env.tundev, 'up', 'mtu', mtu)

    # set IPv4, IPv6 addresses for tunnel device
    if env.myaddr:
        iproute('addr', 'add', env.myaddr, 'dev', env.tundev)
    if env.myaddr6:
        iproute('addr', 'add', env.myaddr6, 'dev', env.tundev)

    # save routes for excluded subnets
    exc_subnets = [(dest, iproute('route', 'get', dest)) for dest in args.exc_subnets]

    # set up routes to the DNS and Windows name servers, subnets, and local aliases
    ns = env.dns + (env.nbns if args.nbns else [])
    for dest in chain(ns, args.subnets, args.aliases):
        iproute('route', 'replace', dest, 'dev', env.tundev)
    else:
        iproute('route', 'flush', 'cache')
        if args.verbose:
            print("Added routes for %d nameservers, %d subnets, %d aliases." % (len(ns), len(args.subnets), len(args.aliases)), file=stderr)

    # restore routes to excluded subnets
    for dest, exc_route in exc_subnets:
        iproute('route', 'replace', dest, exc_route)
    else:
        iproute('route', 'flush', 'cache')
        if args.verbose:
            print("Restored routes for %d excluded subnets." % len(exc_subnets), file=stderr)

def do_post_connect(env, args):
    # lookup named hosts for which we need routes and/or host_map entries
    # (the DNS/NBNS servers already have their routes)
    ip_routes = set()
    host_map = []

    if args.ns_hosts:
        ns_names = [ (ip, ('dns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.dns) ]
        if args.nbns:
            ns_names += [ (ip, ('nbns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.nbns) ]
        host_map += ns_names
        if args.verbose:
            print("Adding /etc/hosts entries for %d nameservers..." % len(ns_names), file=stderr)
            for ip, names in ns_names:
                print("  %s = %s" % (ip, ', '.join(map(str, names))), file=stderr)

    if args.verbose:
        print("Looking up %d hosts using VPN DNS servers..." % len(args.hosts), file=stderr)
    for host in args.hosts:
        ips = dig(env.myaddr, host, env.dns, args.domain)
        if ips is None:
            print("WARNING: Lookup for %s on VPN DNS servers failed." % host, file=stderr)
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
        write_hosts(host_map, 'vpn-slice-%s AUTOCREATED' % args.name)
        if args.verbose:
            print("Added hostnames and aliases for %d addresses to /etc/hosts." % len(host_map), file=stderr)

    # add routes to hosts
    for ip in ip_routes:
        iproute('route', 'replace', ip, 'dev', env.tundev)
    else:
        iproute('route', 'flush', 'cache')
        if args.verbose:
            print("Added %d routes for named hosts." % len(ip_routes), file=stderr)

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
    ('dns','INTERNAL_IP4_DNS',lambda x: [IPv4Address(x) for x in x.split()],[]),
    ('nbns','INTERNAL_IP4_NBNS',lambda x: [IPv4Address(x) for x in x.split()],[]),
    ('myaddr6','INTERNAL_IP6_ADDRESS',IPv6Interface), # x:y::z or x:y::z/p
    ('netmask6','INTERNAL_IP6_NETMASK',IPv6Interface), # x:y:z:: or x:y::z/p
    ('dns6','INTERNAL_IP6_DNS',lambda x: [IPv6Address(x) for x in x.split()],[]),
    ('nsplitinc','CISCO_SPLIT_INC',int,0),
    ('nsplitexc','CISCO_SPLIT_EXC',int,0),
    ('nsplitinc6','CISCO_IPV6_SPLIT_INC',int,0),
    ('nsplitexc6','CISCO_IPV6_SPLIT_EXC',int,0),
]

def parse_env(env=None, environ=os.environ):
    global vpncenv
    if env is None:
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
        env.network = IPv4Network(env.network).supernet(new_prefix=env.netmasklen)
        assert env.network.netmask==env.netmask

    # IPv6 network is determined by the netmask only
    # (e.g. /16 supplied as part of the address, or ffff:ffff:ffff:ffff:: supplied as separate netmask)
    if env.myaddr6:
        env.network6 = env.netmask6.network if env.netmask6 else env.myaddr6.network
        env.myaddr6 = env.myaddr6.ip

    # Handle splits
    env.splitinc = []
    env.splitexc = []
    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc)),
                        (('EXC', n) for n in range(env.nsplitexc))):
        ad = IPv4Address(environ['CISCO_SPLIT_%s_%d_ADDR' % (pfx, n)])
        nm = IPv4Address(environ['CISCO_SPLIT_%s_%d_MASK' % (pfx, n)])
        nml = int(environ['CISCO_SPLIT_%s_%d_MASKLEN' % (pfx, n)])
        net = IPv4Network(ad).supernet(new_prefix=nml)
        if net.netmask!=nm:
            raise AssertionError("Netmask supplied in CISCO_SPLIT_%s_%d_MASK (%s) does not match the %d-bit prefix (_MASKLEN) of the network address %s (_ADDR)\n\t%s != %s" % (pfx, n, nm, nml, ad, nm, net.netmask))
        env['split'+pfx.lower()].append(net)

    return env

# Parse command-line arguments
def parse_args(env, args=None):
    p = argparse.ArgumentParser()
    p.add_argument('routes', nargs='*', type=net_or_host_param, help='List of VPN-internal hostnames, subnets (e.g. 192.168.0.0/24), or aliases (e.g. host1=192.168.1.2) to add to routing and /etc/hosts.')
    g = p.add_argument_group('Subprocess options')
    p.add_argument('-k','--kill', default=[], action='append', help='File containing PID to kill before disconnect (may be specified multiple times)')
    g = p.add_argument_group('Informational options')
    g.add_argument('--banner', action='store_true', help='Print banner message (default is to suppress it)')
    g = p.add_argument_group('Routing and hostname options')
    g.add_argument('-i','--incoming', action='store_true', help='Allow incoming traffic from VPN (default is to block)')
    g.add_argument('-n','--name', default=env.tundev, help='Name of this VPN (default is $TUNDEV)')
    g.add_argument('-d','--domain', action='append', help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
    g.add_argument('-I','--route-internal', action='store_true', help="Add route for VPN's default subnet (passed in as $INTERNAL_IP*_NET*")
    g.add_argument('-S','--route-splits', action='store_true', help="Add route for VPN's split-tunnel subnets (passed in via $CISCO_SPLIT_*)")
    g.add_argument('--no-host-names', action='store_false', dest='host_names', default=True, help='Do not add either short or long hostnames to /etc/hosts')
    g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True, help="Only add long/fully-qualified domain names to /etc/hosts")
    g = p.add_argument_group('Nameserver options')
    g.add_argument('--no-ns-hosts', action='store_false', dest='ns_hosts', default=True, help='Do not add nameserver aliases to /etc/hosts (default is to name them dns0.tun0, etc.)')
    g.add_argument('--nbns', action='store_true', dest='nbns', help='Include NBNS (Windows/NetBIOS nameservers) as well as DNS nameservers')
    g = p.add_argument_group('Debugging options')
    g.add_argument('-v','--verbose', action='store_true', help="Explain what %(prog)s is doing")
    g.add_argument('-D','--dump', action='store_true', help='Dump environment variables passed by caller')
    g.add_argument('--no-fork', action='store_false', dest='fork', help="Don't fork and continue in background on connect")
    p.add_argument('-V','--version', action='version', version='%(prog)s ' + __version__)
    args = p.parse_args(args, slurpy())

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
    return p, args

def main():
    env = parse_env()
    p, args = parse_args(env)
    if env.reason is None:
        p.error("Must be called as vpnc-script, with $reason set")

    if args.dump:
        ppid = os.getppid()
        exe = pid2exe(ppid)
        if os.path.basename(exe) in ('dash','bash','sh','tcsh','csh','ksh','zsh'):
            ppid = ppidof(ppid)
            exe = pid2exe(ppid)
        caller = '%s (PID %d)'%(exe, ppid) if exe else 'PID %d' % ppid

        print('Called by %s with environment variables for vpnc-script:' % caller, file=stderr)
        width = max(len(envar) for var, envar, *rest in vpncenv if envar in os.environ)
        for var, envar, *rest in vpncenv:
            if envar in os.environ:
                pyvar = var+'='+repr(env[var]) if var else 'IGNORED'
                print('  %-*s => %s' % (width, envar, pyvar), file=stderr)
        if env.splitinc:
            print('  %-*s => %s=%r' % (width, 'CISCO_SPLIT_INC_*', 'splitinc', env.splitinc), file=stderr)
        if env.splitexc:
            print('  %-*s => %s=%r' % (width, 'CISCO_SPLIT_EXC_*', 'splitexc', env.splitexc), file=stderr)

    if env.myaddr6 or env.netmask6:
        print('WARNING: IPv6 address or netmask set, but this version of %s has only rudimentary support for them.' % p.prog, file=stderr)
    if env.dns6:
        print('WARNING: IPv6 DNS servers set, but this version of %s does not know how to handle them' % p.prog, file=stderr)
    if any(v.startswith('CISCO_IPV6_SPLIT_') for v in os.environ):
        print('WARNING: CISCO_IPV6_SPLIT_* environment variables set, but this version of %s does not handle them' % p.prog, file=stderr)

    find_paths() # find paths of utilities used

    if env.reason==reasons.pre_init:
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
