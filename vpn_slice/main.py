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
        host, ip = s.split('=', 1)
        return host, ip_address(ip)
    else:
        try:
            return ip_network(s)
        except ValueError:
            return s


def names_for(host, domain, short=True, long=True):
    if '.' in host: first, rest = host.split('.', 1)
    else: first, rest = host, None

    names = []
    if long:
        if rest: names.append(host)
        elif domain: names.append(host+'.'+domain)
    if short:
        if not rest: names.append(host)
        elif rest==domain: names.append(first)
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

    # set IPv4 address for tunnel device
    iproute('addr', 'add', env.myaddr, 'dev', env.tundev)

    # set IPv6 address for tunnel device
    iproute('addr', 'add', env.myaddr6, 'dev', env.tundev)

    # set up routes to the DNS and Windows name servers, subnets, and local aliases
    ns = env.dns + (env.nbns if args.nbns else [])
    for dest in chain(ns, args.subnets, args.aliases):
        iproute('route', 'replace', dest, 'dev', env.tundev)
    else:
        iproute('route', 'flush', 'cache')
        if args.verbose:
            print("Added routes for %d nameservers, %d subnets, %d aliases." % (len(ns), len(args.subnets), len(args.aliases)), file=stderr)

def do_post_connect(env, args):
    # lookup named hosts for which we need routes and/or host_map entries
    # (the DNS/NBNS servers already have their routes)
    ip_routes = set()
    host_map = []

    if args.ns_lookup:
        nsl = env.dns + (env.nbns if args.nbns else [])
        if args.verbose:
            print("Doing reverse lookup for %d nameservers..." % len(nsl), file=stderr)
        for ip in nsl:
            host = dig(ip, env.dns, args.domain, reverse=True)
            if host is None:
                print("WARNING: Reverse lookup for %s on VPN DNS servers failed." % ip, file=stderr)
            else:
                names = names_for(host, args.domain, args.short_names)
                if args.verbose:
                    print("  %s = %s" % (ip, ', '.join(names)))
                host_map.append((ip, names))

    if args.verbose:
        print("Looking up %d hosts using VPN DNS servers..." % len(args.hosts), file=stderr)
    for host in args.hosts:
        ip = dig(host, env.dns, args.domain)
        if ip is None:
            print("WARNING: Lookup for %s on VPN DNS servers failed." % host, file=stderr)
        else:
            if args.verbose:
                print("  %s = %s" % (host, ip), file=stderr)
            ip_routes.add(ip)
            if args.host_names:
                names = names_for(host, args.domain, args.short_names)
                host_map.append((ip, names))
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
            print("Added routes for %d named hosts." % len(ip_routes), file=stderr)

########################################

# Translate environment variables which may be passed by our caller
# into a more Pythonic form (these are take from vpnc-script)
reasons = Enum('reasons', 'pre_init connect disconnect reconnect')
vpncenv = [
    ('reason','reason',lambda x: reasons[x.replace('-','_')]),
    ('gateway','VPNGATEWAY',ip_address),
    ('tundev','TUNDEV',str),
    ('domain','CISCO_DEF_DOMAIN',str),
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
    g.add_argument('-d','--domain', default=env.domain, help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
    g.add_argument('-I','--route-internal', action='store_true', help="Add route for VPN's default subnet (passed in as $INTERNAL_IP4_NETADDR/$INTERNAL_IP4_NETMASKLEN)")
    g.add_argument('--no-host-names', action='store_false', dest='host_names', default=True, help='Do not add either short or long hostnames to /etc/hosts')
    g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True, help="Only add long/fully-qualified domain names to /etc/hosts")
    g.add_argument('--no-ns-lookup', action='store_false', dest='ns_lookup', default=True, help='Do not lookup nameservers or add them to /etc/hosts')
    g.add_argument('--nbns', action='store_true', dest='nbns', help='Include NBNS (Windows/NetBIOS nameservers) as well as DNS nameservers')
    g = p.add_argument_group('Debugging options')
    g.add_argument('-v','--verbose', action='store_true', help="Explain what %(prog)s is doing")
    g.add_argument('-D','--dump', action='store_true', help='Dump environment variables passed by caller')
    g.add_argument('--no-fork', action='store_false', dest='fork', help="Don't fork and continue in background on connect")
    args = p.parse_args(args, slurpy())

    args.subnets = []
    args.hosts = []
    args.aliases = {}
    for x in args.routes:
        if isinstance(x, (IPv4Network, IPv6Network)):
            args.subnets.append(x)
        elif isinstance(x, str):
            args.hosts.append(x)
        else:
            host, ip = x
            args.aliases.setdefault(ip, []).append(host)
    if args.route_internal:
        if env.network: args.subnets.append(env.network)
        if env.network6: args.subnets.append(env.network6)
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

    find_paths() # find paths of utilities used

    if env.myaddr6 or env.netmask6 or env.dns6:
        print('WARNING: IPv6 variables set, but this version of %s does not know how to handle them' % p.prog, file=stderr)

    if env.reason==reasons.pre_init:
        do_pre_init(env, args)
    elif env.reason==reasons.disconnect:
        do_disconnect(env, args)
    elif env.reason==reasons.connect:
        do_connect(env, args)

        # we continue running in a new child process, so the VPN can actually
        # start in the background, because we need to actually send traffic to it
        if args.fork and os.fork():
            raise SystemExit

        do_post_connect(env, args)

if __name__=='__main__':
    main()
