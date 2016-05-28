#!/usr/bin/env python3

from __future__ import print_function
from sys import stderr
import os, fcntl, time, subprocess as sp
import argparse
from collections import OrderedDict as odict
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network

def networkify(host):
    try:
        return ip_network(host)
    except ValueError:
        return host

def add_splits_to_env(split_routes, env):
    for ii,n in enumerate(split_routes):
        if isinstance(n, (IPv4Network, IPv6Network)):
            net, mask = n.network_address, n.prefixlen
        else:
            net, mask = n
            n = ip_network(net+'/'+mask)

        v = 'IPV6_' if isinstance(n, IPv6Network) else ''
        env['CISCO_%sSPLIT_INC_%d_ADDR'%(v,ii)] = str(net)
        env['CISCO_%sSPLIT_INC_%d_MASK'%(v,ii)] = str(mask)
        env['CISCO_%sSPLIT_INC_%d_MASKLEN'%(v,ii)] = str(n.prefixlen)
        env['CISCO_%sSPLIT_INC'%v] = str( int(env.get('CISCO_%sSPLIT_INC'%v,0))+1 )

def dig(host, dns, domain=None, reverse=False):
    cl = ['/usr/bin/dig','+short']+['@'+s for s in dns]+(['+domain='+domain] if domain else [])+(['-x'] if reverse else [])+[host]
    #print cl
    p = sp.Popen(cl, stdout=sp.PIPE)
    out = [l.strip() for l in p.communicate()[0].decode().splitlines()]
    if out and p.wait()==0:
        out = out[-1].rstrip('\n.')
        if reverse and out.split('.',1)[-1]==domain:
            out = out.split('.',1)[0]
        return out
    else:
        return None

# Environment variables which may be passed by our caller (as listed in /usr/share/vpnc-scripts/vpnc-script)
evs = ['reason', 'VPNGATEWAY', 'TUNDEV', 'CISCO_DEF_DOMAIN', 'CISCO_BANNER',
       'INTERNAL_IP4_ADDRESS', 'INTERNAL_IP4_MTU', 'INTERNAL_IP4_NETMASK', 'INTERNAL_IP4_NETMASKLEN', 'INTERNAL_IP4_NETADDR', 'INTERNAL_IP4_DNS', 'INTERNAL_IP4_NBNS',
       'INTERNAL_IP6_ADDRESS',                     'INTERNAL_IP6_NETMASK',                                                    'INTERNAL_IP4_DNS' ]
env = odict((k,os.environ[k]) for k in evs if k in os.environ)

reason = env.get('reason')
tundev = env.get('TUNDEV')
dns = env.get('INTERNAL_IP4_DNS','').split()
nbns = env.get('INTERNAL_IP4_NBNS','').split()
domain = env.get('CISCO_DEF_DOMAIN')

# Parse command-line arguments
p = argparse.ArgumentParser()
p.add_argument('hosts', nargs='*', type=networkify, help='List of VPN-internal hostnames or subnets to add to routing and /etc/hosts')
g = p.add_argument_group('Subprocess options')
p.add_argument('-s','--script', default='/usr/share/vpnc-scripts/vpnc-script', help='Real vpnc-script to call (default %(default)s)')
p.add_argument('-k','--kill', default=[], action='append', help='File containing PID to kill before disconnect')
g = p.add_argument_group('Informational options')
g.add_argument('-v','--verbose', action='store_true', help="Show what I am doing during connect and disconnect")
g.add_argument('--banner', action='store_true', help='Pass banner message (default is to suppress it)')
g.add_argument('--dump', action='store_true', help='Dump environment variables passed by caller to vpnc-script')
g = p.add_argument_group('Routing and hostname options')
g.add_argument('-n','--name', default=tundev, help='Name of this VPN (default is $TUNDEV)')
g.add_argument('-d','--domain', default=domain, help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
g.add_argument('-N','--route-net', action='store_true', help='Add a route to the whole VPN internal network (default is to route only to specific hosts)')
g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True, help='Only add fully-qualified domain names to /etc/hosts (default is both short and FQDN)')
g.add_argument('--no-host-lookup', action='store_false', dest='host_lookup', default=True, help='Do not lookup hosts and add them to /etc/hosts')
g.add_argument('--no-ns-lookup', action='store_false', dest='ns_lookup', default=True, help='Do not lookup nameservers and add them to /etc/hosts')
args = p.parse_args()

subnets = [x for x in args.hosts if isinstance(x, (IPv4Network, IPv6Network))]
hosts = [x for x in args.hosts if not isinstance(x, (IPv4Network, IPv6Network))]
if not args.banner:
    env.pop('CISCO_BANNER',None)
if reason is None:
    p.error("Must be called as vpnc-script, with $reason set")

if args.dump:
    print('Called with environment variables for vpnc-script:', file=stderr)
    for var,val in env.items():
        print('  %s=%s' % (var, repr(val)), file=stderr)

if reason=='connect':
    # set up split routes to the DNS and Windows name servers
    add_splits_to_env(((ip,'255.255.255.255') for ip in dns+nbns), env)
    # ... and any other subnets specified on command line
    add_splits_to_env(subnets, env)
    # prevent addition of default internal network route unless explicitly specified
    if not args.route_net:
       env.pop('INTERNAL_IP4_NETADDR',None)
       env.pop('INTERNAL_IP4_NETMASK',None)
       env.pop('INTERNAL_IP4_NETMASKLEN',None)
    # we don't want the vpnc-script to disturb our real resolv.conf
    env.pop('INTERNAL_IP4_DNS',None)
    env.pop('INTERNAL_IP4_NBNS',None)
    env.pop('CISCO_DEF_DOMAIN',None)

elif reason=='disconnect':
    for pidfile in args.kill:
        try:
            pid = int(open(pidfile).read())
            os.kill(pid, 15) # SIGTERM=15
            if args.verbose:
                print("Killed pid %d from %s" % (pid, pidfile), file=stderr)
        except (IOError, ValueError, OSError):
            pass

    with open('/etc/hosts','r+') as hostf:
        fcntl.flock(hostf, fcntl.LOCK_EX) # POSIX only, obviously
        lines = hostf.readlines()
        newlines = [l for l in lines if not l.endswith('# vpn-slice-%s AUTOCREATED\n' % args.name)]
        hostf.seek(0, 0)
        hostf.writelines(newlines)
        hostf.truncate()
    if args.verbose:
        print("Removed %d hosts from /etc/hosts" % (len(lines)-len(newlines)), file=stderr)

# run main script
if reason != 'connect':
    os.execve(args.script, [args.script], env)
else:
    # wait for real script to finish:
    sp.check_call([args.script], env=env)

    # ... then continue running in a new child process, so the VPN can actually
    # start in the background
    if os.fork(): raise SystemExit

    # figure out hosts for which we need routes and/or host_map entries
    # (DNS/NBNS servers should ALREADY have routes courtesy of vpnc-script)
    ip_routes = set()
    host_map = []

    if args.ns_lookup:
        if args.verbose:
            print("Doing reverse lookup for %d nameservers..." % (len(dns)+len(nbns)), file=stderr)
        for ip in dns+nbns:
            host = dig(ip, dns, args.domain, reverse=True)
            if host is None:
                print("WARNING: Reverse lookup for %s on VPN DNS servers (%s) failed." % (ip, ', '.join(dns)), file=stderr)
            else:
                host_names = []
                if '.' in host:
                    host_names.append(host)
                else:
                    if args.short_names: host_names.append(host)
                    if args.domain: host_names.append(host+'.'+args.domain)
                if args.verbose:
                    print("  %s = %s" % (ip, host_names))
                host_map.append((ip, host_names))

    if args.verbose:
        print("Looking up %d hosts using VPN DNS servers..." % len(args.hosts), file=stderr)
    for host in hosts:
        ip = dig(host, dns, args.domain)
        if ip is None:
            print("WARNING: Lookup for %s on VPN DNS servers (%s) failed." % (host, ', '.join(dns)), file=stderr)
        else:
            if args.verbose:
                print("  %s = %s" % (host, ip), file=stderr)
            ip_routes.add(ip)
            if args.host_lookup:
                host_names = []
                if '.' in host:
                    host_names.append(host)
                else:
                    if args.short_names: host_names.append(host)
                    if args.domain: host_names.append(host+'.'+args.domain)
                host_map.append((ip, host_names))

    # add them to /etc/hosts
    if host_map:
        with open('/etc/hosts','a') as hostf:
            fcntl.flock(hostf, fcntl.LOCK_EX) # POSIX only, obviously
            for ip, hostnames in host_map:
                hostf.write('%s %s\t\t# vpn-slice-%s AUTOCREATED\n' % (ip, ' '.join(hostnames), args.name))
        if args.verbose:
            print("Added %d VPN hosts to /etc/hosts." % len(host_map), file=stderr)

    # add routes to hosts
    for ip in ip_routes:
        sp.check_call(['/sbin/ip','route','replace',ip+'/32','dev',tundev])
    else:
        sp.check_call(['/sbin/ip','route','flush','cache'])
        if args.verbose:
            print("Added routes for %d VPN IP address." % len(ip_routes), file=stderr)
