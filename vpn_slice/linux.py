import os, fcntl
import subprocess as sp

DIG = '/usr/bin/dig'
IPROUTE = '/sbin/ip'
HOSTS = '/etc/hosts'
IPTABLES = '/sbin/iptables'

def pid2exe(pid):
    try:
        return os.readlink('/proc/%d/exe' % pid)
    except (OSError, IOError):
        return None

def ppidof(pid):
    try:
        return int(next(open('/proc/%d/stat'%pid)).split()[3])
    except (OSError, ValueError, IOError):
        pass

def check_tun():
    if not os.access('/dev/net/tun', os.R_OK|os.W_OK):
        raise OSError("can't read and write /dev/net/tun")

def write_hosts(host_map, tag):
    global HOSTS
    with open(HOSTS,'r+') as hostf:
        fcntl.flock(hostf, fcntl.LOCK_EX) # POSIX only, obviously
        lines = hostf.readlines()
        keeplines = [l for l in lines if not l.endswith('# %s\n'%tag)]
        hostf.seek(0,0)
        hostf.writelines(keeplines)
        for ip, names in host_map:
            print('%s %s\t\t# %s' % (ip, ' '.join(names), tag), file=hostf)
        hostf.truncate()
    return len(host_map) or len(lines)-len(keeplines)

def dig(host, dns, domain=None, reverse=False):
    global DIG
    host, dns = str(host), map(str, dns)
    cl = [DIG,'+short']+['@'+s for s in dns]+(['+domain='+domain] if domain else [])+(['-x'] if reverse else [])+[host]
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

def iproute(*args):
    global IPROUTE
    cl = [IPROUTE]
    for arg in args:
        if isinstance(arg, dict):
            for k,v in arg.items():
                cl += [k] if v is None else [k, str(v)]
        else:
            cl.append(str(arg))

    if args[:2]==('route','get'): get, start, keys = 'route', 1, ('via','dev','src','mtu')
    elif args[:2]==('link','show'): get, start, keys = 'link', 3, ('mtu','state')
    else: get = None

    if get is None:
        sp.check_call(cl)
    else:
        w = sp.check_output(cl).decode().split()
        return {w[ii]:w[ii+1] for ii in range(start, len(w), 2) if w[ii] in keys}

def iptables(*args):
    global IPTABLES
    cl = [IPTABLES] + list(args)
    sp.check_call(cl)
