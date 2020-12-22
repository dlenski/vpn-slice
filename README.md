vpn-slice
=========

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://github.com/dlenski/vpn-slice/workflows/test_and_release/badge.svg)](https://github.com/dlenski/vpn-slice/actions?query=workflow%3Atest_and_release)
[![PyPI](https://img.shields.io/pypi/v/vpn-slice.svg)](https://pypi.python.org/pypi/vpn-slice)
[![Homebrew](https://img.shields.io/homebrew/v/vpn-slice.svg)](https://formulae.brew.sh/formula/vpn-slice)

Table of Contents
=================

  * [Introduction](#introduction)
    * [Who this is for](#who-this-is-for)
    * [Requirements](#requirements)
    * [First steps](#first-steps)
    * [Usage](#usage)
    * [Diagnostics](#diagnostics)
  * [Inspiration and credits](#inspiration-and-credits)
  * [License](#license)
    * [TODO](#todo)

## Introduction

This is a replacement for the
[`vpnc-script`](https://www.infradead.org/openconnect/vpnc-script.html)
used by [OpenConnect](https://www.infradead.org/openconnect) or
[VPNC](https://www.unix-ag.uni-kl.de/~massar/vpnc).

Instead of trying to copy the behavior of standard corporate VPN clients,
which normally reroute **all** your network traffic through the VPN,
this one tries to _minimize your contact_ with an intrusive VPN.
This is also known as a
[split-tunnel](https://en.wikipedia.org/wiki/Split_tunneling) VPN, since
it splits your traffic between the VPN tunnel and your normal network
interfaces.

`vpn-slice` makes it easy to set up a split-tunnel VPN:

* It only routes traffic for **specific hosts or subnets** through the VPN.
* It automatically looks up named hosts, using the VPN's DNS servers,
  and adds entries for them to your `/etc/hosts` (which it cleans up
  after VPN disconnection), however it **does not otherwise alter your
  `/etc/resolv.conf` at all**.

## Who this is for

If you are using a VPN to route *all* your traffic for privacy reasons
(or to avoid censorship in repressive countries), then you **do not want
to use this**.

The purpose of this tool is almost the opposite; it makes it easy to
connect to a VPN while **minimizing** the traffic that passes over the
VPN.

This is for people who have to connect to the high-security VPNs of
corporations or other bureaucracies (which monitor and filter and
otherwise impede network traffic), and thus wish to route as little
traffic as possible through those VPNs.

## Requirements

* Python 3.3+
* Either of the following:
  * [`dnspython`](https://pypi.org/project/dnspython) module (**preferred**, tested with v1.16.0)
  * [`dig`](https://en.wikipedia.org/wiki/Dig_(command)) command-line DNS lookup tool (tested with v9.9.5 and v9.10.3)
* Supported OSes:
  * Linux kernel 3.x+ with
    [`iproute2`](https://en.wikipedia.org/wiki/iproute2) and
    [`iptables`](https://en.wikipedia.org/wiki/iptables) utilities
    (used for all routing setup)
  * macOS 10.x with BSD
    [`route`](https://en.wikipedia.org/wiki/Route_(command))
  * FreeBSD with BSD
    [`route`](https://en.wikipedia.org/wiki/Route_(command))
    if [`procfs`](https://www.freebsd.org/cgi/man.cgi?query=procfs&sektion=5) is mounted

You can install the latest build with `pip` (make sure you are using
the Python 3.x version, usually invoked with `pip3`).

You should install as `root` (e.g. using `sudo`), because
`openconnect` or `vpnc` will need to be able to invoke `vpn-slice`
while running as root:

    $ sudo pip3 install https://github.com/dlenski/vpn-slice/archive/master.zip

On macOS, you can also install using [Homebrew](https://brew.sh):

    $ brew install vpn-slice

## First steps

Before trying to use `vpn-slice` with `openconnect` or `vpnc`,
check that it works properly on your platform, and can verify that it has all of
the access and dependencies that it needs (to modify `/etc/hosts`, alter
routing table, etc.):

    $ sudo vpn-slice --self-test
    ***************************************************************************
    *** Self-test passed. Try using vpn-slice with openconnect or vpnc now. ***
    ***************************************************************************

If you run the self-test as a non-`root` user, it will tell you what required
access it is unable to obtain:

    $ vpn-slice --self-test
    WARNING: Couldn't configure hosts provider: Cannot read/write /etc/hosts
    ******************************************************************************************
    *** Self-test did not pass. Double-check that you are running as root (e.g. with sudo) ***
    ******************************************************************************************
    Aborting because providers for hosts are required; use --help for more information

When you start trying to use `vpn-slice` for real, you should use the
[diagnostic options](#diagnostics) (e.g `openconnect -s 'vpn-slice
--verbose --dump'`) to troubleshoot and understand its behavior.

## Usage

You should specify `vpn-slice` as your connection script with
`openconnect` or `vpnc`. It has been tested with vpnc v0.5.3, OpenConnect
v7.06+ (Cisco AnyConnect and Juniper protocols) and v8.0+ (PAN GlobalProtect
protocol).

For example:

```sh
$ sudo openconnect gateway.bigcorp.com -u user1234 \
    -s 'vpn-slice 192.168.1.0/24 hostname1 alias2=alias2.bigcorp.com=192.168.1.43'
$ cat /etc/hosts
...
192.168.1.1 dns0.tun0					# vpn-slice-tun0 AUTOCREATED
192.168.1.2 dns1.tun0					# vpn-slice-tun0 AUTOCREATED
192.168.1.57 hostname1 hostname1.bigcorp.com		# vpn-slice-tun0 AUTOCREATED
192.168.1.43 alias2 alias2.bigcorp.com		# vpn-slice-tun0 AUTOCREATED
```

or

```sh
# With most versions of vpnc, you *must* specify an absolute path
# for the disconnect hook to work correctly, due to a bug.
#
# I reported this bug, but the original maintainers no longer maintain vpnc.
#   https://lists.unix-ag.uni-kl.de/pipermail/vpnc-devel/2016-August/004199.html
#
# However, some Linux distro packagers have picked up my patch in recent
# releases, e.g. Ubuntu 17.04:
#   https://changelogs.ubuntu.com/changelogs/pool/universe/v/vpnc/vpnc_0.5.3r550-3/changelog
#
$ sudo vpnc config_file \
       --script '/path/to/vpn-slice 192.168.1.0/24 hostname1 alias2=alias2.bigcorp.com=192.168.1.43'
```

Notice that `vpn-slice` accepts both *hostnames alone* (`hostname1`) as well as
host-to-IP* aliases (`alias2=alias2.bigcorp.com=192.168.1.43`). The former are first looked up using the
VPN's DNS servers. Both are also added to the routing table, as well as to
`/etc/hosts` (unless `--no-host-names` is specified). As in this
example, multiple aliases can be specified for a single IP address.

There are many command-line options to alter the behavior of
`vpn-slice`; try `vpn-slice --help` to show them all.

# Diagnostics

Running with `--verbose` makes it explain what it is doing, while running with
`--dump` shows the environment variables passed in by the caller.

# Inspiration and credits

* [**@jagtesh**](https://github.com/jagtesh)'s
  [split-tunnelling tutorial gist](https://gist.github.com/jagtesh/5531300) taught me the
  basics of how to set up a split-tunnel VPN by wrapping the standard `vpnc-script`.
* [**@apenwarr**](https://github.com/apenwarr)'s
  [sshuttle](https://github.com/apenwarr/sshuttle) has the excellent
  `--auto-hosts` and `--seed-hosts` options. These inspired the
  automatic host lookup feature.
* [**@gmacon**](https://github.com/gmacon)'s
  [PR #11](https://github.com/dlenski/vpn-slice/pull/11) substantially
  refactored the code to separate the OS-dependent parts more
  cleanly, and added macOS support.
* [**@joelbu**](https://github.com/joelbu)'s
  [PR #30](https://github.com/dlenski/vpn-slice/pull/30) added support for IPv6 DNS
  lookups using `dig`.

# License

GPLv3 or later.

## TODO / Help Wanted

* Better error-explaining
* Fix timing issues
* Improve IPv6 support
* Support OSes other than Linux and macOS
    * Other Unix-like operating systems should be pretty easy
* Mechanism for specifying split-_exclude_ subnets on the command line
