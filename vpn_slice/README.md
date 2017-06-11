
Table of Contents
=================

  * [vpn-slice](#vpn-slice)
    * [Who this is for](#who-this-is-for)
    * [Requirements](#requirements)
    * [Usage](#usage)
  * [Inspiration](#inspiration)
  * [Alternatives](#alternatives)
  * [License](#license)
    * [TODO](#todo)

# vpn-slice

This is a replacement for the
[`vpnc-script`](http://www.infradead.org/openconnect/vpnc-script.html)
used by [OpenConnect](http://www.infradead.org/openconnect) or
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
* [`dig`](https://en.wikipedia.org/wiki/Dig_(command)) (DNS lookup
  tool; tested with v9.9.5)
* Linux OS (the [`iproute2`](https://en.wikipedia.org/wiki/iproute2)
  and [`iptables`](http://en.wikipedia.org/wiki/iptables) utilities
  are used for all routing setup)

You can install the latest build with `pip` (make sure you are using
the Python 3.x version, usually invoked with `pip3`):

    $ pip3 install https://github.com/dlenski/vpn-slice/archive/master.zip

## Usage

You should specify `vpn-slice` as your connection script with
`openconnect` or `vpnc`. It has been tested with vpnc v0.5.3, OpenConnect
v7.06-v7.08 (with both Cisco AnyConnect and Juniper protocols), and also
[my OpenConnect fork that supports PAN GlobalProtect](//github.com/dlenski/openconnect-gp).

For example:

    $ sudo openconnect gateway.bigcorp.com -u user1234 \
        -s 'vpn-slice 192.168.1.0/24 hostname1 alias2=192.168.1.43'
    $ cat /etc/hosts
    ...
    192.168.1.1 dns0.tun0					# vpn-slice-tun0 AUTOCREATED
    192.168.1.2 dns1.tun0					# vpn-slice-tun0 AUTOCREATED
    192.168.1.57 hostname1 hostname1.bigcorp.com		# vpn-slice-tun0 AUTOCREATED
    192.168.1.43 alias2		# vpn-slice-tun0 AUTOCREATED

or

    # With vpnc, you *must* specify an absolute path for the disconnect hook
    # to work correctly, due to a bug which I reported:
    #   http://lists.unix-ag.uni-kl.de/pipermail/vpnc-devel/2016-August/004199.html
    $ sudo vpnc config_file \
           --script '/path/to/vpn-slice 192.168.1.0/24 hostname1 alias2=192.168.1.43'

Notice that `vpn-slice` accepts both *hostnames alone* (`hostname1`) as well as
*host-to-IP* aliases (`alias2=192.168.1.43`). The former are first looked up using the
VPN's DNS servers. Both are also added to the routing table, as well as to
`/etc/hosts` (unless `--no-host-names` is specified).

There are many command-line options to alter the behavior of
`vpn-slice`; try `vpn-slice --help` to show them all.

Running with `--verbose` makes it explain what it is doing, while running with
`--dump` shows the environment variables passed in by the caller.

# Inspiration

[**@jagtesh**](https://github.com/jagtesh)'s
[split-tunnelling tutorial gist](https://gist.github.com/jagtesh/5531300) taught me the
basics of how to set up a split-tunnel VPN by wrapping the standard `vpnc-script`.

[**@apenwarr**](https://github.com/apenwarr)'s
[sshuttle](https://github.com/apenwarr/sshuttle) has the excellent
`--auto-hosts` and `--seed-hosts` options. These inspired the
automatic host lookup feature.

# Alternatives
[**@cernekee**](https://github.com/cernekee/ocproxy)'s ocproxy is also a great alternative
# License

GPLv3 or later.

## TODO

* Fix timing issues
* Improve IPv6 support
* Support OSes other than Linux?
* Handle `CISCO_SPLIT_*` environment variables.
