# vpn-slice

This is a replacement for the `vpnc-script` used by
[OpenConnect](http://www.infradead.org/openconnect/vpnc-script.html)
or [VPNC](https://www.unix-ag.uni-kl.de/~massar/vpnc/).

Instead of trying to copy the behavior of the standard Cisco VPN clients,
which normally reroute **all** your network traffic through the VPN,
this one tries to minimize your contact with an intrusive corporate VPN:

* It only routes traffic for **specific hosts or subnets** through the VPN.
* It automatically looks up named hosts, using the VPN's DNS servers,
  and adds entries for them to your `/etc/hosts` (which it cleans up
  after VPN disconnection), however it **does not otherwise alter your
  `/etc/resolv.conf` at all**.

## Who this is for

If you are using a VPN to route *all* your traffic (such as for
privacy or to avoid censorship in repressive countries), you **do not
want this**.

This is for people who have to connect to rapacious corporate VPNs
which monitor and filter and otherwise impede their network traffic,
and wish to route as little traffic as possible through those VPNs.

## Requirements

* Python 3.3+
* DiG (DNS lookup tool; tested with v9.9.5)
* Modern version of Linux (it calls `ip` for all routing setup)

## Usage

You should specific this as your connection script with `openconnect` or
`vpnc` (I've tested it with) both, for example:

    $ sudo openconnect gateway.bigcorp.com -u user1234 \
           -s 'vpn-slice.py 192.168.1.0/24 hostname1 hostname2'

or

    $ sudo vpnc config_file \
           --script 'vpn-slice.py 192.168.1.0/24 hostname1 hostname2'

There are many command-line options to alter the behavior of `vpn-slice.py`.
Running with `--verbose` makes it explain what it is doing, while running with
`--dump` shows the environment variables passed in by the caller:

    usage: vpn-slice.py [-h] [-k KILL] [--no-fork] [-v] [--banner] [--dump]
                        [-n NAME] [-d DOMAIN] [--no-host-lookup]
                        [--no-short-names] [--no-ns-lookup]
                        [hosts [hosts ...]]

    positional arguments:
      hosts                 List of VPN-internal hostnames or subnets to add to
                            routing and /etc/hosts

    optional arguments:
      -h, --help            show this help message and exit
      -k KILL, --kill KILL  File containing PID to kill before disconnect
      --no-fork             Don't fork and continue in background on connect

    Informational options:
      -v, --verbose         Show what I am doing during connect and disconnect
      --banner              Pass banner message (default is to suppress it)
      --dump                Dump environment variables passed by caller to vpnc-
                            script

    Routing and hostname options:
      -n NAME, --name NAME  Name of this VPN (default is $TUNDEV)
      -d DOMAIN, --domain DOMAIN
                            Search domain inside the VPN (default is
                            $CISCO_DEF_DOMAIN)
      --no-host-lookup      Do not add either short or long hostnames to
                            /etc/hosts
      --no-short-names      Only add long/fully-qualified domain names to
                            /etc/hosts
      --no-ns-lookup        Do not lookup nameservers and add them to /etc/hosts

## TODO

* Fix timing issues
* IPv6 support?
* Support OS other than Linux
