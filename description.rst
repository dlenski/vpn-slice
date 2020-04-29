vpn-slice
=========

This is a replacement for the
`vpnc-script <https://www.infradead.org/openconnect/vpnc-script.html>`__
used by `OpenConnect <https://www.infradead.org/openconnect>`__ or
`VPNC <https://www.unix-ag.uni-kl.de/~massar/vpnc>`__.

Instead of trying to copy the behavior of standard corporate VPN
clients, which normally reroute **all** your network traffic through
the VPN, this one tries to *minimize your contact* with an intrusive
corporate VPN. This is also known as a `split-tunnel
<https://en.wikipedia.org/wiki/Split_tunneling>`__ VPN, since it splits
your traffic between the VPN tunnel and your normal network
interfaces.

``vpn-slice`` makes it easy to set up a split-tunnel VPN:

-  It only routes traffic for **specific hosts or subnets** through the
   VPN.
-  It automatically looks up named hosts, using the VPN's DNS servers,
   and adds entries for them to your ``/etc/hosts`` (which it cleans up
   after VPN disconnection), however it **does not otherwise alter your**
   ``/etc/resolv.conf`` **at all**.

Requirements
------------

-  Python 3.3+
-  Either of the following:
    - `dnspython <https://pypi.org/project/dnspython>`__ module (**preferred**, tested with v1.16.0)
    - `dig <https://en.wikipedia.org/wiki/Dig_(command)>`__ command-line DNS lookup tool (tested with v9.9.5 and v9.10.3)
-  Supported OSes:
    -  Linux kernel 3.x+ with
       `iproute2 <https://en.wikipedia.org/wiki/iproute2>`__ and
       `iptables <https://en.wikipedia.org/wiki/iptables>`__ utilities
       (used for all routing setup)
    -  macOS 10.x

Usage
-----

You should specify ``vpn-slice`` as your connection script with
``openconnect`` or ``vpnc``. It has been tested with vpnc v0.5.3, OpenConnect
v7.06+ (Cisco AnyConnect and Juniper protocols) and v8.0+ (PAN GlobalProtect
protocol).

For example:

::

    $ sudo openconnect gateway.bigcorp.com -u user1234 \
        -s 'vpn-slice 192.168.1.0/24 hostname1 hostname2'
    $ cat /etc/hosts
    ...
    192.168.1.1 dnsmain00 dnsmain00.bigcorp.com         # vpn-slice-tun0 AUTOCREATED
    192.168.1.2 dnsbackup2 dnsmain2.bigcorp.com         # vpn-slice-tun0 AUTOCREATED
    192.168.1.57 hostname1 hostname1.bigcorp.com        # vpn-slice-tun0 AUTOCREATED
    192.168.1.173 hostname1 hostname1.bigcorp.com       # vpn-slice-tun0 AUTOCREATED

Notice that ``vpn-slice`` accepts both *hostnames alone*
(``hostname1``) as well as host-to-IP* aliases
(``alias2=alias2.bigcorp.com=192.168.1.43``). The former are first
looked up using the VPN's DNS servers. Both are also added to the
routing table, as well as to ``/etc/hosts`` (unless
``--no-host-names`` is specified). As in this example, multiple
aliases can be specified for a single IP address.

There are many command-line options to alter the behavior of
``vpn-slice``; try ``vpn-slice --help`` to show them all.

Running with ``--verbose`` makes it explain what it is doing, while
running with ``--dump`` shows the environment variables passed in by the
caller.

Home page
---------

https://github.com/dlenski/vpn-slice
