```
  Copyright 2010, 2011, 2012
    IIJ Innovation Institute Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY IIJ INNOVATION INSTITUTE INC. ``AS IS'' AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL IIJ INNOVATION INSTITUTE INC. OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```


# INTRODUCTION

map646 is a one to one IPv4-IPv6 address mapping program for protocol
translation.

This program is used in a scenario when you have a pure IPv6 network
but want to open some of the server services to IPv4 users.  To do
this, you need the following things.

  - IPv4 connectivity at the boundary of your IPv6 network.
  - Enough number of global IPv4 addresses that you want to map your
    IPv6 servers.


# HOW TO COMPILE
## With make

Just type `make`.  The program is developed for the FreeBSD operating
system and the Linux operating system, but if your operating system
supports the tun interface, then you can probably compile the program.

## With docker
Simply `docker build`. The underlying image is debian jessie.


# HOW TO CONFIGURE

In this section, we assume that you have IPv6 address space
`2001:db8:0:0::/64` for your pure IPv6 network.  Also, we assume that
you have `192.0.2.0/24` as global IPv4 address space.  Your IPv6 nodes
don't have any global IPv4 addresses, so they cannot communicate with
IPv4 nodes.

First we need to define the mapping information of your IPv6 servers
and your global IPv4 addresses.  As an example, let's define the
following mapping.
```
  192.0.2.1 <=> 2001:db8:0:0::100
  192.0.2.2 <=> 2001:db8:0:0::500
```

With the above mapping, you are now exposing two of your IPv6 servers
to the global IPv4 Internet, using `192.0.2.1` and `192.0.2.2`.  The
program reads the configuration information from the configuration
file located at /etc/map646.conf.  The file contents should be as
follows.

```
mapping-prefix 64::
map-static 192.0.2.1 2001:db8:0:0::100
map-static 192.0.2.2 2001:db8:0:0::500
```

The first line defines the pseudo IPv6 prefix of the mapping system.
When your IPv6 server communicates with an IPv4 node, the IPv4 node
address is mapped to that prefix range.  For example, if your server
is contacting to `202.214.86.196`, the endpoint address seen from your
IPv6 server will be `64::cad6:56c4` (also noted `64::202.214.86.196`).
The IPv4 addresses are mapped to the lower 4 bytes of the pseudo IPv6
address in a hexadecimal form (in this case, 0xCA (202), 0xD6 (214),
0x56 (86), and 0xC4 (196)).

Similarly, any IPv4 node can contact your IPv6 server using the
global address mapped to your server address.  If the IPv4 node (which
IPv4 address is `202.214.86.196`) connects to `192.0.2.2`, then your IPv6
server (`2001:db8:0:0::500`) will receive an incoming packet from
64::cad6:56c5 (i.e. `64::202.214.86.196`).

To use the program, you need to setup your node as a router by
enabling the forwarding function.  The following example is a sample
startup operation procedure for the FreeBSD operating system.
```
# (run map646 in background.)
# sysctl -w net.inet.ip.forwarding=1
# sysctl -w net.inet6.ip6.forwarding=1
```

The below is an example in the Linux case.
```
# (run map646 in background)
# sysctl -w net.ipv4.conf.all.forwarding=1
# sysctl -w net.ipv6.conf.all.forwarding=1
```

Once you have done all the settings, your mapping server is ready.


## Routing
Please note that the mapping prefix (in this case `64::/96`) and
IPv4 static addresses  MUST be routed to your server. Your kernel
must then forward this ranges to the `tun646` interface.


# DNS CONFIGURATION

You need to configure your IPv4 global addresses used to map your IPv6
servers in your DNS server database.  The example entries are like below.

```
your-ipv6-sever-1    IN    A    192.0.2.1
your-ipv6-sever-2    IN    A    192.0.2.2
```

Any IPv4 host can now contact to your IPv6 server 1
(`2001:db8:0:0::100`) by contacting your-ipv6-server-1.example.com.  At
this point, your IPv6 servers are fully accessible from any IPv4 hosts
in the Internet.

The reverse direction is a bit complicated.  You need a modified DNS
server for your pure IPv6 network, since the DNS server must reply a
pseudo IPv6 address associated to the real IPv4 address that the
server want to contact to.  When your IPv6 server asks AAAA record of
www.yahoo.com (assuming that it doesn't have IPv6 addresses and its
IPv4 address is `72.30.2.43`), your internal DNS server must reply
`64::481e:22b`.

Unfortunately, this map646 package doesn't include the modified DNS
server.  You may be interested in using Trick Or Treat Daemon (totd)
for this function
(http://www.vermicelli.pasta.cs.uit.no/software/totd.html)
