# Examples

## Hello world example

In this example, we will create two WireGuard peers on the current computer
and forward connections to TCP port 2000 to port 3000.

First, create two configuration directories named `peer0` and `peer1`
using `genconf`:

```console
$ cd $(mktemp -d)
$ wgu genconf peer0
(peer0's public key)
$ wgu genconf peer1
(peer1's public key)
```

Edit peer0's config file, and make it look similar to the following:

```ini
[Interface]
PrivateKey = # (...)
ListenPort = 4141
Address = 192.168.0.1/24

[Forwarder]
Name = example tun recv
Listen = tun tcp @us:2000
Dial = host tcp 127.0.0.1:2000

[Peer]
Name = peer1
PublicKey = # (peer1's public key goes here)
AllowedIPs = 192.168.0.2/32
```

Modify peer1's config file to look like the following:

```ini
[Interface]
PrivateKey = # (...)
Address = 192.168.0.2/24

[Forwarder]
Name = example host forward
Listen = host tcp 127.0.0.1:3000
Dial = tun tcp @peer0:2000

[Peer]
Name = peer0
PublicKey = # (peer0's public key goes here)
Endpoint = 127.0.0.1:4141
AllowedIPs = 192.168.0.1/32
```

To create the tunnel, execute the following commands in two
different shells:

```console
$ wgu up peer0/wgu.conf
$ wgu up peer1/wgu.conf
```

Finally, in two different shells, test the tunnel using nc:

```console
$ nc -l 2000
$ echo 'hello' | nc 127.0.0.1 3000
```

## Automatic address planning mode example

We can simplify the previous example's configuration using automatic address
planning mode. In this mode, each user's internal VPN address is derived
from their public key. Like the previous example, we will create two
WireGuard peers on the current computer.

First, create two configuration directories named `peer0` and `peer1`
using genconf:

```console
$ cd $(mktemp -d)
$ wgu genconf peer0
(peer0's public key)
$ wgu genconf peer1
(peer1's public key)
```

Edit peer0's config file, and make it look similar to the following:

```ini
[wgu]
AutomaticAddressPlanningMode = true

[Interface]
PrivateKey = # (...)
ListenPort = 4141

[Forwarder]
Name = example tun recv
Listen = tun tcp @us:2000
Dial = host tcp 127.0.0.1:2000

[Peer]
Name = peer1
PublicKey = # (peer1's public key goes here)
```

Modify peer1's config file to look like the following:

```ini
[wgu]
AutomaticAddressPlanningMode = true

[Interface]
PrivateKey = # (...)

[Forwarder]
Name = example host forward
Listen = host tcp 127.0.0.1:3000
Dial = tun tcp @peer0:2000

[Peer]
Name = peer0
PublicKey = # (peer0's public key goes here)
Endpoint = 127.0.0.1:4141
```

To create the tunnel *and* enable automatic address planning,
execute the following commands in two different shells:

```console
$ wgu up peer0/wgu.conf
$ wgu up peer1/wgu.conf
```

Finally, in two different shells, test the tunnel using nc:

```console
$ nc -l 2000
$ echo 'hello' | nc 127.0.0.1 3000
```
