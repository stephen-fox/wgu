# wgu

wgu (WireGuard User Space) is a fork of Jonathan Giannuzzi's [wgfwd][wgfwd].
wgu allows users to create WireGuard tunnels without running as root.
Connections to network services running on peers are managed using
forwarding specifications. Each specification tells wgu where to listen
for incoming connections and where to forward the connections to.

[wgfwd]: https://github.com/jgiannuzzi/wgfwd

## Features

wgu expands on wgfwd's functionality with the following features:

- Specify which side of the tunnel a network listener should be created on
- Support for WireGuard configuration syntax via a configuration file
- Support for common `wg` helper commands like `genkey` and `pubkey`
- Added additional helper commands like `genconfig` to make setup easier
- Optionally address peers' WireGuard interfaces using their public keys
  as IPv6 addresses using automatic address planning mode
- Support for resolving peers' external addresses using DNS hostnames
- Store the private key in a separate file

## Automatic address planning mode

If the `-A` argument is specified, then each peer's virtual WireGuard
address is generated from its public key in the form of an IPv6 address.
This makes it easier to construct simple WireGuard topologies without
planning out IP address allocations or needing to know each peer's
WireGuard address.

In this mode, it is unnecessary to specify the 'Address' configuration
parameter for other peers.

## Configuration

Configuration is specified using a configuration file using the same `ini`
configuration syntax as WireGuard. Command line arguments can be used to
modify wgu's behavior as well.

After installing wgu, it is recommended to create a private key file using
the `genconfig` command. The following example will create a `.wgu` directory
in the user's home directory containing an example configuration file and
a private key file. The private key's corresponding public key is then
written to standard output:

```console
$ wgu genconfig
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

#### Forwarding specification

Port forwards are defined in the `[Forwards]` section using the following
specification format:

```
transport = net-type listen-address:port -> net-type dial-address:port
```

`net-type` may be one of the following values:

- host - The host computer's networking stack is used
- tun  - The WireGuard networking stack is used

For example, the following specification forwards TCP connections to
127.0.0.1:22 on the host machine to a WireGuard peer who has the
virtual address of 10.0.0.1:

```ini
TCP = host 127.0.0.1:22 -> tun 10.0.0.1:22
```

#### Forwarding magic strings

The "listen-address" and "dial-address" values can be replaced with
magic strings that are expanded to the corresponding address.

- `us` - The first IP address of our virtual WireGuard interface
- `@<name>` - The address of the peer with the corresponding name according                                                    to the peer's Name field Name field
- `peerN` - The address of peer number N as they appear in the WireGuard
  configuration file. For example, "peer0" would be the address
  of the first peer in the WireGuard configuration file

## Helper commands

wgu supports several helper commands. If a command is not specified,
wgu will attempt to create a WireGuard tunnel.

#### `help`

In addition to the `-h` argument, `help` provides configuration syntax
descriptions and examples via standard output. It is recommended to
pipe it to a program like `less` to make it searchable:

```console
$ wgu help
$ wgu help | less
```

#### `genconfig`

Generates an example configuration file and a private key file in the
user's home directory under `.wgu/` followed by writing the public key
to standard output.

Example:

```console
$ wgu genconfig
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug= 
```

If a different directory is desired, simply specify it as an argument.
If the directory does not already exist, wgu will create it for you:

```console
$ wgu genconfig /usr/local/etc/wgu
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

#### `genkey`

Generates a new WireGuard private key and writes it to standard output.

Example:

```console
$ wgu genkey
<private-key-plaintext>
```

#### `pubkey`

Reads a private key from standard input and writes the corresponding
public key to standard output.

Example:

```console
$ wgu pubkey < example-private-key-file 
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

#### `pubkey-from-config`

Reads a configuration file from standard input, parses the private key
from the file, and writes the corresponding public key to standard output.

Example:

```console
$ wgu pubkey-from-config < example-config-file
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

#### `pubkey-addr`

Note: This is for use with the `automatic address planning mode` feature.

Generates an IPv6 address for the given WireGuard public key.

Example:

```console
$ wgu pubkey-addr < another-peers-public-key
483b:9c67:9217:d415:774d:480:f642:1e5c
```

## Examples

#### Hello world example

In this example, we will create two WireGuard peers on the current computer
and forward connections to TCP port 2000 to port 3000.

First, create two configuration directories named `peer0` and `peer1`
using `genconfig`:

```console
$ cd $(mktemp -d)
$ wgu genconfig peer0
qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
$ wgu genconfig peer1
92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
```

Edit peer0's config file, and make it look similar to the following:

```ini
[Interface]
PrivateKey = file:///tmp/example/peer0/private-key
ListenPort = 4141
Address = 192.168.0.1/24

[Forwards]
TCP = tun us:2000 -> host 127.0.0.1:2000

# peer1:
[Peer]
PublicKey = 92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
AllowedIPs = 192.168.0.2/32
```

Modify peer1's config file to look like the following:

```ini
[Interface]
PrivateKey = file:///tmp/example/peer1/private-key
Address = 192.168.0.2/24

[Forwards]
TCP = host 127.0.0.1:3000 -> tun peer0:2000

# peer0:
[Peer]
PublicKey = qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
Endpoint = 127.0.0.1:4141
AllowedIPs = 192.168.0.1/32
```

To create the tunnel, execute the following commands in two
different shells:

```console
$ wgu -config peer0/wgu.conf
$ wgu -config peer1/wgu.conf
```

Finally, in two different shells, test the tunnel using nc:

```console
$ nc -l 2000
$ echo 'hello' | nc 127.0.0.1 3000
```

#### Automatic address planning mode example

We can simplify the previous example's configuration using automatic address
planning mode. In this mode, each user's internal VPN address is derived
from their public key. Like the previous example, we will create two
WireGuard peers on the current computer.

First, create two configuration directories named `peer0` and `peer1`
using genconfig:

```console
$ cd $(mktemp -d)
$ wgu genconfig peer0
qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
$ wgu genconfig peer1
92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
```

Edit peer0's config file, and make it look similar to the following:

```ini
[Interface]
PrivateKey = file:///tmp/example/peer0/private-key
ListenPort = 4141

[Forwards]
TCP = tun us:2000 -> host 127.0.0.1:2000

# peer1:
[Peer]
PublicKey = 92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
```

Modify peer1's config file to look like the following:

```ini
[Interface]
PrivateKey = file:///tmp/example/peer1/private-key

[Forwards]
TCP = host 127.0.0.1:3000 -> tun peer0:2000

# peer0:
[Peer]
PublicKey = qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
Endpoint = 127.0.0.1:4141
```

To create the tunnel *and* enable automatic address planning,
execute the following commands in two different shells:

```console
$ wgu -config peer0/wgu.conf -A
$ wgu -config peer1/wgu.conf -A
```

Finally, in two different shells, test the tunnel using nc:

```console
$ nc -l 2000
$ echo 'hello' | nc 127.0.0.1 3000
```

## Installation

First, [install Go][go]. Once Go is installed, the application can be
securely compiled from source and saved to `~/go/bin` by executing:

```sh
# Note: The resulting executable will be located in ~/go/bin:
go install gitlab.com/stephen-fox/wgu@latest
```

[go]: https://go.dev/
