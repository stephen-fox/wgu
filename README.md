# wgu

wgu (WireGuard Userspace) is a fork of Jonathan Giannuzzi's [wgfwd][wgfwd].
wgu creates WireGuard tunnels without superuser privileges. Connections to
network services are managed using forwarders. Each forwarder tells wgu
where to listen for incoming connections and where to forward connections to.

[wgfwd]: https://github.com/jgiannuzzi/wgfwd

## Features

wgu expands on wgfwd's functionality with the following features:

- Automatic address planning mode: Optionally address peers' WireGuard
  interfaces using their public keys as IPv6 addresses. This mode makes
  it easy to quickly build simple WireGuard networks
- Specify which side of the tunnel a network listener should be created on
- Network listener and dialer type customization allows mixing of network
  protocols (for example: forwarding Unix sockets over TCP / UDP)
- Support for WireGuard configuration syntax via a configuration file
- Support for commonly-used `wg` helper commands like `genkey` and `pubkey`
- New `genconf` command auto-generates a configuration file to make
  getting started easier
- Support for resolving peers' external addresses using DNS hostnames
- Store the private key in a file outside of the configuration file
- Expand the WireGuard interface's address and peers' addresses using
  shortcut strings
- Specify multiple addresses for the virtual WireGuard network interface
  using multiple `Address` parameters

## Basic example

```console
$ # Generate a config file by executing:
$ wgu genconf
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
$ # Modify ~/.wgu/wgu.conf as desired.
$ # Create the WireGuard tunnels by executing:
$ wgu up
$ # ... or specify a different configuration file path:
$ wgu up ~/.wgu/some-other-wgu.conf
```

For additional help and examples, refer to the current README
or execute `wgu help | less`.

## Installation

First, [install Go][go]. Once Go is installed, the application can be
securely compiled from source and saved to `~/go/bin` by executing:

```sh
# Note: The resulting executable will be located in ~/go/bin:
go install gitlab.com/stephen-fox/wgu@latest
```

[go]: https://go.dev/

## Configuration

After installing wgu, it is recommended to create an example configuration
file and a private key file using the `genconf` command. The following
example will create a .wgu directory in the user's home directory
containing an example configuration file and a private key file.
The private key's corresponding public key is written to standard output:

```console
$ wgu genconf
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

wgu is configured using an INI configuration file in a similar manner
to WireGuard. Additional options can be specified using command line
arguments.

General application settings can be specified in the configuration file
in the wgu section. For example:

```ini
[wgu]
ExampleParameter = some value
```

The following general application parameters are available:

- `AutomaticAddressPlanningMode` - Enables automatic address planning mode
  if set to "true". Defaults to "false" if unspecified. In this mode,
  each peer's virtual WireGuard address is generated from its public key
  in the form of an IPv6 address. This mode makes it easier to construct
  simple WireGuard topologies without planning out IP address allocations
  or needing to know each peer's WireGuard address. It is unnecessary to
  specify the 'Address' configuration parameter for other peers in this
  mode. Refer to the [automatic address planning mode example][x-aapm]
  for an example.
- `LogLevel` - Set the log level according to the values that can be
  specified on the command line. Can be: `error`, `info`, or `debug`

[x-aapm]: #automatic-address-planning-mode-example

#### Forwarder configuration

Port forwards are defined in a `Forwarder` configuration section using
the following configuration fields:

```ini
[Forwarder]
Name = <name>
Listen = <transit-specification>
Dial = <transit-specification>
```

A transit specification is of the format:

```
net-stack protocol address:port
```

"net-stack" may be one of the following values:

- host - The host computer's networking stack is used
- tun  - The WireGuard networking stack is used

"protocol" can be any of the strings that the Go net library takes.
This includes:

- tcp, tcp6
- udp, udp6
- unix, unixgram, unixpacket

For more information on the above strings, refer to Go's net.Dial
documentation: https://pkg.go.dev/net#Dial

For example, the following configuration forwards TCP connections to
127.0.0.1:22 on the host machine to a WireGuard peer who has the
virtual address of 10.0.0.1:

```ini
[Forwarder]
Name = example
Listen = host tcp 127.0.0.1:22
Dial = tun tcp 10.0.0.1:22
```

Protocols can be mixed. In the following example, connections to the
Unix socket "example.sock" will be forwarded to a WireGuard peer
who has the virtual address of 10.0.0.1 using TCP:

```ini
[Forwarder]
Name = example
Listen = host unix example.sock
Dial = tun tcp 10.0.0.1:22
```

#### Forwarder variables

The "address" values can be replaced with variables that are
expanded to the corresponding address:

- `@us` - The first IP address of our virtual WireGuard interface
- `@usN` - The nth IP address of our virtual WireGuard interface.
   For example, "@us1" would expand to the second address of the
   network interface
- `@<peer-name>` - The address of the peer with the corresponding name
   according to the peer's Name field

## Commands

wgu supports several commands which are documented below.

#### `help`

In addition to the `-h` argument, `help` provides configuration syntax
descriptions and examples via standard output. It is recommended to
pipe it to a program like `less` to make it searchable:

```console
$ wgu help
$ wgu help | less
```

#### `version`

Writes the version number to standard output and exits.

Example:

```console
$ wgu version
v0.0.8
```

#### `genconf`

Generates an example configuration file and a private key file in the
user's home directory under `.wgu/` followed by writing the public key
to standard output.

Example:

```console
$ wgu genconf
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug= 
```

If a different directory is desired, simply specify it as an argument.
If the directory does not already exist, wgu will create it for you:

```console
$ wgu genconf /usr/local/etc/wgu
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

#### `pubkeyconf`

Reads a configuration file from a path or standard input, parses the
private key from the file, and writes the corresponding public key to
standard output.

Example:

```console
$ wgu pubkeyconf < example-config-file
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
$ # Or read from the default config file path:
$ wgu pubkeyconf
M2njNIDzUKZHa8z55V0u4pb5BJSikUZcmBQkRH06Zg8=
```

#### `pubkeyaddr`

Note: This is for use with the `automatic address planning mode` feature.

Generates an IPv6 address for the given WireGuard public key.

Example:

```console
$ wgu pubkeyaddr < another-peers-public-key
483b:9c67:9217:d415:774d:480:f642:1e5c
```

#### `up`

Creates the WireGuard tunnel(s) using the specified configuration.
Defaults to using the configuration file at `~/.wgu/wgu.conf` if
no configuration file is specified.

Example:

```console
$ # The following line uses the configuration file at ~/.wgu/wgu.conf:
$ wgu up
$ # The following line uses a configuration file named "wgu.conf"
$ # in the current working directory:
$ wgu up wgu.conf
```

## Examples

#### Hello world example

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

#### Automatic address planning mode example

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

## Troubleshooting

#### Startup failure in FreeBSD jail with host networking

If you are trying to run wgu in a FreeBSD jail that utilizes the host's
networking stack and you are encountering the following error:

> failed to set listen_port: listen udp6 :X: socket: protocol not supported

... it is likely you need to enable IPv6 in the jail configuration file
like so:

```diff
 example {
   path = "/zroot/jails/${name}";
   ip4 = "inherit";
+  ip6 = "inherit";
   mount.devfs;
   exec.start = "/bin/sh /etc/rc";
   exec.stop = "/bin/sh /etc/rc.shutdown";
 }
```

## Special thanks

wgu would not have been possible without Jonathan Giannuzzi's original wgfwd
project - thank you, Jonathan.

Thank you to @SeungKang for helping me implement features and fix bugs, plus
spending tons of time testing :)
