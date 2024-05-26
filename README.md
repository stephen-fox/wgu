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
- Support for resolving peers' using DNS hostnames
- Read the private key from a separate file

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

Note: This is for use with the `automatic addressing` feature.

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

First, create two configuration directories using genconfig:

```console
$ wgu genconfig peer0
qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
$ wgu genconfig peer1
92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
```

Edit peer0's config file, and make it look similar to the following:

```ini
[Interface]
PrivateKey = (...)
ListenPort = 4141
Address = 192.168.0.1/24

[Forwards]
TCP = tun us:2000 -> host 127.0.0.1:2000

# peer1:
[Peer]
PublicKey = (peer1's public key goes here)
AllowedIPs = 192.168.0.2/32
```

Modify peer1's config file to look like the following:

```ini
[Interface]
PrivateKey = (...)
Address = 192.168.0.2/24

[Forwards]
TCP = host 127.0.0.1:3000 -> tun peer0:2000

# peer0:
[Peer]
PublicKey = (peer0's public key goes here)
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

Like the previous example, we will create two WireGuard peers on the
current computer. This time we will simplify the configuration using
automatic address planning mode.

First, create two configuration directories using genconfig:

```console
$ wgu genconfig peer0
qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
$ wgu genconfig peer1
92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=
```

Edit peer0's config file, and make it look similar to the following:

```ini
[Interface]
PrivateKey = (...)
ListenPort = 4141

[Forwards]
TCP = tun us:2000 -> host 127.0.0.1:2000

# peer1:
[Peer]
PublicKey = (peer1's public key goes here)
```

Modify peer1's config file to look like the following:

```ini
[Interface]
PrivateKey = (...)

[Forwards]
TCP = host 127.0.0.1:3000 -> tun peer0:2000

# peer0:
[Peer]
PublicKey = (peer0's public key goes here)
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
