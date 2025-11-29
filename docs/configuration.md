# Configuration

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

## Forwarder configuration

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

## Forwarder variables

The "address" values can be replaced with variables that are
expanded to the corresponding address:

- `@us` - The first IP address of our virtual WireGuard interface
- `@usN` - The nth IP address of our virtual WireGuard interface.
   For example, "@us1" would expand to the second address of the
   network interface
- `@<peer-name>` - The address of the peer with the corresponding name
   according to the peer's Name field

## Tap and packet capture functionality

wgu provides functionality for capturing unencrypted traffic transiting
the WireGuard tunnel via the `Tap` configuration parameter and the
[`wgupcap` tool](../tools/wgupcap). Tap functionality works by configuring
wgu to create a network listener (such as a Unix listener socket) and
pointing the wgupcap application at the listener socket. The wgupcap
application converts the raw packets into pcap format which can be
passed to tools like tcpdump and Wireshark.

Tap functionality is disabled by default for security. To enable tap
functionality, compile wgu with the `tap_enabled` build tag:

```sh
go build -tags tap_enabled
```

To create a tap, add a `Tap` parameter to the `[wgu]` section of the
configuration file. The value should be of the format:

```
<listener-protocol> <listen-address>
```

For example, to create a tap that creates a Unix listener socket at
`/home/user/.wgu/tap.sock`:

```ini
Tap = unix /home/user/.wgu/tap.sock
```

In the example above, wgu will create a Unix listener socket and write
all tunnel traffic to any clients that connect to the listener.

To parse the data produced by the tap listener, we need wgupcap.
To compile the wgupcap application, execute:

```sh
cd tools/wgupcap
go install
```

Now we can point wgupcap at the tap listener and pipe its output to
a packet sniffer application:

```sh
# tcpdump:
wgupcap /home/user/.wgu/tap.sock | tcpdump -r -

# Wireshark:
wgupcap /home/user/.wgu/tap.sock | /Applications/Wireshark.app/Contents/MacOS/Wireshark -ki -
```
