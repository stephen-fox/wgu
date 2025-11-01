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
  variable strings
- Specify multiple addresses for the virtual WireGuard network interface
  using more than one `Address` parameters

## Examples

```console
$ # Generate a config file by executing:
$ wgu genconf
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
$ # Create the WireGuard tunnels by executing:
$ wgu up
```

For detailed examples, refer to the [examples documentation][examples]
or execute `wgu help | less`.

[examples]: docs/examples.md

## Installation

First [install Go][go]. Once Go is installed, the application can be
securely compiled from source and saved to `~/go/bin` by executing:

```sh
# Note: The resulting executable will be located in ~/go/bin:
go install gitlab.com/stephen-fox/wgu@latest
```

[go]: https://go.dev/

## Configuration

Please refer to the [configuration documentation][configuration]

[configuration]: docs/configuration.md

## Commands

Please refer to the [commands documentation][commands]

[commands]: docs/command.md

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
