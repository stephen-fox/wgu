// wgu (WireGuard User Space) is a fork of Jonathan Giannuzzi's wgfwd.
// wgu allows users to create WireGuard tunnels without running as root
// Connections to network services running on peers are managed using
// forwarding specifications. Each specification tells wgu where to listen
// for incoming connections and where to forward the connections to.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"gitlab.com/stephen-fox/wgu/internal/wgdns"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	appName = "wgu"

	usage = appName + `

SYNOPSIS
  ` + appName + ` [helper-command] [options]

DESCRIPTION
  wgu (WireGuard User Space) is a fork of Jonathan Giannuzzi's wgfwd.
  wgu allows users to create WireGuard tunnels without running as root
  Connections to network services running on peers are managed using
  forwarding specifications. Each specification tells wgu where to listen
  for incoming connections and where to forward the connections to.

  For helper command documentation and configuration examples, please execute:
    ` + appName + ` ` + helpCmd + `

  To generate a basic configuration file and private key, please execute:
    ` + appName + ` ` + genconfigCmd + `

OPTIONS
`

	help = `HELPER COMMANDS

  ` + helpCmd + `               - Display configuration syntax help and examples
  ` + genconfigCmd + ` [dir]    - Generate an example configuration file and private key.
                       The config and private key files are written to ~/.wgu
                       by default. This can be overriden by specifying a path
                       as an argument
  ` + genkeyCmd + `             - Generate a new WireGuard private key and write it
                       to stdout
  ` + pubkeyCmd + `             - Read a WireGuard private key from stdin and write
                       its public key to stdout
  ` + pubkeyFromConfigCmd + ` - Read a configuration file from stdin, parse
                       its private key, and write the public key to stdout
  ` + pubkeyAddrCmd + `        - (automatic address planning mode) - Read a public key
                       from stdin and convert it to an IPv6 address

FORWARDING SPECIFICATION
  Port forwards are defined in the [Forwards] section using the following
  specification format:

    transport = net-type listen-address:port -> net-type dial-address:port

  "net-type" may be one of the following values:

    - host - The host computer's networking stack is used
    - tun  - The WireGuard networking stack is used

  For example, the following specification forwards TCP connections to
  127.0.0.1:22 on the host machine to a WireGuard peer who has the
  virtual address of 10.0.0.1:

    TCP = host 127.0.0.1:22 -> tun 10.0.0.1:22

FORWARDING MAGIC STRINGS
  The "listen-address" and "dial-address" values can be replaced with
  magic strings that are expanded to the corresponding address.

    us
      The first IP address of our virtual WireGuard interface

    peerN
      The address of peer number N as they appear in the WireGuard
      configuration file. For example, "peer0" would be the address
      of the first peer in the WireGuard configuration file

    <pub-base64>
      The address of the peer with the corresponding base64-encoded
      public key (for use with automatic address planning mode)

AUTOMATIC ADDRESS PLANNING MODE
  If the -` + autoAddressPlanningArg + ` argument is specified, then each peer's virtual WireGuard
  address is generated from its public key in the form of an IPv6 address.
  This makes it easier to construct simple WireGuard topologies without
  planning out IP address allocations or needing to know each peer's
  WireGuard address.

  In this mode, it is unnecessary to specify the 'Address' configuration
  parameter for other peers.

  Refer to the AUTOMATIC ADDRESS PLANNING MODE EXAMPLE section for
  an example.

HELLO WORLD EXAMPLE
  In this example, we will create two WireGuard peers on the current computer
  and forward connections to TCP port 2000 to port 3000.

  First, create two configuration directories using ` + genconfigCmd + `:
    $ wgu ` + genconfigCmd + ` peer0
    qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
    $ wgu ` + genconfigCmd + ` peer1
    92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=

  Edit peer0's config file, and make it look similar to the following:
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

  Modify peer1's config file to look like the following:
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

  To create the tunnel, execute the following commands in two
  different shells:
    $ wgu -config peer0/wgu.conf
    $ wgu -config peer1/wgu.conf

  Finally, in two different shells, test the tunnel using nc:
    $ nc -l 2000
    $ echo 'hello' | nc 127.0.0.1 3000

AUTOMATIC ADDRESS PLANNING MODE EXAMPLE
  Like the previous example, we will create two WireGuard peers on the
  current computer. This time we will simplify the configuration using
  automatic address planning mode.

  First, create two configuration directories using ` + genconfigCmd + `:
    $ wgu ` + genconfigCmd + ` peer0
    qXwhKFk1DkZpf7XFN+pKDieCk5QVHftllLkYbsmJg2A=
    $ wgu ` + genconfigCmd + ` peer1
    92Ur/x6rt949/F7kk0EUTSwRNHuPWgD1mYKOAmrTZl0=

  Edit peer0's config file, and make it look similar to the following:
    [Interface]
    PrivateKey = (...)
    ListenPort = 4141

    [Forwards]
    TCP = tun us:2000 -> host 127.0.0.1:2000

    # peer1:
    [Peer]
    PublicKey = (peer1's public key goes here)

  Modify peer1's config file to look like the following:
    [Interface]
    PrivateKey = (...)

    [Forwards]
    TCP = host 127.0.0.1:3000 -> tun peer0:2000

    # peer0:
    [Peer]
    PublicKey = (peer0's public key goes here)
    Endpoint = 127.0.0.1:4141

  To create the tunnel *and* enable automatic address planning,
  execute the following commands in two different shells:
    $ wgu -config peer0/wgu.conf -` + autoAddressPlanningArg + `
    $ wgu -config peer1/wgu.conf -` + autoAddressPlanningArg + `

  Finally, in two different shells, test the tunnel using nc:
    $ nc -l 2000
    $ echo 'hello' | nc 127.0.0.1 3000
`

	helpCmd             = "help"
	genconfigCmd        = "genconfig"
	genkeyCmd           = "genkey"
	pubkeyCmd           = "pubkey"
	pubkeyFromConfigCmd = "pubkey-from-config"
	pubkeyAddrCmd       = "pubkey-addr"

	logLevelArg            = "L"
	noLogTimestampsArg     = "T"
	autoAddressPlanningArg = "A"
	configPathArg          = "config"
	helpArg                = "h"
	tcpArg                 = "tcp"
	udpArg                 = "udp"
	udpTimeoutArg          = "udp-timeout"

	helpArgv = "'" + appName + " " + helpCmd + "'"
)

var (
	udpTimeout time.Duration

	loggerInfo  = log.New(io.Discard, "", 0)
	loggerErr   = log.New(io.Discard, "", 0)
	loggerDebug = log.New(io.Discard, "", 0)
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	help := flag.Bool(
		helpArg,
		false,
		"Display this information")

	forwards := make(map[string]*forwardConfig)

	tcpForwards := forwardFlag{
		transport:     "tcp",
		strsToConfigs: forwards,
	}
	flag.Var(
		&tcpForwards,
		tcpArg,
		"TCP port forward `specification` (see "+helpArgv+" for details)")

	udpForwards := forwardFlag{
		transport:     "udp",
		strsToConfigs: forwards,
	}
	flag.Var(
		&udpForwards,
		udpArg,
		"UDP port forward `specification` (see "+helpArgv+" for details)")

	flag.DurationVar(
		&udpTimeout,
		udpTimeoutArg,
		2*time.Minute,
		"UDP timeout")

	configPath := flag.String(
		configPathArg,
		"",
		"Configuration file `path`")

	autoAddrPlanning := flag.Bool(
		autoAddressPlanningArg,
		false,
		"Enable automatic address planning mode (see "+helpArgv+" for details)")

	writeConfig := flag.Bool(
		"write-config",
		false,
		"")

	writeIpcConfig := flag.Bool(
		"write-ipc-config",
		false,
		"")

	logLevelString := flag.String(
		logLevelArg,
		"info",
		"Log level (possible values: 'error', 'info', 'debug')")

	noLogTimestamps := flag.Bool(
		noLogTimestampsArg,
		false,
		"Disable logging timestamps")

	// Disable annoying flag.PrintDefaults on flag parse error.
	flag.Usage = func() {}

	flag.Parse()

	if *help {
		flag.CommandLine.Output().Write([]byte(usage))
		flag.PrintDefaults()
		os.Exit(1)
	}

	if flag.NArg() > 0 {
		return helperCommand(flag.Arg(0))
	}

	if !*noLogTimestamps {
		log.SetFlags(log.LstdFlags)
	}

	switch *logLevelString {
	case "debug":
		loggerDebug = log.New(log.Writer(), "[debug] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "info":
		loggerInfo = log.New(log.Writer(), "[info] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "error":
		loggerErr = log.New(log.Writer(), "[error] ", log.Flags()|log.Lmsgprefix)
	}

	var configFD *os.File
	switch *configPath {
	case "":
		return fmt.Errorf("please specify a config path using -%s", configPathArg)
	case "-":
		configFD = os.Stdin
	default:
		var err error
		configFD, err = os.Open(*configPath)
		if err != nil {
			return err
		}
	}

	cfg, err := wgconfig.Parse(configFD)
	_ = configFD.Close()
	if err != nil {
		return fmt.Errorf("failed to parse config file - %w", err)
	}

	if cfg.Interface.MTU == nil {
		// TODO: Add flag.
		i := 1420
		cfg.Interface.MTU = &i
	}

	for _, section := range cfg.Others {
		if section.Name != "Forwards" {
			continue
		}

		for _, param := range section.Params {
			switch param.Name {
			case "TCP":
				err := tcpForwards.Set(param.Value)
				if err != nil {
					return fmt.Errorf("failed to parse tcp forward from config (%q) - %w",
						param.Value, err)
				}
			case "UDP":
				err := udpForwards.Set(param.Value)
				if err != nil {
					return fmt.Errorf("failed to parse udp forward from config (%q) - %w",
						param.Value, err)
				}
			default:
				return fmt.Errorf("forward from config specifies unknown transport: %q",
					param.Name)
			}
		}
	}

	if *autoAddrPlanning {
		err = doAutoAddrPlanning(cfg)
		if err != nil {
			return fmt.Errorf("failed to do automatic address planning - %w", err)
		}
	}

	if *writeConfig {
		_, err = os.Stdout.WriteString(cfg.WireGuardString())
		return err
	}

	if *writeIpcConfig {
		str, err := cfg.IPCConfig()
		if err != nil {
			return fmt.Errorf("failed to convert config to ipc format - %w", err)
		}

		_, err = os.Stdout.WriteString(str)
		return err
	}

	if cfg.Interface.Address == nil {
		return fmt.Errorf("failed to get our internal wg address from config")
	}

	ourWgAddrStr := cfg.Interface.Address.Addr().String()
	for str, forward := range forwards {
		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:      &forward.lAddr.addr,
			ourWgAddr: ourWgAddrStr,
			peers:     cfg.Peers,
		})
		if err != nil {
			return fmt.Errorf("failed to replace listen addr for %q - %w",
				str, err)
		}

		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:      &forward.dAddr.addr,
			ourWgAddr: ourWgAddrStr,
			peers:     cfg.Peers,
		})
		if err != nil {
			return fmt.Errorf("failed to replace dial addr for %q - %w",
				str, err)
		}
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	defer cancelFn()

	ipcConfig, err := cfg.IPCConfigWithoutDnsPeers()
	if err != nil {
		return fmt.Errorf("failed to convert config to ipc format - %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.Interface.Address.Addr()},
		[]netip.Addr{},
		*cfg.Interface.MTU,
	)
	if err != nil {
		return fmt.Errorf("Error creating tunnel interface: %s", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: loggerDebug.Printf,
		Errorf:   loggerErr.Printf,
	})

	err = dev.IpcSet(ipcConfig)
	if err != nil {
		return fmt.Errorf("Error setting device configuration: %s", err)
	}

	err = dev.Up()
	if err != nil {
		return fmt.Errorf("Error bringing up device: %s", err)
	}
	defer dev.Down()

	loggerInfo.Println("wg device up")

	dnsMonitorErrs := make(chan error, 1)
	wgdns.MonitorPeers(ctx, cfg.Peers, dev, dnsMonitorErrs, loggerInfo)

	waitGroup, err := startForwarders(ctx, tnet, forwards)
	if err != nil {
		return fmt.Errorf("failed to start network forwarders - %w", err)
	}

	select {
	case <-ctx.Done():
		waitGroup.Wait()
		return ctx.Err()
	case err = <-dnsMonitorErrs:
		return fmt.Errorf("failed to monitor peer's dns changes - %w", err)
	}
}

func helperCommand(command string) error {
	switch command {
	case helpCmd:
		os.Stdout.WriteString(help)
	case genconfigCmd:
		var configDirPath string
		var privateKeyPathInConfig string
		const privateKeyFileName = "private-key"

		if flag.NArg() > 1 {
			var err error
			configDirPath, err = filepath.Abs(flag.Arg(1))
			if err != nil {
				return err
			}

			privateKeyPathInConfig = filepath.Join(configDirPath, privateKeyFileName)
		} else {
			homeDirPath, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			configDirPath = filepath.Join(homeDirPath, ".wgu")

			privateKeyPathInConfig = "~/.wgu/" + privateKeyFileName
		}

		err := os.MkdirAll(configDirPath, 0o700)
		if err != nil {
			return err
		}

		err = os.Chmod(configDirPath, 0o700)
		if err != nil {
			return err
		}

		configFilePath := filepath.Join(configDirPath, appName+".conf")

		_, statErr := os.Stat(configFilePath)
		if statErr == nil {
			return fmt.Errorf("a configuration file already exists at: '%s'",
				configFilePath)
		}

		privateKeyFilePath := filepath.Join(configDirPath, privateKeyFileName)

		_, statErr = os.Stat(privateKeyFilePath)
		if statErr == nil {
			return fmt.Errorf("a private key file already exists at: '%s'",
				privateKeyFilePath)
		}

		err = os.WriteFile(configFilePath, []byte(`[Interface]
PrivateKey = file://`+privateKeyPathInConfig+`
# Optionally, allow other peers to connect to us:
# ListenPort = 4141

# Note: For more information, please execute: "`+appName+` `+helpCmd+`"
#
# The following forwarding example sends TCP port 2222 on your machine
# to the WireGuard peer with virtual address 10.0.0.2 on TCP port 22 (ssh):
#
# [Forwards]
# TCP = host 127.0.0.1:2222 -> tun 10.0.0.2:22

# Example peer definition:
#
# [Peer]
# PublicKey = <public-key>
# Endpoint = <address>:<port>
# PersistentKeepalive = 25
`), 0o600)

		privateKey, err := wgkeys.NewNoisePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key - %w", err)
		}

		err = os.WriteFile(
			privateKeyFilePath,
			[]byte(base64.StdEncoding.EncodeToString(privateKey[:])+"\n"),
			0o600,
		)
		if err != nil {
			return fmt.Errorf("failed to write private key file - %w", err)
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(
			wgkeys.NoisePublicKeyFromPrivate(privateKey)[:]) + "\n")
	case genkeyCmd:
		privateKey, err := wgkeys.NewNoisePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key - %w", err)
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(privateKey[:]) + "\n")
	case pubkeyCmd:
		privateKeyB64, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		privateKey, err := wgkeys.NoisePrivateKeyFromBase64(string(privateKeyB64))
		if err != nil {
			return fmt.Errorf("failed to parse private key - %w", err)
		}

		pub := wgkeys.NoisePublicKeyFromPrivate(privateKey)

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(pub[:]) + "\n")
	case pubkeyFromConfigCmd:
		cfg, err := wgconfig.Parse(os.Stdin)
		if err != nil {
			return err
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(
			cfg.Interface.PublicKey[:]) + "\n")
	case pubkeyAddrCmd:
		publicKeyRaw, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, os.Stdin))
		if err != nil {
			return err
		}

		publicKey, err := wgkeys.NoisePublicKeyFromBytes(publicKeyRaw)
		if err != nil {
			return err
		}

		addr, err := publicKeyToV6Addr(publicKey[:])
		if err != nil {
			return err
		}

		os.Stdout.WriteString(addr.String() + "\n")
	default:
		return fmt.Errorf("unknown helper command: %q", command)
	}

	return nil
}

type netOp interface {
	Dial(ctx context.Context, network string, address string) (net.Conn, error)
	Listen(ctx context.Context, network string, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error)
}

type localNetOp struct{}

func (n *localNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (n *localNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	var l net.ListenConfig
	return l.Listen(ctx, network, address)
}

func (n *localNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	var l net.ListenConfig
	return l.ListenPacket(ctx, network, address)
}

type tunnelNetOp struct {
	tun *netstack.Net
}

func (n *tunnelNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	return n.tun.DialContext(ctx, network, address)
}

func (n *tunnelNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return n.tun.ListenTCP(addr)
}

func (n *tunnelNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return n.tun.ListenUDP(addr)
}

func startForwarders(ctx context.Context, tnet *netstack.Net, forwards map[string]*forwardConfig) (*sync.WaitGroup, error) {
	waitGroup := &sync.WaitGroup{}
	var localNetOp = &localNetOp{}
	var tunnelNetOp = &tunnelNetOp{tnet}

	for fwdStr, fwd := range forwards {
		var listenNet netOp
		switch fwd.lNet {
		case hostNetType:
			listenNet = localNetOp
		case tunNetType:
			listenNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported listen net type: %q", fwd.lNet)
		}

		var dialNet netOp
		switch fwd.dNet {
		case hostNetType:
			dialNet = localNetOp
		case tunNetType:
			dialNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported dial net type: %q", fwd.lNet)
		}

		loggerInfo.Printf("starting %q...", fwdStr)

		var err error

		switch fwd.proto {
		case "tcp":
			err = forwardTCP(ctx, waitGroup, fwd, listenNet, dialNet)
		case "udp":
			err = forwardUDP(ctx, waitGroup, fwd, listenNet, dialNet)
		default:
			return nil, fmt.Errorf("unknown protocol: %s", fwd.proto)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to forward %q - %w", fwdStr, err)
		}
	}

	return waitGroup, nil
}

func forwardTCP(ctx context.Context, waitGroup *sync.WaitGroup, config *forwardConfig, lNet netOp, rNet netOp) error {
	lAddr := config.lAddr.String()
	rAddr := config.dAddr.String()

	listener, err := lNet.Listen(ctx, "tcp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("Stopping TCP forwarder for %s -> %s",
			lAddr, rAddr)

		listener.Close()
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				loggerErr.Printf("Error accepting tcp connection: %s", err)
				return
			}

			loggerDebug.Printf("Accepted TCP connection from %s for %s",
				conn.RemoteAddr(), lAddr)

			go dialAndCopyTCP(ctx, conn, rNet, rAddr)
		}
	}()

	loggerInfo.Printf("TCP forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

func dialAndCopyTCP(ctx context.Context, conn net.Conn, rNet netOp, rAddr string) {
	remote, err := rNet.Dial(ctx, "tcp", rAddr)
	if err != nil {
		loggerErr.Printf("Error connecting to remote TCP: %s", err)
		conn.Close()
		return
	}
	loggerDebug.Printf("TCP connection forwarded from %s to %s", conn.RemoteAddr(), rAddr)

	iwg := &sync.WaitGroup{}
	iwg.Add(2)

	go func() {
		defer iwg.Done()
		defer remote.Close()
		defer conn.Close()
		_, err := io.Copy(remote, conn)
		if err != nil && err != io.EOF {
			loggerDebug.Printf("Error copying from %s: %s", conn.RemoteAddr(), err)
		}
	}()

	go func() {
		defer iwg.Done()
		defer remote.Close()
		defer conn.Close()
		_, err := io.Copy(conn, remote)
		if err != nil {
			loggerDebug.Printf("Error copying to %s: %s", conn.RemoteAddr(), err)
		}
	}()

	iwg.Wait()
	loggerDebug.Printf("Connection from %s closed", conn.RemoteAddr())
}

func forwardUDP(ctx context.Context, waitGroup *sync.WaitGroup, config *forwardConfig, lNet netOp, rNet netOp) error {
	lAddr := config.lAddr.String()
	rAddr := config.dAddr.String()

	localConn, err := lNet.ListenPacket(ctx, "udp", lAddr)
	if err != nil {
		return err
	}

	remoteConns := newConnMap()

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("stopping UDP forwarder for %s -> %s", lAddr, rAddr)

		remoteConns.do(func(m map[string]net.Conn) {
			for addr, c := range m {
				c.Close()
				delete(m, addr)
			}
		})

		localConn.Close()
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		buffer := make([]byte, 1392)

		for {
			n, addr, err := localConn.ReadFrom(buffer)
			if err != nil {
				loggerDebug.Printf("error reading from UDP socket: %#v", err)
				return
			}

			addrStr := addr.String()

			if loggerDebug.Writer() != io.Discard {
				loggerDebug.Printf("received %d bytes from %s for %s",
					n, addrStr, lAddr)
			}

			remote, ok := remoteConns.lookup(addrStr)
			if ok {
				n, err = remote.Write(buffer[:n])
				if err != nil {
					loggerErr.Printf("error writing to remote UDP from %s: %s",
						addrStr, err)

					continue
				}

				if loggerDebug.Writer() != io.Discard {
					loggerDebug.Printf("forwarded %d bytes from %s to %s",
						n, addrStr, rAddr)
				}

				continue
			}

			remote, err = rNet.Dial(ctx, "udp", rAddr)
			if err != nil {
				loggerErr.Printf("error connecting to remote UDP: %s", err)
				continue
			}

			remoteConns.set(addrStr, remote)

			go func() {
				defer remoteConns.delete(addrStr)

				copyUDP(addr, remote, rAddr, localConn)
			}()
		}
	}()

	loggerInfo.Printf("udp forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

func copyUDP(addr net.Addr, remote net.Conn, rAddr string, localConn net.PacketConn) {
	buffer := make([]byte, 1392)

	for {
		remote.SetReadDeadline(time.Now().Add(udpTimeout))

		n, err := remote.Read(buffer)
		if err != nil {
			if loggerDebug.Writer() != io.Discard {
				loggerDebug.Printf("error reading from UDP socket: %s", err)
			}

			return
		}

		if loggerDebug.Writer() != io.Discard {
			loggerDebug.Printf("received %d bytes from %s for %s",
				n, rAddr, remote.LocalAddr())
		}

		_, err = localConn.WriteTo(buffer[:n], addr)
		if err != nil {
			if loggerDebug.Writer() != io.Discard {
				loggerDebug.Printf("error writing to local: %s", err)
			}

			return
		}

		if loggerDebug.Writer() != io.Discard {
			loggerDebug.Printf("forwarded %d bytes from %s to %s",
				n, rAddr, addr)
		}
	}
}

func newConnMap() *connMap {
	return &connMap{
		conns: make(map[string]net.Conn),
	}
}

type connMap struct {
	rwMu  sync.RWMutex
	conns map[string]net.Conn
}

func (o *connMap) set(addr string, conn net.Conn) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	o.conns[addr] = conn
}

func (o *connMap) do(fn func(m map[string]net.Conn)) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	fn(o.conns)
}

func (o *connMap) lookup(addr string) (net.Conn, bool) {
	o.rwMu.RLock()
	defer o.rwMu.RUnlock()

	conn, ok := o.conns[addr]

	return conn, ok
}

func (o *connMap) delete(addr string) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	delete(o.conns, addr)
}

type addrPort struct {
	addr string
	port uint16
}

func (o addrPort) String() string {
	return net.JoinHostPort(o.addr, strconv.Itoa(int(o.port)))
}

func (o addrPort) toAddrPort() (netip.AddrPort, error) {
	// TODO: Name resolution.
	addr, err := netip.ParseAddr(o.addr)
	if err != nil {
		return netip.AddrPort{}, err
	}

	return netip.AddrPortFrom(addr, o.port), nil
}

type forwardFlag struct {
	transport     string
	strsToConfigs map[string]*forwardConfig
}

func (o *forwardFlag) Set(fwd string) error {
	_, alreadyHasIt := o.strsToConfigs[fwd]
	if alreadyHasIt {
		return errors.New("forward config already specified")
	}

	config, err := parseForwardingConfig(o.transport, fwd)
	if err != nil {
		return err
	}

	if o.strsToConfigs == nil {
		o.strsToConfigs = make(map[string]*forwardConfig)
	}

	o.strsToConfigs["-"+o.transport+" "+fwd] = config

	return nil
}

func parseForwardingConfig(transport string, fwd string) (*forwardConfig, error) {
	listenSide, dialSide, hasIt := strings.Cut(fwd, "->")
	if !hasIt {
		return nil, errors.New("missing '->'")
	}

	lnet, listenAddr, err := parseForwardSideStr(listenSide)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen spec %q - %w",
			listenSide, err)
	}

	dnet, dialAddr, err := parseForwardSideStr(dialSide)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dial address %q - %w",
			dialSide, err)
	}

	return &forwardConfig{
		proto: transport,
		lNet:  lnet,
		lAddr: listenAddr,
		dNet:  dnet,
		dAddr: dialAddr,
	}, nil
}

func parseForwardSideStr(str string) (netType, addrPort, error) {
	fields := strings.Fields(strings.TrimSpace(str))

	if len(fields) != 2 {
		return unknownNetType, addrPort{}, errors.New("format should be: <net-type> <address>")
	}

	var netT netType
	switch fields[0] {
	case "host", "tun":
		netT = netType(fields[0])
	default:
		return unknownNetType, addrPort{}, fmt.Errorf("unknown network type: %q", fields[0])
	}

	addr, err := strToAddrAndPort(fields[1])
	if err != nil {
		return unknownNetType, addrPort{}, fmt.Errorf("failed to parse address %q - %w",
			fields[1], err)
	}

	return netT, addr, nil
}

type forwardConfig struct {
	proto string
	lNet  netType
	lAddr addrPort
	dNet  netType
	dAddr addrPort
}

type netType string

const (
	unknownNetType netType = ""
	hostNetType    netType = "host"
	tunNetType     netType = "tun"
)

func strToAddrAndPort(str string) (addrPort, error) {
	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		return addrPort{}, err
	}

	port, err := strToPort(portStr)
	if err != nil {
		return addrPort{}, err
	}

	return addrPort{
		addr: host,
		port: port,
	}, nil
}

func strToPort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(port), nil
}

func (o *forwardFlag) String() string {
	return "" // TODO
}

func doAutoAddrPlanning(cfg *wgconfig.Config) error {
	ourIntAddr, err := publicKeyToV6Addr(cfg.Interface.PublicKey[:])
	if err != nil {
		return fmt.Errorf("failed to convert our public key to v6 addr: %q - %w",
			base64.StdEncoding.EncodeToString(cfg.Interface.PublicKey[:]), err)
	}

	ourAddr := netip.PrefixFrom(ourIntAddr, 128)
	cfg.Interface.Address = &ourAddr

	var peers []autoPeer

	for _, peer := range cfg.Peers {
		peerAddr, err := publicKeyToV6Addr(peer.PublicKey[:])
		if err != nil {
			return fmt.Errorf("failed to convert peer public key to v6 addr: %q - %w",
				base64.StdEncoding.EncodeToString(peer.PublicKey[:]), err)
		}

		peer.AllowedIPs = append(peer.AllowedIPs, netip.PrefixFrom(peerAddr, 128))

		peers = append(peers, autoPeer{
			publicKey: peer.PublicKey[:],
			addr:      peerAddr,
		})
	}

	return nil
}

type autoPeer struct {
	publicKey []byte
	addr      netip.Addr
}

type replaceWgAddrShortcutsArgs struct {
	addr      *string
	ourWgAddr string
	peers     []*wgconfig.Peer
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	if *args.addr == "us" {
		*args.addr = args.ourWgAddr
		return nil
	}

	nPeers := len(args.peers)

	if n, ok := isPeerNStr(*args.addr); ok {
		if n >= nPeers {
			return fmt.Errorf("peer index %d was specified but only %d peers are declared", n, nPeers)
		}

		addr, err := singleAddrPrefix(args.peers[n].AllowedIPs)
		if err != nil {
			return fmt.Errorf("failed to get address for peer index %d (%s) - %w",
				n,
				base64.StdEncoding.EncodeToString(args.peers[n].PublicKey[:]),
				err)
		}

		*args.addr = addr.String()

		return nil
	}

	if publicKey, ok := isWgPublicKeyStr(*args.addr); ok {
		addr, err := publicKeyToV6Addr(publicKey)
		if err != nil {
			return fmt.Errorf("failed to convert peer public key to v6 addr: %q - %w",
				*args.addr, err)
		}

		*args.addr = addr.String()
	}

	return nil
}

func isPeerNStr(str string) (int, bool) {
	withoutPeer := strings.TrimPrefix(str, "peer")
	if withoutPeer == str {
		return 0, false
	}

	n, err := strconv.Atoi(withoutPeer)
	if err != nil {
		return 0, false
	}

	return n, true
}

func singleAddrPrefix(prefixes []netip.Prefix) (netip.Addr, error) {
	if len(prefixes) == 0 {
		return netip.Addr{}, errors.New("no AllowedIPs were specified")
	}

	for _, prefix := range prefixes {
		if prefix.Bits() == 128 || prefix.Bits() == 32 {
			return prefix.Addr(), nil
		}
	}

	return netip.Addr{}, errors.New("AllowedIPs missing single address entry")
}

func isWgPublicKeyStr(str string) ([]byte, bool) {
	if len(str) < device.NoisePublicKeySize {
		return nil, false
	}

	pub, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, false
	}

	if len(pub) != device.NoisePublicKeySize {
		return nil, false
	}

	return pub, true
}

func publicKeyToV6Addr(pub []byte) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(pub[len(pub)-16:])
	if !ok {
		return netip.Addr{}, errors.New("netip.AddrFromSlice returned false")
	}

	return addr, nil
}

func isLocalAddr(addr netip.Addr) (bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range ifs {
		hasIt, err := ifaceHasAddr(iface, addr)
		if err != nil {
			return false, err
		}

		if hasIt {
			return true, nil
		}
	}

	return false, nil
}

func ifaceHasAddr(iface net.Interface, addr netip.Addr) (bool, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return false, err
	}

	for _, ifAddrStr := range addrs {
		ifAddr, err := netip.ParseAddr(ifAddrStr.String())
		if err != nil {
			return false, err
		}

		if ifAddr == addr {
			return true, nil
		}
	}

	return false, nil
}
