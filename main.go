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

	"gitlab.com/stephen-fox/wgu/internal/ini"
	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"gitlab.com/stephen-fox/wgu/internal/wgdns"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	appName = "wgu"

	usage = `SYNOPSIS
  ` + appName + ` ` + helpCmd + `
  ` + appName + ` ` + genconfigCmd + ` [dir]
  ` + appName + ` ` + pubkeyCmd + ` < private-key-file
  ` + appName + ` ` + pubkeyFromConfigCmd + ` < public-key-file
  ` + appName + ` ` + pubkeyAddrCmd + ` < public-key-file
  ` + appName + ` ` + upCmd + ` [options] CONFIG-PATH

DESCRIPTION
  wgu (WireGuard User Space) is a fork of Jonathan Giannuzzi's wgfwd.
  wgu allows users to create WireGuard tunnels without running as root
  Connections to network services running on peers are managed using
  forwarding specifications. Each specification tells wgu where to listen
  for incoming connections and where to forward the connections to.

  For detailed documentation and configuration examples, please execute:
    ` + appName + ` ` + helpCmd + `

  To generate a basic configuration file and private key, please execute:
    ` + appName + ` ` + genconfigCmd + `

OPTIONS
`

	helpLong = `COMMANDS

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
  ` + upCmd + ` CONFIG-PATH     - Start the virtual WireGuard interface and forwarders

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

    @us
      The first IP address of our virtual WireGuard interface

    @<peer-name>
      The address of the peer with the corresponding name according
      to the peer's Name field

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
    TCP = tun @us:2000 -> host 127.0.0.1:2000

    [Peer]
    Name = peer1
    PublicKey = (peer1's public key goes here)
    AllowedIPs = 192.168.0.2/32

  Modify peer1's config file to look like the following:
    [Interface]
    PrivateKey = (...)
    Address = 192.168.0.2/24

    [Forwards]
    TCP = host 127.0.0.1:3000 -> tun @peer0:2000

    [Peer]
    Name = peer0
    PublicKey = (peer0's public key goes here)
    Endpoint = 127.0.0.1:4141
    AllowedIPs = 192.168.0.1/32

  To create the tunnel, execute the following commands in two
  different shells:
    $ wgu ` + upCmd + ` peer0/wgu.conf
    $ wgu ` + upCmd + ` peer1/wgu.conf

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
    TCP = tun @us:2000 -> host 127.0.0.1:2000

    [Peer]
    Name = peer1
    PublicKey = (peer1's public key goes here)

  Modify peer1's config file to look like the following:
    [Interface]
    PrivateKey = (...)

    [Forwards]
    TCP = host 127.0.0.1:3000 -> tun @peer0:2000

    [Peer]
    Name = peer0
    PublicKey = (peer0's public key goes here)
    Endpoint = 127.0.0.1:4141

  To create the tunnel *and* enable automatic address planning,
  execute the following commands in two different shells:
    $ wgu ` + upCmd + ` -` + autoAddressPlanningArg + ` peer0/wgu.conf
    $ wgu ` + upCmd + ` -` + autoAddressPlanningArg + ` peer1/wgu.conf

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
	upCmd               = "up"

	logLevelArg            = "L"
	noLogTimestampsArg     = "T"
	autoAddressPlanningArg = "A"
	helpArg                = "h"
	forwardArg             = "f"
	udpTimeoutArg          = "udp-timeout"

	helpArgv = "'" + appName + " " + helpCmd + "'"
)

var (
	udpTimeout time.Duration

	loggerInfo  = log.New(io.Discard, "", 0)
	loggerErr   = log.New(io.Discard, "", 0)
	loggerDebug = log.New(io.Discard, "", 0)

	// These bools are used to control logging in places where
	// performance really matters (like UDP forwarding).
	linfo  = false
	lerr   = false
	ldebug = false
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	flagSet := flag.CommandLine

	help := flagSet.Bool(
		helpArg,
		false,
		"Display this information")

	flagSet.Parse(os.Args[1:])

	// Disable annoying flag.PrintDefaults on flag parse error.
	flagSet.Usage = func() {}

	flagSet.Parse(os.Args[1:])

	if *help {
		flagSet.Output().Write([]byte(usage))
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	command := flagSet.Arg(0)

	switch command {
	case helpCmd:
		os.Stdout.WriteString(helpLong)
	case genconfigCmd:
		return genConfig()
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
	case upCmd:
		return up()
	default:
		return fmt.Errorf("unknown command: %q", command)
	}

	return nil
}

func genConfig() error {
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
# TCP = host 127.0.0.1:3000 -> tun @peer0:2000
# TCP = tun @us:2000 -> host 127.0.0.1:2000

# Example peer definition:
#
# [Peer]
# Name = peer0
# PublicKey = <public-key>
# Endpoint = 192.168.0.1:4141
# PersistentKeepalive = 25
# AllowedIPs = 192.168.0.2/32
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

	return nil
}

func up() error {
	flagSet := flag.NewFlagSet(upCmd, flag.ExitOnError)

	help := flagSet.Bool(
		helpArg,
		false,
		"Display this information")

	flagSet.DurationVar(
		&udpTimeout,
		udpTimeoutArg,
		2*time.Minute,
		"UDP timeout")

	autoAddrPlanning := flagSet.Bool(
		autoAddressPlanningArg,
		false,
		"Enable automatic address planning mode (see "+helpArgv+" for details)")

	writeConfig := flagSet.Bool(
		"write-config",
		false,
		"")

	writeIpcConfig := flagSet.Bool(
		"write-ipc-config",
		false,
		"")

	logLevelString := flagSet.String(
		logLevelArg,
		"info",
		"Log level (possible values: 'error', 'info', 'debug')")

	noLogTimestamps := flagSet.Bool(
		noLogTimestampsArg,
		false,
		"Disable logging timestamps")

	// Disable annoying flag.PrintDefaults on flag parse error.
	flagSet.Usage = func() {}

	flagSet.Parse(os.Args[2:])

	if *help {
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if flagSet.NArg() > 1 {
		return errors.New("please specify only one config file path")
	}

	if !*noLogTimestamps {
		log.SetFlags(log.LstdFlags)
	}

	switch *logLevelString {
	case "debug":
		ldebug = true
		loggerDebug = log.New(log.Writer(), "[debug] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "info":
		linfo = true
		loggerInfo = log.New(log.Writer(), "[info] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "error":
		lerr = true
		loggerErr = log.New(log.Writer(), "[error] ", log.Flags()|log.Lmsgprefix)
	default:
		return fmt.Errorf("unknown log level: %q", *logLevelString)
	}

	configPath := flagSet.Arg(0)

	var configFD *os.File
	switch configPath {
	case "":
		return errors.New("please specify a config file path as the last argument")
	case "-":
		configFD = os.Stdin
	default:
		var err error
		configFD, err = os.Open(configPath)
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

	appCfg, err := ParseConfig(cfg.Others)
	if err != nil {
		return fmt.Errorf("failed to parse app config - %w", err)
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
	for str, forward := range appCfg.Forwarders {
		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:      &forward.ListenAddr.addr,
			ourWgAddr: ourWgAddrStr,
			wgConfig:  cfg,
		})
		if err != nil {
			return fmt.Errorf("failed to replace listen addr for %q - %w",
				str, err)
		}

		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:      &forward.DialAddr.addr,
			ourWgAddr: ourWgAddrStr,
			wgConfig:  cfg,
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
		return fmt.Errorf("failed to convert config to wg ipc format - %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.Interface.Address.Addr()},
		[]netip.Addr{},
		*cfg.Interface.MTU,
	)
	if err != nil {
		return fmt.Errorf("failed to create wg tunnel interface: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: loggerDebug.Printf,
		Errorf:   loggerErr.Printf,
	})

	err = dev.IpcSet(ipcConfig)
	if err != nil {
		return fmt.Errorf("failed to set wg device configuration - %w", err)
	}

	err = dev.Up()
	if err != nil {
		return fmt.Errorf("failed to bring up wg device - %w", err)
	}
	defer dev.Down()

	loggerInfo.Println("wg device up")

	dnsMonitorErrs := make(chan error, 1)
	wgdns.MonitorPeers(ctx, cfg.Peers, dev, dnsMonitorErrs, loggerInfo)

	waitGroup, err := startForwarders(ctx, tnet, appCfg.Forwarders)
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

func ParseConfig(sections []*ini.Section) (*Config, error) {
	config := &Config{}

	for _, section := range sections {
		if section.Name != "Forwarder" {
			continue
		}

		err := config.parseForwarder(section)
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

type Config struct {
	Forwarders map[string]*ForwarderSpec
}

func (o *Config) parseForwarder(fwd *ini.Section) error {
	name, err := fwd.FirstParam("Name")
	if err != nil {
		return err
	}

	listen, err := fwd.FirstParam("Listen")
	if err != nil {
		return err
	}

	dial, err := fwd.FirstParam("Dial")
	if err != nil {
		return err
	}

	lNetwork, lProtocol, lAddr, err := parseForwarderTransitSpec(listen.Value)
	if err != nil {
		return fmt.Errorf("failed to parse listen spec - %w", err)
	}

	dNetwork, dProtocol, dAddr, err := parseForwarderTransitSpec(dial.Value)
	if err != nil {
		return fmt.Errorf("failed to parse dial spec - %w", err)
	}

	_, alreadyHasIt := o.Forwarders[name.Value]
	if alreadyHasIt {
		return fmt.Errorf("forward config already specified: %q", name)
	}

	if o.Forwarders == nil {
		o.Forwarders = make(map[string]*ForwarderSpec)
	}

	o.Forwarders[name.Value] = &ForwarderSpec{
		ListenNet:   lNetwork,
		ListenProto: lProtocol,
		ListenAddr:  lAddr,
		DialNet:     dNetwork,
		DialProto:   dProtocol,
		DialAddr:    dAddr,
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

func startForwarders(ctx context.Context, tnet *netstack.Net, forwards map[string]*ForwarderSpec) (*sync.WaitGroup, error) {
	waitGroup := &sync.WaitGroup{}
	var localNetOp = &localNetOp{}
	var tunnelNetOp = &tunnelNetOp{tnet}

	for fwdStr, fwd := range forwards {
		var listenNet netOp
		switch fwd.ListenNet {
		case HostNetT:
			listenNet = localNetOp
		case TunNetT:
			listenNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported listen net type: %q", fwd.ListenNet)
		}

		var dialNet netOp
		switch fwd.DialNet {
		case HostNetT:
			dialNet = localNetOp
		case TunNetT:
			dialNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported dial net type: %q", fwd.ListenNet)
		}

		loggerInfo.Printf("starting %q...", fwdStr)

		var err error

		switch {
		case fwd.ListenProto.IsStream():
			err = forwardStream(ctx, waitGroup, fwd, listenNet, dialNet)
		case fwd.ListenProto.IsDatagram():
			err = forwardDatagram(ctx, waitGroup, fwd, listenNet, dialNet)
		default:
			err = fmt.Errorf("unsupported listen protocol: %q", fwd.ListenProto)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to forward %q - %w", fwdStr, err)
		}
	}

	return waitGroup, nil
}

func forwardStream(ctx context.Context, waitg *sync.WaitGroup, spec *ForwarderSpec, lNet netOp, dNet netOp) error {
	lAddr := spec.ListenAddr.String()
	dAddr := spec.DialAddr.String()

	listener, err := lNet.Listen(ctx, string(spec.ListenProto), lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("stopping %s forwarder for %s -> %s...",
			spec.ListenProto, lAddr, dAddr)

		listener.Close()
	}()

	waitg.Add(1)
	go func() {
		defer waitg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if lerr {
					loggerErr.Printf("error accepting %s connection: %s",
						spec.ListenProto, err)
				}

				return
			}

			if ldebug {
				loggerDebug.Printf("accepted TCP connection from %s for %s",
					conn.RemoteAddr(), lAddr)
			}

			go dialAndCopyStream(ctx, conn, dNet, spec.DialProto, dAddr)
		}
	}()

	loggerInfo.Printf("stream forwarder started for %s %s -> %s",
		spec.ListenProto, lAddr, dAddr)

	return nil
}

func dialAndCopyStream(ctx context.Context, src net.Conn, dNet netOp, dPro ProtocolT, dstAddr string) {
	defer src.Close()

	dst, err := dNet.Dial(ctx, string(dPro), dstAddr)
	if err != nil {
		if lerr {
			loggerErr.Printf("error connecting to remote %s: %s",
				dPro, err)
		}

		return
	}
	defer dst.Close()

	if ldebug {
		loggerDebug.Printf("stream connection forwarded from %s %s to %s %s",
			src.LocalAddr().Network(), src.RemoteAddr(), dPro, dstAddr)
	}

	done := make(chan string, 2)

	go func() {
		_, err := io.Copy(dst, src)
		done <- fmt.Sprintf("error copying from %s: %v",
			src.RemoteAddr(), err)
	}()

	go func() {
		_, err := io.Copy(src, dst)
		done <- fmt.Sprintf("error copying to %s: %v",
			src.RemoteAddr(), err)
	}()

	select {
	case <-ctx.Done():
		return
	case reason := <-done:
		if ldebug {
			loggerDebug.Printf("connection from %s closed: %s",
				src.RemoteAddr(), reason)
		}
	}
}

func forwardDatagram(ctx context.Context, waitg *sync.WaitGroup, spec *ForwarderSpec, lNet netOp, dNet netOp) error {
	lAddr := spec.ListenAddr.String()
	rAddr := spec.DialAddr.String()

	localConn, err := lNet.ListenPacket(ctx, string(spec.ListenProto), lAddr)
	if err != nil {
		return err
	}

	remoteConns := newConnMap()

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("stopping %s orwarder for %s -> %s...",
			spec.ListenProto, lAddr, rAddr)

		remoteConns.do(func(m map[string]net.Conn) {
			for addr, c := range m {
				c.Close()
				delete(m, addr)
			}
		})

		localConn.Close()
	}()

	waitg.Add(1)
	go func() {
		defer waitg.Done()
		buffer := make([]byte, 1392)

		for {
			n, addr, err := localConn.ReadFrom(buffer)
			if err != nil {
				if ldebug {
					loggerDebug.Printf("error reading from %s socket: %#v",
						spec.ListenProto, err)
				}

				return
			}

			addrStr := addr.String()

			if ldebug {
				loggerDebug.Printf("received %d bytes from %s for %s",
					n, addrStr, lAddr)
			}

			remote, ok := remoteConns.lookup(addrStr)
			if ok {
				n, err = remote.Write(buffer[:n])
				if err != nil {
					if lerr {
						loggerErr.Printf("error writing to remote %s from %s: %s",
							spec.DialProto, addrStr, err)
					}

					continue
				}

				if ldebug {
					loggerDebug.Printf("forwarded %d bytes from %s to %s",
						n, addrStr, rAddr)
				}

				continue
			}

			remote, err = dNet.Dial(ctx, "udp", rAddr)
			if err != nil {
				if lerr {
					loggerErr.Printf("error connecting to remote %s: %s",
						spec.DialProto, err)
				}

				continue
			}

			remoteConns.set(addrStr, remote)

			go func() {
				defer remoteConns.delete(addrStr)

				copyDatagram(addr, remote, rAddr, localConn)
			}()
		}
	}()

	loggerInfo.Printf("datagram forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

func copyDatagram(addr net.Addr, remote net.Conn, dAddr string, localConn net.PacketConn) {
	buffer := make([]byte, 1392)

	for {
		remote.SetReadDeadline(time.Now().Add(udpTimeout))

		n, err := remote.Read(buffer)
		if err != nil {
			if ldebug {
				loggerDebug.Printf("error reading from %s socket: %s",
					remote.LocalAddr().Network(), err)
			}

			return
		}

		if ldebug {
			loggerDebug.Printf("received %d bytes from %s for %s",
				n, dAddr, remote.LocalAddr())
		}

		_, err = localConn.WriteTo(buffer[:n], addr)
		if err != nil {
			if ldebug {
				loggerDebug.Printf("error writing to local: %s", err)
			}

			return
		}

		if ldebug {
			loggerDebug.Printf("forwarded %d bytes from %s to %s",
				n, dAddr, addr)
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

type Addr struct {
	addr string
	port uint16
}

func (o Addr) String() string {
	if o.port == 0 {
		return o.addr
	}

	return net.JoinHostPort(o.addr, strconv.Itoa(int(o.port)))
}

func parseForwarderTransitSpec(str string) (NetT, ProtocolT, Addr, error) {
	fields := strings.Fields(strings.TrimSpace(str))

	if len(fields) != 3 {
		return UnknownNetT, "", Addr{}, errors.New("format should be: <net-type> <proto> <address>")
	}

	var netT NetT
	switch fields[0] {
	case "host", "tun":
		netT = NetT(fields[0])
	default:
		return UnknownNetT, "", Addr{}, fmt.Errorf("unknown network type: %q", fields[0])
	}

	proto := ProtocolT(fields[1])

	var addr Addr
	var err error
	if strings.HasPrefix(string(proto), "unix") {
		addr = Addr{addr: fields[2]}
	} else {
		addr, err = strToAddrAndPort(fields[2])
		if err != nil {
			return UnknownNetT, "", Addr{}, fmt.Errorf("failed to parse address %q - %w",
				fields[1], err)
		}
	}

	return netT, ProtocolT(fields[1]), addr, nil
}

type ForwarderSpec struct {
	ListenNet   NetT
	ListenProto ProtocolT
	ListenAddr  Addr
	DialNet     NetT
	DialProto   ProtocolT
	DialAddr    Addr
}

type NetT string

const (
	UnknownNetT NetT = ""
	HostNetT    NetT = "host"
	TunNetT     NetT = "tun"
)

type ProtocolT string

func (proto ProtocolT) IsStream() bool {
	switch {
	case strings.HasPrefix(string(proto), "tcp"):
		return true
	case proto == "unix":
		return true
	default:
		return false
	}
}

func (proto ProtocolT) IsDatagram() bool {
	switch {
	case strings.HasPrefix(string(proto), "udp"):
		return true
	case proto == "unixgram":
		return true
	default:
		return false
	}
}

func strToAddrAndPort(str string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		return Addr{}, err
	}

	port, err := strToPort(portStr)
	if err != nil {
		return Addr{}, err
	}

	return Addr{
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
	wgConfig  *wgconfig.Config
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	if *args.addr == "@us" {
		*args.addr = args.ourWgAddr
		return nil
	}

	if strings.HasPrefix(*args.addr, "@") {
		name := *args.addr
		name = name[1:]

		actualPeer, hasIt := args.wgConfig.NamedPeer[name]
		if !hasIt {
			return fmt.Errorf("unknown peer nickname: %q", name)
		}

		addr, err := singleAddrPrefix(actualPeer.AllowedIPs)
		if err != nil {
			return fmt.Errorf("failed to get address for peer with nickname %q - %w",
				name,
				err)
		}

		*args.addr = addr.String()

		return nil
	}

	return nil
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

func publicKeyToV6Addr(pub []byte) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(pub[len(pub)-16:])
	if !ok {
		return netip.Addr{}, errors.New("netip.AddrFromSlice returned false")
	}

	return addr, nil
}
