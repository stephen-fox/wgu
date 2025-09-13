// wgu (WireGuard Userspace) is a fork of Jonathan Giannuzzi's wgfwd.
// wgu creates WireGuard tunnels without superuser privileges.
// Connections to network services are managed using forwarders.
// Each forwarder tells wgu where to listen for incoming connections
// and where to forward connections to.
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
  ` + appName + ` ` + pubkeyFromConfigCmd + ` [config-file] [< config-file]
  ` + appName + ` ` + pubkeyAddrCmd + ` < public-key-file
  ` + appName + ` ` + upCmd + ` [options] [config-file]

DESCRIPTION
  wgu (WireGuard Userspace) is a fork of Jonathan Giannuzzi's wgfwd.
  wgu creates WireGuard tunnels without superuser privileges.
  Connections to network services are managed using forwarders.
  Each forwarder tells wgu where to listen for incoming connections
  and where to forward connections to.

  For detailed documentation and configuration examples, please execute:
    ` + appName + ` ` + helpCmd + `

  To generate a basic configuration file and private key, please execute:
    ` + appName + ` ` + genconfigCmd + `

OPTIONS
`

	helpLong = `COMMANDS

  ` + helpCmd + `             - Display configuration syntax help and examples
  ` + genconfigCmd + ` [dir]    - Generate an example configuration file and private key.
                     The config and private key files are written to ~/.wgu
                     by default. This can be overriden by specifying a path
                     as an argument
  ` + genkeyCmd + `           - Generate a new WireGuard private key and write it
                     to stdout
  ` + pubkeyCmd + `           - Read a WireGuard private key from stdin and write
                     its public key to stdout
  ` + pubkeyFromConfigCmd + `       - Read a configuration file from a path or stdin, parse
                     its private key, and write the public key to stdout
  ` + pubkeyAddrCmd + `       - (automatic address planning mode) - Read a public key
                     from stdin and convert it to an IPv6 address
  ` + upCmd + ` [config-file] - Start the virtual WireGuard interface and forwarders.
                     Defaults to using the configuration file located at
                     ~/.` + appName + `/` + defConfigFileName + ` if one is unspecified

CONFIGURATION
  After installing wgu, it is recommended to create an example configuration
  file and a private key file using the ` + genconfigCmd + ` command. The following
  example will create a .wgu directory in the user's home directory
  containing an example configuration file and a private key file.
  The private key's corresponding public key is written to standard output:

    $ wgu genconf
    z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=

  ` + appName + ` is configured using an INI configuration file in a similar manner
  to WireGuard. Additional options can be specified using command line
  arguments.

  General application settings can be specified in the configuration file
  in the ` + appOptionsConfigSection + ` section. For example:

    [` + appOptionsConfigSection + `]
    ExampleParameter = some value

  The following general application parameters are available:

    - ` + autoAddrPlanningModeConfigOpt + ` - Enables automatic address planning mode
      if set to "true". Defaults to "false" if unspecified. In this mode,
      each peer's virtual WireGuard address is generated from its public key
      in the form of an IPv6 address. This mode makes it easier to construct
      simple WireGuard topologies without planning out IP address allocations
      or needing to know each peer's WireGuard address. It is unnecessary to
      specify the 'Address' configuration parameter for other peers in this
      mode. Refer to the AUTOMATIC ADDRESS PLANNING MODE EXAMPLE section for
      an example.

FORWARDER CONFIGURATION
  Port forwards are defined in a Forwarder configuration section using
  the following configuration fields:

    [Forwarder]
    Name = <name>
    Listen = <transit-specification>
    Dial = <transit-specification>

  A transit specification is of the format:

    net-stack protocol address:port

  "net-stack" may be one of the following values:

    - host - The host computer's networking stack is used
    - tun  - The WireGuard networking stack is used

  "protocol" can be any of the strings that the Go net library takes.
  This includes:

    - tcp, tcp6
    - udp, udp6
    - unix, unixgram, unixpacket

  For more information on the above strings, refer to the Go's net.Dial
  documentation: https://pkg.go.dev/net#Dial

  For example, the following configuration forwards TCP connections to
  127.0.0.1:22 on the host machine to a WireGuard peer who has the
  virtual address of 10.0.0.1:

    [Forwarder]
    Name = example
    Listen = host tcp 127.0.0.1:22
    Dial = tun tcp 10.0.0.1:22

  Protocols can be mixed. In the following example, connections to the
  Unix socket "example.sock" will be forwarded to a WireGuard peer
  who has the virtual address of 10.0.0.1 using TCP:

    [Forwarder]
    Name = example
    Listen = host unix example.sock
    Dial = tun tcp 10.0.0.1:22

FORWARDER MAGIC STRINGS
  The "address" values can be replaced with magic strings that are
  expanded to the corresponding address:

    @us
      The first IP address of our virtual WireGuard interface

    @<peer-name>
      The address of the peer with the corresponding name according
      to the peer's Name field

HELLO WORLD EXAMPLE
  In this example, we will create two WireGuard peers on the current computer
  and forward connections to TCP port 2000 to port 3000.

  First, create two configuration directories using ` + genconfigCmd + `:

    $ wgu ` + genconfigCmd + ` peer0
    (peer0's public key)
    $ wgu ` + genconfigCmd + ` peer1
    (peer1's public key)

  Edit peer0's config file, and make it look similar to the following:

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

  Modify peer1's config file to look like the following:

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
    (peer0's public key)
    $ wgu ` + genconfigCmd + ` peer1
    (peer1's public key)

  Edit peer0's config file, and make it look similar to the following:

    [` + appOptionsConfigSection + `]
    ` + autoAddrPlanningModeConfigOpt + ` = true

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

  Modify peer1's config file to look like the following:

    [` + appOptionsConfigSection + `]
    ` + autoAddrPlanningModeConfigOpt + ` = true

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

  To create the tunnel *and* enable automatic address planning,
  execute the following commands in two different shells:

    $ wgu ` + upCmd + ` peer0/wgu.conf
    $ wgu ` + upCmd + ` peer1/wgu.conf

  Finally, in two different shells, test the tunnel using nc:

    $ nc -l 2000
    $ echo 'hello' | nc 127.0.0.1 3000
`

	helpCmd             = "help"
	genconfigCmd        = "genconf"
	genkeyCmd           = "genkey"
	pubkeyCmd           = "pubkey"
	pubkeyFromConfigCmd = "pubkeyconf"
	pubkeyAddrCmd       = "pubkeyaddr"
	upCmd               = "up"

	logLevelArg        = "L"
	noLogTimestampsArg = "T"
	helpArg            = "h"
	childArg           = "c"
	udpTimeoutArg      = "udp-timeout"

	defConfigFileName = appName + ".conf"

	appOptionsConfigSection       = appName
	autoAddrPlanningModeConfigOpt = "AutomaticAddressPlanningMode"

	forwarderConfigSection = "Forwarder"
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
		srcArg := flagSet.Arg(1)

		src := os.Stdin
		defer src.Close()

		switch srcArg {
		case "":
			inStat, _ := os.Stdin.Stat()
			if inStat.Mode()&os.ModeCharDevice == 0 {
				// Use stdin.
				break
			}

			configDirPath, err := defConfigDirPath()
			if err != nil {
				return err
			}

			configPath := filepath.Join(configDirPath, defConfigFileName)

			src, err = os.Open(configPath)
			if err != nil {
				return fmt.Errorf("failed to open config file '%s' - %w",
					configPath, err)
			}
		default:
			var err error

			src, err = os.Open(flagSet.Arg(1))
			if err != nil {
				return fmt.Errorf("failed to open config file '%s' - %w",
					srcArg, err)
			}
		}

		cfg, err := wgconfig.Parse(src)
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
	var err error

	if flag.NArg() > 1 {
		configDirPath, err = filepath.Abs(flag.Arg(1))
		if err != nil {
			return err
		}

		privateKeyPathInConfig = filepath.Join(configDirPath, privateKeyFileName)
	} else {
		configDirPath, err = defConfigDirPath()
		if err != nil {
			return err
		}

		privateKeyPathInConfig = "~/." + appName + "/" + privateKeyFileName
	}

	err = os.MkdirAll(configDirPath, 0o700)
	if err != nil {
		return err
	}

	err = os.Chmod(configDirPath, 0o700)
	if err != nil {
		return err
	}

	configFilePath := filepath.Join(configDirPath, defConfigFileName)

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

	err = os.WriteFile(configFilePath, []byte(`[`+appOptionsConfigSection+`]
# `+autoAddrPlanningModeConfigOpt+` = true

[Interface]
PrivateKey = file://`+privateKeyPathInConfig+`
# Optionally, allow other peers to connect to us:
# ListenPort = 4141

# The following example sends connections to TCP port 2000 on
# the WireGuard tunnel to the same port on your machine:
#
# [Forwarder]
# Name = example tun recv
# Listen = tun tcp @us:2000
# Dial = host tcp 127.0.0.1:2000
#
# The following forwarding example sends connections to TCP
# port 2000 on your machine to the WireGuard peer named peer0:
#
# [Forwarder]
# Name = example host forward
# Listen = host tcp 127.0.0.1:3000
# Dial = tun tcp @peer0:2000

# Example peer definition:
#
# [Peer]
# Name = peer0
# PublicKey = <public-key>
# Endpoint = 127.0.0.1:4141
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

func defConfigDirPath() (string, error) {
	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user's home directory - %w", err)
	}

	return filepath.Join(homeDirPath, "."+appName), nil
}

func up() error {
	flagSet := flag.NewFlagSet(upCmd, flag.ExitOnError)

	help := flagSet.Bool(
		helpArg,
		false,
		"Display this information")

	child := flagSet.Bool(
		childArg,
		false,
		"Indicate that process is running as a child of another process")

	flagSet.DurationVar(
		&udpTimeout,
		udpTimeoutArg,
		2*time.Minute,
		"UDP timeout")

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
		configDirPath, err := defConfigDirPath()
		if err != nil {
			return fmt.Errorf("failed to get default config directory - %w", err)
		}

		configFD, err = os.Open(filepath.Join(configDirPath, defConfigFileName))
		if err != nil {
			return err
		}
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

	if appCfg.IsAutoAddrPlanningMode {
		loggerInfo.Println("automatic address planning mode is enabled")

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
			host:      &forward.ListenAddr,
			ourWgAddr: ourWgAddrStr,
			wgConfig:  cfg,
		})
		if err != nil {
			return fmt.Errorf("failed to replace listen addr for %q - %w",
				str, err)
		}

		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			host:      &forward.DialAddr,
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

	if *child {
		os.Stdout.WriteString("ready\n")
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
		switch section.Name {
		case appOptionsConfigSection:
			err := config.parseOptions(section)
			if err != nil {
				return nil, err
			}
		case forwarderConfigSection:
			err := config.parseForwarder(section)
			if err != nil {
				return nil, err
			}
		}
	}

	return config, nil
}

type Config struct {
	IsAutoAddrPlanningMode bool
	Forwarders             map[string]*ForwarderSpec
}

func (o *Config) parseOptions(options *ini.Section) error {
	autoAddrPlanning, _ := options.FirstParam("AutomaticAddressPlanningMode")
	if autoAddrPlanning != nil {
		enabled, err := strconv.ParseBool(autoAddrPlanning.Value)
		if err != nil {
			return fmt.Errorf("failed to parse automatic address planning mode value: %q - %w",
				autoAddrPlanning.Value, err)
		}

		o.IsAutoAddrPlanningMode = enabled
	}

	return nil
}

func (o *Config) parseForwarder(fwd *ini.Section) error {
	name, err := fwd.FirstParam("Name")
	if err != nil {
		return err
	}

	listen, err := fwd.FirstParam("Listen")
	if err != nil {
		return fmt.Errorf("forwarder %q: %w", name.Value, err)
	}

	dial, err := fwd.FirstParam("Dial")
	if err != nil {
		return fmt.Errorf("forwarder %q: %w", name.Value, err)
	}

	lNetwork, lAddr, err := parseTransitSpec(listen.Value)
	if err != nil {
		return fmt.Errorf("failed to parse listen transit spec for %q - %w",
			name.Value, err)
	}

	dNetwork, dAddr, err := parseTransitSpec(dial.Value)
	if err != nil {
		return fmt.Errorf("failed to parse dial transit spec for %q - %w",
			name.Value, err)
	}

	_, alreadyHasIt := o.Forwarders[name.Value]
	if alreadyHasIt {
		return fmt.Errorf("forward config already specified: %q", name)
	}

	var dialTimeout time.Duration

	dialTimeoutStr, _ := fwd.FirstParam("DialTimeout")
	if dialTimeoutStr != nil {
		dialTimeout, err = time.ParseDuration(dialTimeoutStr.Value)
		if err != nil {
			return fmt.Errorf("failed to parse dial timeout: %q - %w",
				dialTimeoutStr.Value, err)
		}
	}

	if o.Forwarders == nil {
		o.Forwarders = make(map[string]*ForwarderSpec)
	}

	o.Forwarders[name.Value] = &ForwarderSpec{
		Name:           name.Value,
		ListenNet:      lNetwork,
		ListenAddr:     lAddr,
		DialNet:        dNetwork,
		DialAddr:       dAddr,
		OptDialTimeout: dialTimeout,
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
		case HostNetStackT:
			listenNet = localNetOp
		case TunNetStackT:
			listenNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported listen net stack: %q", fwd.ListenNet)
		}

		var dialNet netOp
		switch fwd.DialNet {
		case HostNetStackT:
			dialNet = localNetOp
		case TunNetStackT:
			dialNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported dial net stack: %q", fwd.DialNet)
		}

		loggerInfo.Printf("starting %q (%s)...", fwd.Name, fwd.String())

		var err error

		switch {
		case fwd.ListenAddr.Protocol().IsStream():
			err = forwardStream(ctx, waitGroup, fwd, listenNet, dialNet)
		case fwd.ListenAddr.Protocol().IsDatagram():
			err = forwardDatagram(ctx, waitGroup, fwd, listenNet, dialNet)
		default:
			err = fmt.Errorf("unsupported listen protocol: %q", fwd.ListenAddr.Protocol())
		}

		if err != nil {
			return nil, fmt.Errorf("failed to forward %q - %w", fwdStr, err)
		}
	}

	return waitGroup, nil
}

func forwardStream(ctx context.Context, waitg *sync.WaitGroup, spec *ForwarderSpec, lNet netOp, dNet netOp) error {
	listener, err := lNet.Listen(ctx, string(spec.ListenAddr.Protocol()), spec.ListenAddr.String())
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("[%s] stopping forwarder...",
			spec.Name)

		listener.Close()
	}()

	waitg.Add(1)
	go func() {
		defer waitg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if lerr {
					loggerErr.Printf("[%s] error accepting connection - %s",
						spec.Name, err)
				}

				return
			}

			if ldebug {
				loggerDebug.Printf("[%s] accepted connection from %s",
					spec.Name, conn.RemoteAddr())
			}

			go dialAndCopyStream(ctx, conn, dNet, spec)
		}
	}()

	loggerInfo.Printf("[%s] stream forwarder started",
		spec.Name)

	return nil
}

func dialAndCopyStream(ctx context.Context, src net.Conn, dNet netOp, spec *ForwarderSpec) {
	defer src.Close()

	var dst net.Conn
	var err error

	if spec.OptDialTimeout > 0 {
		retrier := retryDialer{dNet.Dial}

		dst, err = retrier.dial(
			ctx,
			string(spec.DialAddr.Protocol()),
			spec.DialAddr.String(),
			spec.OptDialTimeout)
	} else {
		dst, err = dNet.Dial(
			ctx,
			string(spec.DialAddr.Protocol()),
			spec.DialAddr.String())
	}

	if err != nil {
		if lerr {
			loggerErr.Printf("[%s] error connecting to remote - %s",
				spec.Name, err)
		}

		return
	}
	defer dst.Close()

	if ldebug {
		loggerDebug.Printf("[%s] new stream connection forwarded",
			spec.Name)
	}

	done := make(chan string, 2)

	go func() {
		_, err := io.Copy(dst, src)
		if ldebug {
			done <- fmt.Sprintf("error copying from %s: %v",
				spec.DialAddr.String(), err)
		} else {
			done <- ""
		}
	}()

	go func() {
		_, err := io.Copy(src, dst)
		if ldebug {
			done <- fmt.Sprintf("error copying to %s: %v",
				src.RemoteAddr(), err)
		} else {
			done <- ""
		}
	}()

	select {
	case <-ctx.Done():
		return
	case reason := <-done:
		if reason != "" {
			loggerDebug.Printf("[%s] connection from %s closed - %s",
				spec.Name, src.RemoteAddr(), reason)
		}
	}
}

func forwardDatagram(ctx context.Context, waitg *sync.WaitGroup, spec *ForwarderSpec, lNet netOp, dNet netOp) error {
	localConn, err := lNet.ListenPacket(ctx, string(spec.ListenAddr.Protocol()), spec.ListenAddr.String())
	if err != nil {
		return err
	}

	srcToDstConns := newConnMap()

	go func() {
		<-ctx.Done()

		loggerInfo.Printf("[%s] stopping datagram forwarder...",
			spec.Name)

		localConn.Close()

		srcToDstConns.do(func(m map[string]net.Conn) {
			for addr, c := range m {
				c.Close()
				delete(m, addr)
			}
		})
	}()

	waitg.Add(1)
	go func() {
		defer waitg.Done()

		const bufSizeBytes = 1392
		buffer := make([]byte, bufSizeBytes)

		lAddrStr := spec.ListenAddr.String()
		dAddrStr := spec.DialAddr.String()

		for {
			n, srcAddr, err := localConn.ReadFrom(buffer)
			if err != nil {
				if ldebug {
					loggerDebug.Printf("[%s] error reading from datagram listener - %#v",
						spec.Name, err)
				}

				return
			}

			srcAddrStr := srcAddr.String()

			if ldebug {
				loggerDebug.Printf("[%s] received %d bytes from %s for %s",
					spec.Name, n, srcAddrStr, lAddrStr)
			}

			remote, hasIt := srcToDstConns.lookup(srcAddrStr)
			if hasIt {
				n, err = remote.Write(buffer[:n])
				if err != nil {
					if lerr {
						loggerErr.Printf("[%s] error writing to remote %s - %s",
							spec.Name, srcAddrStr, err)
					}

					continue
				}

				if ldebug {
					loggerDebug.Printf("[%s] forwarded %d bytes from %s",
						spec.Name, n, srcAddrStr)
				}

				continue
			}

			go dialAndCopyDatagram(ctx, dialAndCopyDatagramArgs{
				name:        spec.Name,
				localConn:   localConn,
				srcAddr:     srcAddr,
				srcAddrStr:  srcAddrStr,
				dNet:        dNet,
				dProto:      spec.DialAddr.Protocol(),
				dAddrStr:    dAddrStr,
				bufSizeByte: bufSizeBytes,
				remoteConns: srcToDstConns,
				optTimeout:  spec.OptDialTimeout,
			})
		}
	}()

	loggerInfo.Printf("[%s] datagram forwarder started",
		spec.Name)

	return nil
}

type dialAndCopyDatagramArgs struct {
	name        string
	localConn   net.PacketConn
	srcAddr     net.Addr
	srcAddrStr  string
	dNet        netOp
	dProto      ProtocolT
	dAddrStr    string
	bufSizeByte int
	remoteConns *connMap
	optTimeout  time.Duration
}

func dialAndCopyDatagram(ctx context.Context, args dialAndCopyDatagramArgs) {
	var remote net.Conn
	var err error

	if args.optTimeout > 0 {
		retrier := retryDialer{args.dNet.Dial}

		remote, err = retrier.dial(
			ctx,
			string(args.dProto),
			args.dAddrStr,
			args.optTimeout)
	} else {
		remote, err = args.dNet.Dial(
			ctx,
			string(args.dProto),
			args.dAddrStr)
	}

	if err != nil {
		if lerr {
			loggerErr.Printf("[%s] error connecting to remote - %s",
				args.name, err)
		}

		return
	}

	args.remoteConns.set(args.srcAddrStr, remote)

	defer args.remoteConns.delete(args.srcAddrStr)

	buffer := make([]byte, args.bufSizeByte)

	for {
		remote.SetReadDeadline(time.Now().Add(udpTimeout))

		n, err := remote.Read(buffer)
		if err != nil {
			if ldebug {
				loggerDebug.Printf("[%s] error reading from socket - %s",
					args.name, err)
			}

			return
		}

		if ldebug {
			loggerDebug.Printf("[%s] received %d bytes from %s for %s",
				args.name, n, args.dAddrStr, remote.LocalAddr())
		}

		_, err = args.localConn.WriteTo(buffer[:n], args.srcAddr)
		if err != nil {
			if ldebug {
				loggerDebug.Printf("[%s] error writing to local - %s",
					args.name, err)
			}

			return
		}

		if ldebug {
			loggerDebug.Printf("[%s] forwarded %d bytes from %s to %s",
				args.name, n, args.dAddrStr, args.srcAddr)
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

type retryDialer struct {
	DialFn func(ctx context.Context, network string, address string) (net.Conn, error)
}

func (o *retryDialer) dial(ctx context.Context, network string, addr string, timeout time.Duration) (net.Conn, error) {
	wctx, cancelFn := context.WithTimeout(ctx, timeout)
	defer cancelFn()

	sleep := time.Second
	scale := time.Duration(2)
	attempts := 0

	for {
		attempts++

		conn, err := o.DialFn(wctx, network, addr)
		if err == nil {
			return conn, nil
		}

		select {
		case <-wctx.Done():
			return nil, fmt.Errorf("gave up connecting after %d attempt(s) - %w (last error: %v)",
				attempts, wctx.Err(), err)
		case <-time.After(sleep):
			// 1 * 2
			// 1 * 5
			// 1 * 8
			// 1 * 11
			sleep = sleep * scale

			scale = scale + 3
		}
	}
}

func strToAddr(proto ProtocolT, str string) (Addr, error) {
	if strings.HasPrefix(string(proto), "unix") {
		return Addr{
			proto: proto,
			addr:  str,
		}, nil
	}

	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		return Addr{}, err
	}

	port, err := strToPort(portStr)
	if err != nil {
		return Addr{}, err
	}

	return Addr{
		proto: proto,
		addr:  host,
		port:  port,
	}, nil
}

func strToPort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(port), nil
}

type Addr struct {
	proto ProtocolT
	addr  string
	port  uint16
}

func (o *Addr) SetHost(newHost string) {
	o.addr = newHost
}

func (o Addr) Protocol() ProtocolT {
	return o.proto
}

func (o Addr) Host() string {
	return o.addr
}

func (o Addr) Port() uint16 {
	return o.port
}

func (o Addr) String() string {
	if o.port == 0 {
		return o.addr
	}

	return net.JoinHostPort(o.addr, strconv.Itoa(int(o.port)))
}

func parseTransitSpec(str string) (NetStackT, Addr, error) {
	fields := strings.Fields(strings.TrimSpace(str))

	if len(fields) != 3 {
		return UnknownNetStackT, Addr{}, errors.New("format should be: <net-stack> <protocol> <address>")
	}

	var netT NetStackT
	switch fields[0] {
	case "host", "tun":
		netT = NetStackT(fields[0])
	default:
		return UnknownNetStackT, Addr{}, fmt.Errorf("unknown network stack: %q", fields[0])
	}

	proto := ProtocolT(fields[1])
	addrStr := fields[2]

	addr, err := strToAddr(proto, addrStr)
	if err != nil {
		return UnknownNetStackT, Addr{}, fmt.Errorf("failed to parse address %q - %w",
			addrStr, err)
	}

	return netT, addr, nil
}

type ForwarderSpec struct {
	Name           string
	ListenNet      NetStackT
	ListenAddr     Addr
	DialNet        NetStackT
	DialAddr       Addr
	OptDialTimeout time.Duration
}

func (o ForwarderSpec) String() string {
	return string(o.ListenNet) + " " +
		string(o.ListenAddr.Protocol()) + " " +
		o.ListenAddr.String() + " " +
		"-> " +
		string(o.DialNet) + " " +
		string(o.DialAddr.Protocol()) + " " +
		o.DialAddr.String()
}

type NetStackT string

const (
	UnknownNetStackT NetStackT = ""
	HostNetStackT    NetStackT = "host"
	TunNetStackT     NetStackT = "tun"
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
	host      *Addr
	ourWgAddr string
	wgConfig  *wgconfig.Config
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	if args.host.Host() == "@us" {
		args.host.SetHost(args.ourWgAddr)
		return nil
	}

	if strings.HasPrefix(args.host.Host(), "@") {
		name := args.host.Host()
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

		args.host.SetHost(addr.String())

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
