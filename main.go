// wgu (WireGuard Userspace, pronounced "woo-goo" or "w-g-u") is a fork
// of Jonathan Giannuzzi's wgfwd. wgu creates WireGuard tunnels without
// superuser privileges. Connections to network services are managed
// using forwarders. Each forwarder tells wgu where to listen for
// incoming connections and where to forward connections to.
//
// Think of wgu like SSH port forwarding, but with WireGuard instead of SSH.
//
// If you would like a graphical version of wgu, check out Seung Kang's wgui.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gitlab.com/stephen-fox/wgu/config"
	"gitlab.com/stephen-fox/wgu/forwarding"
	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"gitlab.com/stephen-fox/wgu/internal/wgdns"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"gitlab.com/stephen-fox/wgu/internal/wgtap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	version = "v0.0.13"

	appName = "wgu"

	usage = `SYNOPSIS
  ` + appName + ` ` + helpCmd + `
  ` + appName + ` ` + versionCmd + `
  ` + appName + ` ` + genconfigCmd + ` [dir]
  ` + appName + ` ` + pubkeyCmd + ` < private-key-file
  ` + appName + ` ` + pubkeyFromConfigCmd + ` [config-file] [< config-file]
  ` + appName + ` ` + pubkeyAddrCmd + ` < public-key-file
  ` + appName + ` ` + upCmd + ` [options] [config-file]

DESCRIPTION
  wgu (WireGuard Userspace, pronounced "woo-goo" or "w-g-u") is a fork
  of Jonathan Giannuzzi's wgfwd. wgu creates WireGuard tunnels without
  superuser privileges. Connections to network services are managed
  using forwarders. Each forwarder tells wgu where to listen for
  incoming connections and where to forward connections to.

  For detailed documentation and configuration examples, please execute:
    ` + appName + ` ` + helpCmd + `

  To generate a basic configuration file and private key, please execute:
    ` + appName + ` ` + genconfigCmd + `

OPTIONS
`

	helpLong = `COMMANDS

  ` + helpCmd + `             - Display configuration syntax help and examples
  ` + versionCmd + `          - Display version number and exit
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

    $ wgu ` + genconfigCmd + `
    z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=

  ` + appName + ` is configured using an INI configuration file in a similar manner
  to WireGuard. Additional options can be specified using command line
  arguments.

  General application settings can be specified in the configuration file
  in the ` + config.AppOptionsConfigSection + ` section. For example:

    [` + config.AppOptionsConfigSection + `]
    ExampleParameter = some value

  The following general application parameters are available:

    - ` + config.AutoAddrPlanningModeConfigOpt + ` - Enables automatic address planning mode
      if set to "true". Defaults to "false" if unspecified. In this mode,
      each peer's virtual WireGuard address is generated from its public key
      in the form of an IPv6 address. This mode makes it easier to construct
      simple WireGuard topologies without planning out IP address allocations
      or needing to know each peer's WireGuard address. It is unnecessary to
      specify the 'Address' configuration parameter for other peers in this
      mode. Refer to the AUTOMATIC ADDRESS PLANNING MODE EXAMPLE section for
      an example.
    - ` + config.LogLevelConfigOpt + ` - Set the log level according to the values that can be
      specified on the command line. Can be: 'error', 'info', or 'debug'

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

FORWARDER VARIABLES
  The "address" values can be replaced with variables that are
  expanded to the corresponding address:

    @us
      The first IP address of our virtual WireGuard interface

    @usN
      The nth IP address of our virtual WireGuard interface.
      For example, "@us1" would expand to the second address
      of the network interface

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

    $ wgu ` + upCmd + ` peer0/` + defConfigFileName + `
    $ wgu ` + upCmd + ` peer1/` + defConfigFileName + `

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

    [` + config.AppOptionsConfigSection + `]
    ` + config.AutoAddrPlanningModeConfigOpt + ` = true

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

    [` + config.AppOptionsConfigSection + `]
    ` + config.AutoAddrPlanningModeConfigOpt + ` = true

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

    $ wgu ` + upCmd + ` peer0/` + defConfigFileName + `
    $ wgu ` + upCmd + ` peer1/` + defConfigFileName + `

  Finally, in two different shells, test the tunnel using nc:

    $ nc -l 2000
    $ echo 'hello' | nc 127.0.0.1 3000
`

	helpCmd             = "help"
	versionCmd          = "version"
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

	defConfigFileName = appName + ".conf"
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
	case versionCmd:
		os.Stdout.WriteString(version + "\n")
	case genconfigCmd:
		return genConfig()
	case genkeyCmd:
		privateKey, err := wgkeys.NewNoisePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key - %w", err)
		}

		os.Stdout.WriteString(wgkeys.NoisePrivateKeyToDisplayString(privateKey) + "\n")
	case pubkeyCmd:
		privateKeyB64, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		privateKey, err := wgkeys.NoisePrivateKeyFromBase64(string(privateKeyB64))
		if err != nil {
			return fmt.Errorf("failed to parse private key - %w", err)
		}

		os.Stdout.WriteString(wgkeys.NoisePrivateKeyToPublicDisplayString(privateKey) + "\n")
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
				return fmt.Errorf("failed to open default config file '%s' - %w",
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

		os.Stdout.WriteString(wgkeys.NoisePublicKeyToDisplayString(
			cfg.Interface.PublicKey) + "\n")
	case pubkeyAddrCmd:
		publicKeyRaw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		publicKey, err := wgkeys.NoisePublicKeyFromBase64(string(publicKeyRaw))
		if err != nil {
			return err
		}

		addr, err := config.PublicKeyToV6Addr(publicKey[:])
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
	flagSet := flag.NewFlagSet(genconfigCmd, flag.ExitOnError)

	help := flagSet.Bool(
		helpArg,
		false,
		"Display this information")

	configFileName := flagSet.String(
		"n",
		defConfigFileName,
		"The config file name to use")

	// Disable annoying flag.PrintDefaults on flag parse error.
	flagSet.Usage = func() {}

	flagSet.Parse(os.Args[2:])

	if *help {
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if strings.ContainsAny(*configFileName, "\\/") {
		return fmt.Errorf("the specified config file name contains one or more path separators: '%s'",
			*configFileName)
	}

	var configDirPath string
	var privateKeyPathInConfig string
	const privateKeyFileName = "private-key"
	var err error

	switch flagSet.NArg() {
	case 0:
		configDirPath, err = defConfigDirPath()
		if err != nil {
			return err
		}

		privateKeyPathInConfig = "~/." + appName + "/" + privateKeyFileName
	case 1:
		configDirPath, err = filepath.Abs(flagSet.Arg(0))
		if err != nil {
			return err
		}

		privateKeyPathInConfig = filepath.Join(configDirPath, privateKeyFileName)
	default:
		return errors.New("please specify only one config file path")
	}

	err = os.MkdirAll(configDirPath, 0o700)
	if err != nil {
		return err
	}

	err = os.Chmod(configDirPath, 0o700)
	if err != nil {
		return err
	}

	configFilePath := filepath.Join(configDirPath, *configFileName)

	_, configStatErr := os.Stat(configFilePath)
	if configStatErr == nil {
		return fmt.Errorf("a configuration file already exists at: '%s'",
			configFilePath)
	}

	err = os.WriteFile(configFilePath, []byte(`[`+config.AppOptionsConfigSection+`]
# `+config.AutoAddrPlanningModeConfigOpt+` = true

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

	privateKeyFilePath := filepath.Join(configDirPath, privateKeyFileName)

	_, statPrivateKeyErr := os.Stat(privateKeyFilePath)

	var privateKey *device.NoisePrivateKey

	if statPrivateKeyErr == nil {
		privateKey, err = wgkeys.NoisePrivateKeyFromFilePath(privateKeyFilePath)
		if err != nil {
			return fmt.Errorf("failed to parse existing private key - %w", err)
		}
	} else {
		privateKey, err = wgkeys.NewNoisePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key - %w", err)
		}

		err = wgkeys.WriteNoisePrivateKeyToFile(privateKey, privateKeyFilePath)
		if err != nil {
			return fmt.Errorf("failed to write new private key file - %w", err)
		}
	}

	os.Stdout.WriteString(wgkeys.NoisePrivateKeyToPublicDisplayString(privateKey) + "\n")

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

	appCfg, err := config.Parse(configFD)
	_ = configFD.Close()
	if err != nil {
		return fmt.Errorf("failed to parse config file - %w", err)
	}

	if appCfg.OptLogLevel != "" {
		cliLogLevelSet := false

		flagSet.Visit(func(f *flag.Flag) {
			if f.Name == logLevelArg {
				cliLogLevelSet = true
			}
		})

		if !cliLogLevelSet {
			*logLevelString = appCfg.OptLogLevel
		}
	}

	var loggerInfo *log.Logger
	var loggerErr *log.Logger
	var loggerDebug *log.Logger

	switch *logLevelString {
	case "debug":
		loggerDebug = log.New(log.Writer(), "[debug] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "info":
		loggerInfo = log.New(log.Writer(), "[info] ", log.Flags()|log.Lmsgprefix)
		fallthrough
	case "error":
		loggerErr = log.New(log.Writer(), "[error] ", log.Flags()|log.Lmsgprefix)
	default:
		return fmt.Errorf("unknown log level: %q", *logLevelString)
	}

	if loggerInfo != nil && appCfg.IsAutoAddrPlanningMode {
		loggerInfo.Println("automatic address planning mode is enabled")
	}

	if *writeConfig {
		_, err = os.Stdout.WriteString(appCfg.Wireguard.WireGuardString())
		return err
	}

	if *writeIpcConfig {
		str, err := appCfg.Wireguard.IPCConfig()
		if err != nil {
			return fmt.Errorf("failed to convert config to ipc format - %w", err)
		}

		_, err = os.Stdout.WriteString(str)
		return err
	}

	ipcConfig, err := appCfg.Wireguard.IPCConfigWithoutDnsPeers()
	if err != nil {
		return fmt.Errorf("failed to convert config to wg ipc format - %w", err)
	}

	wgIfaceAddrs := make([]netip.Addr, len(appCfg.Wireguard.Interface.Addresses))
	var wgIfaceAddrsSummary string

	for i, addrPrefix := range appCfg.Wireguard.Interface.Addresses {
		addr := addrPrefix.Addr()
		wgIfaceAddrs[i] = addr

		if wgIfaceAddrsSummary != "" {
			wgIfaceAddrsSummary += ", "
		}

		wgIfaceAddrsSummary += fmt.Sprintf("%s (%d)", addr.String(), i)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		wgIfaceAddrs,
		[]netip.Addr{},
		*appCfg.Wireguard.Interface.MTU,
	)
	if err != nil {
		return fmt.Errorf("failed to create wg tunnel interface - %w", err)
	}

	if appCfg.OptTap.Address != "" {
		ctx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()

		tun, err = wgtap.Setup(ctx, tun, appCfg.OptTap)
		if err != nil {
			return fmt.Errorf("failed to create tapped wg tun device - %w", err)
		}

		if loggerInfo != nil {
			loggerInfo.Printf("[warn] added tap to wg tun device at: %q %q",
				appCfg.OptTap.Protocol, appCfg.OptTap.Address)
		}
	}

	wgDeviceLogger := &device.Logger{
		Errorf:   func(format string, args ...any) {},
		Verbosef: func(format string, args ...any) {},
	}

	if loggerErr != nil {
		wgDeviceLogger.Errorf = loggerErr.Printf
	}

	if loggerDebug != nil {
		wgDeviceLogger.Verbosef = loggerDebug.Printf
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), wgDeviceLogger)

	err = dev.IpcSet(ipcConfig)
	if err != nil {
		return fmt.Errorf("failed to set wg device configuration - %w", err)
	}

	err = dev.Up()
	if err != nil {
		return fmt.Errorf("failed to bring up wg device - %w", err)
	}
	defer dev.Down()

	if loggerInfo != nil {
		if len(wgIfaceAddrs) == 1 {
			loggerInfo.Printf("wg device up - address: %s", wgIfaceAddrsSummary)
		} else {
			loggerInfo.Printf("wg device up - addresses: %s", wgIfaceAddrsSummary)
		}
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	defer cancelFn()

	dnsMonitorErrs := make(chan error, 1)
	wgdns.MonitorPeers(ctx, appCfg.Wireguard.Peers, dev, dnsMonitorErrs, loggerInfo)

	waitGroup, err := forwarding.StartForwarders(ctx, forwarding.StartForwardersArgs{
		TunNet:      tnet,
		StrsToSpecs: appCfg.Forwarders,
		Loggers: forwarding.Loggers{
			Info:  loggerInfo,
			Err:   loggerErr,
			Debug: loggerDebug,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start network forwarders - %w", err)
	}

	if *child {
		os.Stdout.WriteString("ready\n")

		go func() {
			// read will fail if the parent process has exited, we use this as
			// a dead person's switch to ensure that the process exits
			os.Stdin.Read(make([]byte, 1))
			os.Exit(1)
		}()
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-dnsMonitorErrs:
		err = fmt.Errorf("failed to monitor peer's dns changes - %w", err)

		cancelFn()
	}

	onWaitGroupDone := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(onWaitGroupDone)
	}()

	select {
	case <-time.After(time.Second):
	case <-onWaitGroupDone:
	}

	return err
}
