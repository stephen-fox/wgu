package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jgiannuzzi/wgfwd/internal/netstack"
	"github.com/jgiannuzzi/wgfwd/internal/ossignals"
	"github.com/jgiannuzzi/wgfwd/internal/wgu"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	appName = "wgu"

	usage = appName + `

SYNOPSIS

DESCRIPTION

FORWARDING SPECIFICATION
  Port forwards can be specified using the following specification format:

    listen-address:port->dial-address:port

  For example, the following specification forwards connections to
  127.0.0.1:22 on the host machine to a WireGuard peer who has the
  virtual address of 10.0.0.1:

    127.0.0.1:22->10.0.0.1:22

  The addresses are checked against the IP address of the virtual WireGuard
  interface and a series of magic strings.

  The "listen-address" and "dial-address" values can be replaced with
  magic strings that are expanded to the corresponding address.
  Note: Strings marked with "*" are only expanded in automatic address
  planning mode.

    us
      The first IP address of the virtual WireGuard interface

    peerN*
      The address of peer number N as they appear in the WireGuard
      configuration file. For example, "peer0" would be the address
      of the first peer in the WireGuard configuration file

    <pub-base64>*
      The address of the peer with the corresponding base64-encoded
      public key

OPTIONS
`
)

var (
	udpTimeout time.Duration

	loggerInfo  = log.New(io.Discard, "", 0)
	loggerErr   = log.New(io.Discard, "", 0)
	loggerDebug = log.New(io.Discard, "", 0)
)

func main() {
	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	// Disable annoying flag.PrintDefaults on flag parse error.
	flag.Usage = func() {}

	help := flag.Bool("h", false, "Display this information")

	forwards := make(map[string]*forwardConfig)

	tcpForwards := forwardFlag{
		transport:     "tcp",
		strsToConfigs: forwards,
	}
	flag.Var(&tcpForwards, "tcp", "TCP port forward `specification` (see -h for details)")

	udpForwards := forwardFlag{
		transport:     "udp",
		strsToConfigs: forwards,
	}
	flag.Var(&udpForwards, "udp", "UDP port forward `specification` (see -h for details)")

	wgConfig := flag.String("wg-config", "", "Wireguard config file")

	logLevelString := flag.String("log-level", "info", "Log level")

	flag.DurationVar(&udpTimeout, "udp-timeout", 2*time.Minute, "UDP timeout")

	autoAddrPlanning := flag.Bool("auto", false, "")

	writeWgConfig := flag.Bool("write-wg-config", false, "")

	writeWgIpcConfig := flag.Bool("write-wg-ipc-config", false, "")

	flag.Parse()

	if *help {
		flag.CommandLine.Output().Write([]byte(usage))
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "genkey":
		privateKey, err := wgu.NewNoisePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key - %w", err)
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(privateKey[:]) + "\n")

		return nil
	case "pubkey":
		privateKeyB64, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		privateKey, err := wgu.NoisePrivateKeyFromBase64(string(privateKeyB64))
		if err != nil {
			return fmt.Errorf("failed to parse private key - %w", err)
		}

		pub := wgu.NoisePublicKeyFromPrivate(privateKey)

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(pub[:]) + "\n")

		return nil
	case "pubkey-from-config":
		cfg, err := parseWgConfig(os.Stdin)
		if err != nil {
			return err
		}

		pubKey, err := cfg.ourPublicKey()
		if err != nil {
			return err
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(pubKey) + "\n")

		return nil
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

	var wgConf *os.File
	if *wgConfig == "-" {
		wgConf = os.Stdin
	} else {
		var err error
		wgConf, err = os.Open(*wgConfig)
		if err != nil {
			return err
		}
	}

	// TODO: Support reading wg private key from a file.
	cfg, err := parseWgConfig(wgConf)
	_ = wgConf.Close()
	if err != nil {
		return fmt.Errorf("failed to parse wireguard config file - %w", err)
	}

	var optAutoPeers []autoPeer
	if *autoAddrPlanning {
		optAutoPeers, err = doAutoAddrPlanning(cfg, forwards)
		if err != nil {
			return fmt.Errorf("failed to do automatic address planning - %w", err)
		}
	}

	if *writeWgConfig {
		_, err = os.Stdout.WriteString(cfg.String())
		return err
	}

	if *writeWgIpcConfig {
		_, err = os.Stdout.WriteString(cfg.IPCConfig())
		return err
	}

	ourAddr, err := cfg.ourAddr()
	if err != nil {
		return fmt.Errorf("failed to get our internal address from config - %w", err)
	}

	ourAddrStr := ourAddr.Addr().String()
	for _, forward := range forwards {
		_ = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:               &forward.lAddr.addr,
			ourIntAddr:         ourAddrStr,
			isAutoAddrPlanning: *autoAddrPlanning,
			wgConfig:           cfg,
			optAutoPeers:       optAutoPeers,
		})

		_ = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:               &forward.rAddr.addr,
			ourIntAddr:         ourAddrStr,
			isAutoAddrPlanning: *autoAddrPlanning,
			wgConfig:           cfg,
			optAutoPeers:       optAutoPeers,
		})
	}

	// TODO: Add flag.
	ourMtu, err := cfg.ourMtuOr(1420)
	if err != nil {
		return fmt.Errorf("failed to read mtu from config - %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ourAddr.Addr()},
		[]netip.Addr{},
		ourMtu,
	)
	if err != nil {
		return fmt.Errorf("Error creating tunnel interface: %s", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: loggerDebug.Printf,
		Errorf:   loggerErr.Printf,
	})

	err = dev.IpcSet(cfg.IPCConfig())
	if err != nil {
		return fmt.Errorf("Error setting device configuration: %s", err)
	}

	err = dev.Up()
	if err != nil {
		return fmt.Errorf("Error bringing up device: %s", err)
	}
	defer dev.Down()

	loggerInfo.Println("wg device up")

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var localNetOp = &localNetOp{}
	var tunnelNetOp = &tunnelNetOp{tnet}

	for fwdStr, fwd := range forwards {
		lAddr, err := fwd.lAddr.toAddrPort()
		if err != nil {
			return fmt.Errorf("failed to parse listen addr port for %q - %w",
				fwdStr, err)
		}

		rAddr, err := fwd.rAddr.toAddrPort()
		if err != nil {
			return fmt.Errorf("failed to parse dial addr port for %q - %w",
				fwdStr, err)
		}

		var lNet netOp
		var rNet netOp

		if fwd.lAddr.addr == ourAddr.Addr().String() {
			lNet = tunnelNetOp
			rNet = localNetOp
		} else {
			lNet = localNetOp
			rNet = tunnelNetOp
		}

		err = forward(ctx, &wg, fwd.proto, lNet, lAddr.String(), rNet, rAddr.String())
		if err != nil {
			return fmt.Errorf("error forwarding %+v: %s", fwd, err)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, ossignals.QuitSignals()...)
	s := <-sigChan

	return fmt.Errorf("received signal: %s", s.String())
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

func forward(ctx context.Context, wg *sync.WaitGroup, proto string, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	switch proto {
	case "tcp":
		return forwardTCP(ctx, wg, lNet, lAddr, rNet, rAddr)
	case "udp":
		return forwardUDP(ctx, wg, lNet, lAddr, rNet, rAddr)
	default:
		return fmt.Errorf("unknown protocol: %s", proto)
	}
}

func forwardTCP(ctx context.Context, wg *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	wg.Add(1)

	listener, err := lNet.Listen(ctx, "tcp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		loggerInfo.Printf("Stopping TCP forwarder for %s -> %s", lAddr, rAddr)
		listener.Close()
	}()

	go func() {
		defer wg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				loggerErr.Printf("error accepting tcp connection: %s", err)
				return
			}
			loggerDebug.Printf("accepted tcp connection from %s for %s", conn.RemoteAddr(), lAddr)

			remote, err := rNet.Dial(ctx, "tcp", rAddr)
			if err != nil {
				loggerErr.Printf("error connecting to remote TCP: %s", err)
				conn.Close()
				continue
			}
			loggerDebug.Printf("tcp connection forwarded from %s to %s", conn.RemoteAddr(), rAddr)

			var iwg sync.WaitGroup
			go func() {
				defer iwg.Done()
				defer remote.Close()
				defer conn.Close()
				_, err := io.Copy(remote, conn)
				if err != nil && err != io.EOF {
					loggerDebug.Printf("error copying from %s: %s", conn.RemoteAddr(), err)
				}
			}()
			go func() {
				defer iwg.Done()
				defer remote.Close()
				defer conn.Close()
				_, err := io.Copy(conn, remote)
				if err != nil {
					loggerDebug.Printf("error copying to %s: %s", conn.RemoteAddr(), err)
				}
			}()
			iwg.Add(2)
			go func() {
				iwg.Wait()
				loggerDebug.Printf("connection from %s closed", conn.RemoteAddr())
			}()
		}
	}()

	loggerInfo.Printf("tcp forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

func forwardUDP(ctx context.Context, wg *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	wg.Add(1)

	remoteConns := make(map[string]net.Conn)

	localConn, err := lNet.ListenPacket(ctx, "udp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		loggerInfo.Printf("stopping UDP forwarder for %s -> %s", lAddr, rAddr)
		for _, c := range remoteConns {
			c.Close()
		}
		localConn.Close()
	}()

	buffer := make([]byte, 1392)
	go func() {
		defer wg.Done()

		for {
			n, addr, err := localConn.ReadFrom(buffer)
			if err != nil {
				loggerDebug.Printf("error reading from UDP socket: %#v", err)
				return
			}

			loggerDebug.Printf("received %d bytes from %s for %s", n, addr, lAddr)

			remote, ok := remoteConns[addr.String()]
			if !ok {
				remote, err = rNet.Dial(ctx, "udp", rAddr)
				if err != nil {
					loggerErr.Printf("error connecting to remote UDP: %s", err)
					continue
				}

				remoteConns[addr.String()] = remote

				go func() {
					defer delete(remoteConns, addr.String())

					buffer := make([]byte, 1392)
					for {
						remote.SetReadDeadline(time.Now().Add(udpTimeout))
						n, err = remote.Read(buffer)
						if err != nil {
							loggerDebug.Printf("error reading from UDP socket: %s", err)
							return
						}

						loggerDebug.Printf("received %d bytes from %s for %s", n, rAddr, remote.LocalAddr())
						_, err = localConn.WriteTo(buffer[:n], addr)
						if err != nil {
							loggerDebug.Printf("error writing to local: %s", err)
							return
						}

						loggerDebug.Printf("forwarded %d bytes from %s to %s", n, rAddr, addr)
					}
				}()
			}

			n, err = remote.Write(buffer[:n])
			if err != nil {
				loggerErr.Printf("error writing to remote UDP from %s: %s", addr, err)
				continue
			}

			loggerDebug.Printf("forwarded %d bytes from %s to %s", n, addr, rAddr)
		}
	}()

	loggerInfo.Printf("udp forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

type addrPort struct {
	addr string
	port uint16
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
	components := strings.Split(fwd, "->")

	numArrows := len(components)
	if numArrows <= 1 {
		return nil, errors.New("missing '->'")
	}

	if numArrows > 2 {
		return nil, errors.New("contains more than one '->'")
	}

	listenAddr, err := strToAddrAndPort(components[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address %q - %w",
			components[0], err)
	}

	dialAddr, err := strToAddrAndPort(components[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse dial address %q - %w",
			components[1], err)
	}

	return &forwardConfig{
		proto: transport,
		lAddr: listenAddr,
		rAddr: dialAddr,
	}, nil
}

type forwardConfig struct {
	proto string
	lAddr addrPort
	rAddr addrPort
}

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

func parseWgConfig(r io.Reader) (*basicWGConfig, error) {
	scanner := bufio.NewScanner(r)

	line := 0

	var sections []*wgSection

	for scanner.Scan() {
		line++

		withoutSpaces := bytes.TrimSpace(scanner.Bytes())

		if len(withoutSpaces) == 0 || withoutSpaces[0] == '#' {
			continue
		}

		if withoutSpaces[0] == '[' {
			name, err := parseConfigSectionLine(withoutSpaces)
			if err != nil {
				return nil, fmt.Errorf("line %d - failed to parse section header - %w", line, err)
			}

			sections = append(sections, &wgSection{name: name})

			continue
		}

		if len(sections) == 0 {
			return nil, fmt.Errorf("line %d - parameter appears outside of a section", line)
		}

		paramName, paramValue, err := parseConfigParamLine(withoutSpaces)
		if err != nil {
			return nil, fmt.Errorf("line %d - failed to parse line - %w", line, err)
		}

		currentSection := sections[len(sections)-1]
		currentSection.params = append(*&currentSection.params, wgParam{
			name:  paramName,
			value: paramValue,
		})
	}

	err := scanner.Err()
	if err != nil {
		return nil, err
	}

	return &basicWGConfig{
		sections: sections,
	}, nil
}

type basicWGConfig struct {
	sections []*wgSection
}

func (o *basicWGConfig) String() string {
	buf := bytes.NewBuffer(nil)

	for i, section := range o.sections {
		section.string(buf)

		if len(o.sections) > 1 && i < len(o.sections)-1 {
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

func (o *basicWGConfig) IPCConfig() string {
	buf := bytes.NewBuffer(nil)

	for _, section := range o.sections {
		section.ipcString(buf)
	}

	return buf.String()
}

func (o *basicWGConfig) ourPublicKey() ([]byte, error) {
	privateKeyB64, err := o.paramInSection("PrivateKey", "Interface")
	if err != nil {
		return nil, err
	}

	privateKey, err := wgu.NoisePrivateKeyFromBase64(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard private key - %w", err)
	}

	pub := wgu.NoisePublicKeyFromPrivate(privateKey)

	return pub[:], nil
}

func (o *basicWGConfig) ourAddr() (netip.Prefix, error) {
	addrStr, err := o.paramInSection("Address", "Interface")
	if err != nil {
		return netip.Prefix{}, err
	}

	ourAddr, err := netip.ParsePrefix(addrStr)
	if err != nil {
		return netip.Prefix{}, err
	}

	return ourAddr, nil
}

func (o *basicWGConfig) ourMtuOr(defMtu int) (int, error) {
	mtuStr, optErr := o.paramInSection("MTU", "Interface")
	if optErr != nil {
		return defMtu, nil
	}

	mtu, err := strconv.Atoi(mtuStr)
	if err != nil {
		return 0, err
	}

	return mtu, nil
}

var errStopIterating = errors.New("stop iterating over sections")

func (o *basicWGConfig) iterateSections(sectionName string, fn func(*wgSection) error) error {
	var foundOneSection bool

	for _, section := range o.sections {
		if section.name == sectionName {
			foundOneSection = true

			err := fn(section)
			if err != nil {
				if errors.Is(err, errStopIterating) {
					return nil
				}

				return err
			}
		}
	}

	if !foundOneSection {
		return fmt.Errorf("failed to find section: %q", sectionName)
	}

	return nil
}

func (o *basicWGConfig) paramInSection(paramName string, sectionName string) (string, error) {
	var foundOneSection bool

	for _, section := range o.sections {
		if section.name == sectionName {
			foundOneSection = true

			for _, param := range section.params {
				if param.name == paramName {
					return param.value, nil
				}
			}
		}
	}

	if !foundOneSection {
		return "", fmt.Errorf("failed to find section: %q", sectionName)
	}

	return "", fmt.Errorf("failed to find %q in section %q", paramName, sectionName)
}

type wgSection struct {
	name   string
	params []wgParam
}

func (o *wgSection) string(b *bytes.Buffer) {
	b.WriteString("[" + o.name + "]\n")
	for _, param := range o.params {
		b.WriteString(param.name)
		b.WriteString(" = ")
		b.WriteString(param.value)
		b.WriteString("\n")
	}
}

func (o *wgSection) ipcString(b *bytes.Buffer) error {
	for _, param := range o.params {
		var ipcParamName string
		var optIpcValue string

		switch o.name {
		case "Interface":
			switch param.name {
			case "PrivateKey":
				ipcParamName = "private_key"

				raw, err := base64.StdEncoding.DecodeString(param.value)
				if err != nil {
					return err
				}

				optIpcValue = hex.EncodeToString(raw)
			case "Address":
				// Not needed for ipc.
				continue
			case "MTU":
				ipcParamName = "mtu"
			case "ListenPort":
				ipcParamName = "listen_port"
			}
		case "Peer":
			switch param.name {
			case "Endpoint":
				ipcParamName = "endpoint"
			case "PublicKey":
				ipcParamName = "public_key"

				raw, err := base64.StdEncoding.DecodeString(param.value)
				if err != nil {
					return err
				}

				optIpcValue = hex.EncodeToString(raw)
			case "AllowedIPs":
				ipcParamName = "allowed_ip"
			case "PersistentKeepalive":
				ipcParamName = "persistent_keepalive_interval"
			}
		default:
			continue
		}

		if ipcParamName == "" {
			return fmt.Errorf("no known ipc param for %q in section %q",
				param, o.name)
		}

		b.WriteString(ipcParamName)
		b.WriteString("=")
		if optIpcValue == "" {
			b.WriteString(param.value)
		} else {
			b.WriteString(optIpcValue)
		}
		b.WriteString("\n")
	}

	return nil
}

func (o *wgSection) iterateParams(paramName string, fn func(*wgParam) error) error {
	var foundOne bool

	for _, param := range o.params {
		if param.name == paramName {
			err := fn(&param)
			if err != nil {
				if errors.Is(err, errStopIterating) {
					return nil
				}

				return err
			}
		}
	}

	if !foundOne {
		return fmt.Errorf("failed to find param: %q", paramName)
	}

	return nil
}

func (o *wgSection) firstParamValue(paramName string) (string, error) {
	for _, param := range o.params {
		if param.name == paramName {
			return param.value, nil
		}
	}

	return "", fmt.Errorf("failed to find param: %q", paramName)
}

func (o *wgSection) addOrSetFirstParam(paramName string, value string) error {
	for i := range o.params {
		if o.params[i].name == paramName {
			o.params[i].value = value
			return nil
		}
	}

	o.params = append(o.params, wgParam{
		name:  paramName,
		value: value,
	})

	return nil
}

type wgParam struct {
	name  string
	value string
}

func parseConfigSectionLine(line []byte) (string, error) {
	if len(line) < 2 {
		return "", errors.New("invalid section header length")
	}

	if line[0] != '[' {
		return "", errors.New("section header does not start with '['")
	}

	if line[len(line)-1] != ']' {
		return "", errors.New("section header does not end with ']'")
	}

	line = bytes.TrimSpace(line[1 : len(line)-1])

	if len(line) == 0 {
		return "", errors.New("section name is empty")
	}

	return string(line), nil
}

func parseConfigParamLine(line []byte) (string, string, error) {
	if !bytes.Contains(line, []byte{'='}) {
		return "", "", errors.New("line is missing '='")
	}

	parts := bytes.SplitN(line, []byte("="), 2)

	switch len(parts) {
	case 0:
		return "", "", errors.New("line is empty")
	case 1:
		return "", "", errors.New("line is missing value")
	}

	param := bytes.TrimSpace(parts[0])
	value := bytes.TrimSpace(parts[1])

	switch {
	case len(param) == 0:
		return "", "", errors.New("parameter name is empty")
	case len(value) == 0:
		return "", "", errors.New("parameter value is empty")
	}

	return string(param), string(value), nil
}

func doAutoAddrPlanning(cfg *basicWGConfig, strsToConfigs map[string]*forwardConfig) ([]autoPeer, error) {
	ourPub, err := cfg.ourPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get our public key from config - %w", err)
	}

	ourIntAddr, ok := netip.AddrFromSlice(ourPub[len(ourPub)-16:])
	if !ok {
		return nil, fmt.Errorf("failed to convert our public key to v6 addr: %x", ourPub)
	}

	err = cfg.iterateSections("Interface", func(s *wgSection) error {
		return s.addOrSetFirstParam("Address", ourIntAddr.String()+"/64")
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set our internal ip to %q - %w",
			ourIntAddr.String(), err)
	}

	var peers []autoPeer

	err = cfg.iterateSections("Peer", func(s *wgSection) error {
		pkB64, err := s.firstParamValue("PublicKey")
		if err != nil {
			return err
		}

		pub, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			return err
		}

		addr, ok := netip.AddrFromSlice(pub[len(pub)-16:])
		if !ok {
			return fmt.Errorf("failed to convert peer public key to v6 addr: %q", pkB64)
		}

		err = s.addOrSetFirstParam("AllowedIPs", addr.String()+"/64")
		if err != nil {
			return fmt.Errorf("failed to add or set AllowedIPs for peer %q - %w",
				pkB64, err)
		}

		peers = append(peers, autoPeer{
			publicKey: pub,
			addr:      addr,
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to automatically set peer addresses - %w", err)
	}

	return peers, nil
}

type autoPeer struct {
	publicKey []byte
	addr      netip.Addr
}

type replaceWgAddrShortcutsArgs struct {
	addr               *string
	ourIntAddr         string
	isAutoAddrPlanning bool
	wgConfig           *basicWGConfig
	optAutoPeers       []autoPeer
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	if *args.addr == "us" {
		*args.addr = args.ourIntAddr
		return nil
	}

	if !args.isAutoAddrPlanning {
		return nil
	}

	nPeers := len(args.optAutoPeers)

	if n, ok := isPeerNStr(*args.addr); ok {
		if n < nPeers {
			*args.addr = args.optAutoPeers[n].addr.String()
			return nil
		}
	}

	if publicKey, ok := isWgPublicKeyStr(*args.addr, args.wgConfig); ok {
		for _, peer := range args.optAutoPeers {
			if bytes.Equal(publicKey, peer.publicKey) {
				*args.addr = peer.addr.String()
				return nil
			}
		}
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

func isWgPublicKeyStr(str string, cfg *basicWGConfig) ([]byte, bool) {
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

	err = cfg.iterateSections("Peer", func(section *wgSection) error {
		err := section.iterateParams("PublicKey", func(param *wgParam) error {
			if param.value == str {
				return errStopIterating
			}

			return errors.New("nope")
		})
		if err != nil {
			return err
		}

		return errStopIterating
	})
	if err != nil {
		return nil, false
	}

	return pub, true
}
