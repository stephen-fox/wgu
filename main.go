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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	appName       = "wgu"
	configPathArg = "config"

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
	log.SetFlags(0)

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

	configPath := flag.String(configPathArg, "", "Configuration file `path`")

	logLevelString := flag.String("log-level", "info", "Log level")

	flag.DurationVar(&udpTimeout, "udp-timeout", 2*time.Minute, "UDP timeout")

	autoAddrPlanning := flag.Bool("auto", false, "")

	writeConfig := flag.Bool("write-config", false, "")

	writeIpcConfig := flag.Bool("write-ipc-config", false, "")

	noTimeStamps := flag.Bool("no-log-timestamps", false, "Disable logging timestamps")

	flag.Parse()

	if *help {
		flag.CommandLine.Output().Write([]byte(usage))
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "genkey":
		privateKey, err := wgkeys.NewNoisePrivateKey()
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

		privateKey, err := wgkeys.NoisePrivateKeyFromBase64(string(privateKeyB64))
		if err != nil {
			return fmt.Errorf("failed to parse private key - %w", err)
		}

		pub := wgkeys.NoisePublicKeyFromPrivate(privateKey)

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(pub[:]) + "\n")

		return nil
	case "pubkey-from-config":
		cfg, err := wgconfig.Parse(os.Stdin)
		if err != nil {
			return err
		}

		os.Stdout.WriteString(base64.StdEncoding.EncodeToString(
			cfg.Interface.PublicKey[:]) + "\n")

		return nil
	}

	if !*noTimeStamps {
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

	var optAutoPeers []autoPeer
	if *autoAddrPlanning {
		optAutoPeers, err = doAutoAddrPlanning(cfg)
		if err != nil {
			return fmt.Errorf("failed to do automatic address planning - %w", err)
		}
	}

	if *writeConfig {
		//_, err = os.Stdout.WriteString(cfg.String())
		//return err
		return errors.New("TODO")
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
			addr:               &forward.lAddr.addr,
			ourWgAddr:          ourWgAddrStr,
			isAutoAddrPlanning: *autoAddrPlanning,
			optAutoPeers:       optAutoPeers,
		})
		if err != nil {
			return fmt.Errorf("failed to replace listen addr for %q - %w",
				str, err)
		}

		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			addr:               &forward.rAddr.addr,
			ourWgAddr:          ourWgAddrStr,
			isAutoAddrPlanning: *autoAddrPlanning,
			optAutoPeers:       optAutoPeers,
		})
		if err != nil {
			return fmt.Errorf("failed to replace dial addr for %q - %w",
				str, err)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to read mtu from config - %w", err)
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	defer cancelFn()

	err = peerDNSResolution(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to resolve peer endpoint hostnames - %w", err)
	}

	ipcConfig, err := cfg.IPCConfig()
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

	var waitGroup sync.WaitGroup
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

		lNet := netOpForAddr(netOpForAddrArgs{
			addr:         lAddr,
			ourWgAddr:    cfg.Interface.Address.Addr(),
			localNetOp:   localNetOp,
			tunnelNetOp:  tunnelNetOp,
			optAutoPeers: optAutoPeers,
		})

		rNet := netOpForAddr(netOpForAddrArgs{
			addr:         rAddr,
			ourWgAddr:    cfg.Interface.Address.Addr(),
			localNetOp:   localNetOp,
			tunnelNetOp:  tunnelNetOp,
			optAutoPeers: optAutoPeers,
		})

		err = forward(ctx, &waitGroup, fwd.proto, lNet, lAddr.String(), rNet, rAddr.String())
		if err != nil {
			return fmt.Errorf("error forwarding %+v: %s", fwd, err)
		}
	}

	<-ctx.Done()
	waitGroup.Wait()
	return ctx.Err()
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

func forward(ctx context.Context, waitGroup *sync.WaitGroup, proto string, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	switch proto {
	case "tcp":
		return forwardTCP(ctx, waitGroup, lNet, lAddr, rNet, rAddr)
	case "udp":
		return forwardUDP(ctx, waitGroup, lNet, lAddr, rNet, rAddr)
	default:
		return fmt.Errorf("unknown protocol: %s", proto)
	}
}

func forwardTCP(ctx context.Context, waitGroup *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	listener, err := lNet.Listen(ctx, "tcp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		loggerInfo.Printf("Stopping TCP forwarder for %s -> %s", lAddr, rAddr)
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
			loggerDebug.Printf("Accepted TCP connection from %s for %s", conn.RemoteAddr(), lAddr)

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

func forwardUDP(ctx context.Context, waitGroup *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	// TODO: Needs synchronization
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

func doAutoAddrPlanning(cfg *wgconfig.Config) ([]autoPeer, error) {
	ourIntAddr, err := publicKeyToV6Addr(cfg.Interface.PublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to convert our public key to v6 addr: %q - %w",
			base64.StdEncoding.EncodeToString(cfg.Interface.PublicKey[:]), err)
	}

	ourAddr := netip.PrefixFrom(ourIntAddr, 128)
	cfg.Interface.Address = &ourAddr

	var peers []autoPeer

	for _, peer := range cfg.Peers {
		peerAddr, err := publicKeyToV6Addr(peer.PublicKey[:])
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer public key to v6 addr: %q - %w",
				base64.StdEncoding.EncodeToString(peer.PublicKey[:]), err)
		}

		peer.AllowedIPs = append(peer.AllowedIPs, netip.PrefixFrom(peerAddr, 128))

		peers = append(peers, autoPeer{
			publicKey: peer.PublicKey[:],
			addr:      peerAddr,
		})
	}

	return peers, nil
}

type autoPeer struct {
	publicKey []byte
	addr      netip.Addr
}

type replaceWgAddrShortcutsArgs struct {
	addr               *string
	ourWgAddr          string
	isAutoAddrPlanning bool
	optAutoPeers       []autoPeer
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	if *args.addr == "us" {
		*args.addr = args.ourWgAddr
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

// TODO: Think about putting in separate library.
// TODO: Need to retry lookup if a transient failure occurs / restructure code.
func peerDNSResolution(ctx context.Context, cfg *wgconfig.Config) error {
	netResolver := net.Resolver{}

	for _, peer := range cfg.Peers {
		if peer.Endpoint == nil {
			continue
		}

		_, isIP := peer.Endpoint.IsIP()
		if isIP {
			continue
		}

		addrs, err := netResolver.LookupHost(ctx, peer.Endpoint.Host())
		if err != nil {
			return fmt.Errorf("peer %q: failed to lookup %q - %w",
				base64.StdEncoding.EncodeToString(peer.PublicKey[:]),
				peer.Endpoint.Host(),
				err)
		}

		// TODO: Doesn't seem like wireguard supports multiple endpoints.
		//  For now we will just use the first address.
		newAddrPort := wgconfig.AddrPortFrom(addrs[0], peer.Endpoint.Port())
		peer.Endpoint = &newAddrPort
	}

	return nil
}

type netOpForAddrArgs struct {
	addr         netip.AddrPort
	ourWgAddr    netip.Addr
	localNetOp   netOp
	tunnelNetOp  netOp
	optAutoPeers []autoPeer
}

func netOpForAddr(args netOpForAddrArgs) netOp {
	if args.addr.Addr() == args.ourWgAddr {
		return args.tunnelNetOp
	}

	if len(args.optAutoPeers) == 0 {
		return args.localNetOp
	}

	for _, peer := range args.optAutoPeers {
		if peer.addr == args.addr.Addr() {
			return args.tunnelNetOp
		}
	}

	return args.localNetOp
}
