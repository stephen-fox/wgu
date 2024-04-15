package wgconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gitlab.com/stephen-fox/wgu/internal/ini"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"golang.zx2c4.com/wireguard/device"
)

// Parse parses a Config from an io.Reader.
func Parse(r io.Reader) (*Config, error) {
	config := &Config{}

	err := ini.ParseSchema(r, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Config represents the WireGuard configuration.
type Config struct {
	Interface *Interface
	Peers     []*Peer
	Others    []*ini.Section
}

// GlobalParam partly implements the ini.Schema interface.
func (o *Config) GlobalParam(*ini.Param) error {
	return errors.New("global parameters are not supported")
}

// StartSection partly implements the ini.Schema interface.
func (o *Config) StartSection(name string) (ini.SectionSchema, error) {
	switch name {
	case "Interface":
		if o.Interface != nil {
			return nil, errors.New("only one Interface section is permitted")
		}

		o.Interface = &Interface{}

		return o.Interface, nil
	case "Peer":
		peer := &Peer{}

		o.Peers = append(o.Peers, peer)

		return peer, nil
	default:
		other := &ini.Section{Name: name}

		o.Others = append(o.Others, other)

		return other, nil
	}
}

// Validate partly implements the ini.Schema interface.
func (o *Config) Validate() error {
	if len(o.Peers) == 0 {
		return errors.New("no Peer sections were defined")
	}

	return nil
}

func (o *Config) WireGuardString() string {
	b := bytes.NewBuffer(nil)

	o.Interface.string(b)
	b.WriteByte('\n')

	for i, peer := range o.Peers {
		peer.string(b)

		if len(o.Peers)-1 != i {
			b.WriteByte('\n')
		}
	}

	return b.String()
}

// IPCConfig returns the Config in WireGuard IPC format.
//
// For more information regarding this format, please refer to:
// https://www.wireguard.com/xplatform/#configuration-protocol
func (o *Config) IPCConfig() (string, error) {
	buf := bytes.NewBuffer(nil)

	err := o.Interface.ipcString(buf)
	if err != nil {
		return "", fmt.Errorf("failed to convert Interface section to ipc string - %w", err)
	}

	for _, peer := range o.Peers {
		err := peer.ipcString(buf)
		if err != nil {
			return "", fmt.Errorf("failed to convert Peer section to ipc string - %w", err)
		}
	}

	return buf.String(), nil
}

// Interface represents the Interface section found in a WireGuard
// configuration file.
//
// See also:
//   - https://github.com/pirate/wireguard-docs?tab=readme-ov-file#interface
type Interface struct {
	PrivateKey *device.NoisePrivateKey
	PublicKey  *device.NoisePublicKey
	ListenPort *uint16
	Address    *netip.Prefix
	MTU        *int
	Others     []*ini.Param
}

// AddParam partly implements the ini.SectionSchema interface.
func (o *Interface) AddParam(p *ini.Param) error {
	switch p.Name {
	case "PrivateKey":
		if o.PrivateKey != nil {
			return errors.New("PrivateKey is already set")
		}

		privateKey, err := parsePrivateKey(p.Value)
		if err != nil {
			return err
		}

		o.PrivateKey = privateKey
		o.PublicKey = wgkeys.NoisePublicKeyFromPrivate(privateKey)
	case "ListenPort":
		i, err := strconv.ParseUint(p.Value, 10, 16)
		if err != nil {
			return err
		}

		tmp := uint16(i)

		o.ListenPort = &tmp
	case "Address":
		if o.Address != nil {
			return errors.New("Address is already set")
		}

		prefix, err := netip.ParsePrefix(p.Value)
		if err != nil {
			return err
		}

		o.Address = &prefix
	case "MTU":
		if o.MTU != nil {
			return errors.New("MTU is already set")
		}

		mtu, err := strconv.Atoi(p.Value)
		if err != nil {
			return fmt.Errorf("failed to parse mtu as an int - %w", err)
		}

		if mtu <= 0 {
			return fmt.Errorf("mtu is less than or equal to zero (%d)", mtu)
		}

		o.MTU = &mtu
	default:
		o.Others = append(o.Others, p)
	}

	return nil
}

// Validate partly implements the ini.SectionSchema interface.
func (o *Interface) Validate() error {
	if o.PrivateKey == nil {
		return errors.New("missing PrivateKey param")
	}

	return nil
}

func (o *Interface) string(b *bytes.Buffer) {
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(base64.StdEncoding.EncodeToString(o.PrivateKey[:]))
	b.WriteString("\n")

	if o.ListenPort != nil {
		b.WriteString("ListenPort = ")
		b.WriteString(strconv.Itoa(int(*o.ListenPort)))
		b.WriteString("\n")
	}

	if o.Address != nil {
		b.WriteString("Address = ")
		b.WriteString(o.Address.String())
		b.WriteString("\n")
	}

	if o.MTU != nil {
		b.WriteString("MTU = ")
		b.WriteString(strconv.Itoa(*o.MTU))
		b.WriteString("\n")
	}
}

func (o *Interface) ipcString(b *bytes.Buffer) error {
	b.WriteString("private_key")
	b.WriteString("=")
	b.WriteString(hex.EncodeToString(o.PrivateKey[:]))
	b.WriteString("\n")

	if o.ListenPort != nil {
		b.WriteString("listen_port")
		b.WriteString("=")
		b.WriteString(strconv.Itoa(int(*o.ListenPort)))
		b.WriteString("\n")
	}

	// Address is not passed as an IPC param.

	return nil
}

// Peer represents the Peer section found in a WireGuard configuration file.
//
// See also:
//   - https://github.com/pirate/wireguard-docs?tab=readme-ov-file#peer
type Peer struct {
	PublicKey           *device.NoisePublicKey
	Endpoint            *AddrPort
	AllowedIPs          []netip.Prefix
	PersistentKeepalive *uint64
	Others              []*ini.Param
}

// AddParam partly implements the ini.SectionSchema interface.
func (o *Peer) AddParam(p *ini.Param) error {
	switch p.Name {
	case "PublicKey":
		if o.PublicKey != nil {
			return errors.New("PublicKey is already set")
		}

		publicKey, err := wgkeys.NoisePublicKeyFromBase64(p.Value)
		if err != nil {
			return err
		}

		o.PublicKey = publicKey
	case "Endpoint":
		if o.Endpoint != nil {
			return errors.New("Endpoint is already set")
		}

		addrPort, err := addrPortFromString(p.Value)
		if err != nil {
			return fmt.Errorf("failed to parse address and port - %w", err)
		}

		o.Endpoint = &addrPort
	case "AllowedIPs":
		prefixStrs := strings.Split(p.Value, ",")

		for _, str := range prefixStrs {
			allowedIP, err := netip.ParsePrefix(str)
			if err != nil {
				return fmt.Errorf("failed to parse cidr: %q - %w",
					str, err)
			}

			o.AllowedIPs = append(
				o.AllowedIPs,
				allowedIP)

		}
	case "PersistentKeepalive":
		i, err := strconv.ParseUint(p.Value, 10, 64)
		if err != nil {
			return err
		}

		o.PersistentKeepalive = &i
	default:
		o.Others = append(o.Others, p)
	}

	return nil
}

// Validate partly implements the ini.SectionSchema interface.
func (o *Peer) Validate() error {
	if o.PublicKey == nil {
		return errors.New("missing PublicKey param")
	}

	return nil
}

func (o *Peer) string(b *bytes.Buffer) {
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(base64.StdEncoding.EncodeToString(o.PublicKey[:]))
	b.WriteString("\n")

	if o.Endpoint != nil {
		b.WriteString("Endpoint = ")
		b.WriteString(o.Endpoint.String())
		b.WriteString("\n")
	}

	for _, allowed := range o.AllowedIPs {
		b.WriteString("AllowedIPs = ")
		b.WriteString(allowed.String())
		b.WriteString("\n")
	}

	if o.PersistentKeepalive != nil {
		b.WriteString("PersistentKeepalive = ")
		b.WriteString(strconv.Itoa(int(*o.PersistentKeepalive)))
		b.WriteString("\n")
	}
}

func (o *Peer) ipcString(b *bytes.Buffer) error {
	// public_key must always be first.
	b.WriteString("public_key")
	b.WriteString("=")
	b.WriteString(hex.EncodeToString(o.PublicKey[:]))
	b.WriteString("\n")

	if o.Endpoint != nil {
		b.WriteString("endpoint")
		b.WriteString("=")
		b.WriteString(o.Endpoint.String())
		b.WriteString("\n")
	}

	if len(o.AllowedIPs) > 0 {
		for _, prefix := range o.AllowedIPs {
			b.WriteString("allowed_ip")
			b.WriteString("=")
			b.WriteString(prefix.String())
			b.WriteString("\n")
		}
	}

	if o.PersistentKeepalive != nil {
		b.WriteString("persistent_keepalive_interval")
		b.WriteString("=")
		b.WriteString(strconv.Itoa(int(*o.PersistentKeepalive)))
		b.WriteString("\n")
	}

	return nil
}

func addrPortFromString(addrPortStr string) (AddrPort, error) {
	host, portStr, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		return AddrPort{}, err
	}

	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return AddrPort{}, err
	}

	port := uint16(portInt)

	return AddrPortFrom(host, port), nil
}

func AddrPortFrom(host string, port uint16) AddrPort {
	var optAddrPort netip.AddrPort
	ip, err := netip.ParseAddr(host)
	if err == nil {
		optAddrPort = netip.AddrPortFrom(ip, port)
	}

	return AddrPort{
		host: host,
		port: port,
		ip:   optAddrPort,
	}
}

// AddrPort represents an address and port where the host part can be
// an IP address, a hostname, or some other string.
type AddrPort struct {
	host string
	ip   netip.AddrPort
	port uint16
}

func (o AddrPort) Host() string {
	return o.host
}

func (o AddrPort) Port() uint16 {
	return o.port
}

func (o AddrPort) IsIP() (netip.AddrPort, bool) {
	if o.ip.Addr().Compare(netip.Addr{}) == 0 {
		return netip.AddrPort{}, false
	}

	return o.ip, true
}

func (o AddrPort) String() string {
	ip, isIp := o.IsIP()
	if isIp {
		return ip.String()
	}

	return fmt.Sprintf("%s:%d", o.host, o.port)
}

func parsePrivateKey(iniParamValue string) (*device.NoisePrivateKey, error) {
	noPrefix := strings.TrimPrefix(iniParamValue, "file://")
	if noPrefix != iniParamValue {
		if strings.HasPrefix(noPrefix, "~") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get user's home directory - %w", err)
			}

			noPrefix = homeDir + noPrefix[1:]
		}

		contents, err := os.ReadFile(noPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to read file - %w", err)
		}

		noPrefix = string(bytes.TrimRight(contents, "\n\r"))
	}

	privateKey, err := wgkeys.NoisePrivateKeyFromBase64(noPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ini param value - %w", err)
	}

	return privateKey, nil
}
