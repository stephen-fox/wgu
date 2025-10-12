package wgconfig

import (
	"bytes"
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
	NamedPeer map[string]*Peer
}

// Rules partly implements the ini.Schema interface.
func (o *Config) Rules() ini.ParserRules {
	return ini.ParserRules{
		RequiredSections: []string{
			"Interface",
		},
	}
}

// OnGlobalParam partly implements the ini.Schema interface.
func (o *Config) OnGlobalParam(paramName string) (func(*ini.Param) error, ini.SchemaRule) {
	return nil, ini.SchemaRule{}
}

// OnSection partly implements the ini.Schema interface.
func (o *Config) OnSection(name string, _ string) (func() (ini.SectionSchema, error), ini.SchemaRule) {
	switch name {
	case "Interface":
		return func() (ini.SectionSchema, error) {
			o.Interface = &Interface{}

			return o.Interface, nil
		}, ini.SchemaRule{Limit: 1}
	case "Peer":
		return func() (ini.SectionSchema, error) {
			peer := &Peer{}

			o.Peers = append(o.Peers, peer)

			return peer, nil
		}, ini.SchemaRule{}
	default:
		return func() (ini.SectionSchema, error) {
			other := &ini.Section{Name: name}

			o.Others = append(o.Others, other)

			return other, nil
		}, ini.SchemaRule{}
	}
}

// Validate partly implements the ini.Schema interface.
func (o *Config) Validate() error {
	for i, peer := range o.Peers {
		peer := peer

		if peer.Name == "" {
			continue
		}

		if o.NamedPeer == nil {
			o.NamedPeer = make(map[string]*Peer)
		}

		_, alreadyHasIt := o.NamedPeer[peer.Name]
		if alreadyHasIt {
			return fmt.Errorf("peer %d already assigned name %q",
				i, peer.Name)
		}

		o.NamedPeer[peer.Name] = peer
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
		err := peer.IPCString(buf)
		if err != nil {
			return "", fmt.Errorf("failed to convert Peer section to ipc string - %w", err)
		}
	}

	return buf.String(), nil
}

func (o *Config) IPCConfigWithoutDnsPeers() (string, error) {
	buf := bytes.NewBuffer(nil)

	err := o.Interface.ipcString(buf)
	if err != nil {
		return "", fmt.Errorf("failed to convert Interface section to ipc string - %w", err)
	}

	for _, peer := range o.Peers {
		if peer.Endpoint != nil {
			_, isIp := peer.Endpoint.IsIP()
			if !isIp {
				continue
			}
		}

		err := peer.IPCString(buf)
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
	Addresses  []netip.Prefix
	MTU        *int
	Others     []*ini.Param
}

// RequiredParams partly implements the ini.SectionSchema interface.
func (o *Interface) RequiredParams() []string {
	return []string{
		"PrivateKey",
	}
}

// OnParam partly implements the ini.SectionSchema interface.
func (o *Interface) OnParam(paramName string) (func(*ini.Param) error, ini.SchemaRule) {
	switch paramName {
	case "PrivateKey":
		return func(p *ini.Param) error {
			privateKey, err := parsePrivateKey(p.Value)
			if err != nil {
				return err
			}

			o.PrivateKey = privateKey
			o.PublicKey = wgkeys.NoisePublicKeyFromPrivate(privateKey)

			return nil
		}, ini.SchemaRule{Limit: 1}
	case "ListenPort":
		return func(p *ini.Param) error {
			i, err := strconv.ParseUint(p.Value, 10, 16)
			if err != nil {
				return err
			}

			tmp := uint16(i)

			o.ListenPort = &tmp

			return nil
		}, ini.SchemaRule{Limit: 1}
	case "Address":
		return func(p *ini.Param) error {
			prefix, err := netip.ParsePrefix(p.Value)
			if err != nil {
				return err
			}

			o.Addresses = append(o.Addresses, prefix)

			return nil
		}, ini.SchemaRule{}
	case "MTU":
		return func(p *ini.Param) error {
			mtu, err := strconv.Atoi(p.Value)
			if err != nil {
				return fmt.Errorf("failed to parse mtu as an int - %w", err)
			}

			if mtu <= 0 {
				return fmt.Errorf("mtu is less than or equal to zero (%d)", mtu)
			}

			o.MTU = &mtu

			return nil
		}, ini.SchemaRule{Limit: 1}
	default:
		return nil, ini.SchemaRule{}
	}
}

// Validate partly implements the ini.SectionSchema interface.
func (o *Interface) Validate() error {
	return nil
}

func (o *Interface) AddressByIndex(index uint64) (netip.Prefix, error) {
	if len(o.Addresses) == 0 {
		return netip.Prefix{}, errors.New("no interface addresses configured")
	}

	max := uint64(len(o.Addresses) - 1)

	if index > max {
		return netip.Prefix{}, fmt.Errorf("index is outside of range: 0 to %d",
			max)
	}

	return o.Addresses[index], nil
}

func (o *Interface) string(b *bytes.Buffer) {
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(wgkeys.NoisePrivateKeyToString(o.PrivateKey))
	b.WriteString("\n")

	if o.ListenPort != nil {
		b.WriteString("ListenPort = ")
		b.WriteString(strconv.Itoa(int(*o.ListenPort)))
		b.WriteString("\n")
	}

	for _, addr := range o.Addresses {
		b.WriteString("Address = ")
		b.WriteString(addr.String())
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
	Name                string
	Others              []*ini.Param
}

// RequiredParams partly implements the ini.SectionSchema interface.
func (o *Peer) RequiredParams() []string {
	return []string{
		"PublicKey",
	}
}

// OnParam partly implements the ini.SectionSchema interface.
func (o *Peer) OnParam(paramName string) (func(*ini.Param) error, ini.SchemaRule) {
	switch paramName {
	case "PublicKey":
		return func(p *ini.Param) error {
			publicKey, err := wgkeys.NoisePublicKeyFromBase64(p.Value)
			if err != nil {
				return err
			}

			o.PublicKey = publicKey

			return nil
		}, ini.SchemaRule{Limit: 1}
	case "Endpoint":
		return func(p *ini.Param) error {
			addrPort, err := addrPortFromString(p.Value)
			if err != nil {
				return fmt.Errorf("failed to parse address and port - %w", err)
			}

			o.Endpoint = &addrPort

			return nil
		}, ini.SchemaRule{Limit: 1}
	case "AllowedIPs":
		return func(p *ini.Param) error {
			prefixStrs := strings.Split(p.Value, ",")

			for _, str := range prefixStrs {
				str = strings.TrimSpace(str)

				allowedIP, err := netip.ParsePrefix(str)
				if err != nil {
					return fmt.Errorf("failed to parse cidr: %q - %w",
						str, err)
				}

				o.AllowedIPs = append(
					o.AllowedIPs,
					allowedIP)

			}

			return nil
		}, ini.SchemaRule{}
	case "PersistentKeepalive":
		return func(p *ini.Param) error {
			i, err := strconv.ParseUint(p.Value, 10, 64)
			if err != nil {
				return err
			}

			o.PersistentKeepalive = &i

			return nil
		}, ini.SchemaRule{Limit: 1}
	case "Name":
		return func(p *ini.Param) error {
			o.Name = p.Value
			return nil
		}, ini.SchemaRule{Limit: 1}
	default:
		return nil, ini.SchemaRule{}
	}
}

// Validate partly implements the ini.SectionSchema interface.
func (o *Peer) Validate() error {
	return nil
}

func (o *Peer) string(b *bytes.Buffer) {
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(wgkeys.NoisePublicKeyToString(o.PublicKey))
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

func (o *Peer) IPCString(b *bytes.Buffer) error {
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
