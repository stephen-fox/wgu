package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gitlab.com/stephen-fox/wgu/internal/ini"
)

// Forwarder-level config stuff.
const (
	forwarderConfigSection = "Forwarder"

	forwarderListenConfigOpt      = "Listen"
	forwarderDialConfigOpt        = "Dial"
	forwarderDialTimeoutConfigOpt = "DialTimeout"

	UnknownNetStackT NetStackT = ""
	HostNetStackT    NetStackT = "host"
	TunNetStackT     NetStackT = "tun"
)

type NetStackT string

func parseForwarder(fwdSection *ini.Section, name string) (*ForwarderSpec, error) {
	listen, err := fwdSection.FirstParam(forwarderListenConfigOpt)
	if err != nil {
		return nil, err
	}

	dial, err := fwdSection.FirstParam(forwarderDialConfigOpt)
	if err != nil {
		return nil, err
	}

	lNetwork, lAddr, err := parseTransitSpec(listen.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen transit spec - %w",
			err)
	}

	dNetwork, dAddr, err := parseTransitSpec(dial.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dial transit spec - %w",
			err)
	}

	var dialTimeout time.Duration

	dialTimeoutStr, _ := fwdSection.FirstParam(forwarderDialTimeoutConfigOpt)
	if dialTimeoutStr != nil {
		dialTimeout, err = time.ParseDuration(dialTimeoutStr.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dial timeout: %q - %w",
				dialTimeoutStr.Value, err)
		}
	}

	return &ForwarderSpec{
		Name:           name,
		ListenNet:      lNetwork,
		ListenAddr:     lAddr,
		DialNet:        dNetwork,
		DialAddr:       dAddr,
		OptDialTimeout: dialTimeout,
	}, nil
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

type ProtocolT string

func (o ProtocolT) IsStream() bool {
	switch {
	case strings.HasPrefix(string(o), "tcp"):
		return true
	case o == "unix":
		return true
	default:
		return false
	}
}

func (o ProtocolT) IsDatagram() bool {
	switch {
	case strings.HasPrefix(string(o), "udp"):
		return true
	case o == "unixgram":
		return true
	default:
		return false
	}
}
