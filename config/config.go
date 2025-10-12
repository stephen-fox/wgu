package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"gitlab.com/stephen-fox/wgu/internal/ini"
	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
)

// App-level config stuff.
const (
	AppOptionsConfigSection       = "wgu"
	AutoAddrPlanningModeConfigOpt = "AutomaticAddressPlanningMode"
	LogLevelConfigOpt             = "LogLevel"
)

func Parse(r io.Reader) (*Config, error) {
	wgConfig, err := wgconfig.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard config - %w", err)
	}

	if wgConfig.Interface.MTU == nil {
		i := 1420
		wgConfig.Interface.MTU = &i
	}

	appConfig := &Config{
		Wireguard: wgConfig,
	}

	for _, section := range wgConfig.Others {
		switch section.Name {
		case AppOptionsConfigSection:
			err := appConfig.parseAppOptions(section)
			if err != nil {
				return nil, err
			}
		case forwarderConfigSection:
			err := appConfig.parseForwarder(section)
			if err != nil {
				return nil, err
			}
		}
	}

	if appConfig.IsAutoAddrPlanningMode {
		err := doAutoAddrPlanning(wgConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to do automatic address planning - %w", err)
		}
	}

	addr0, err := appConfig.Wireguard.Interface.AddressByIndex(0)
	if err != nil {
		return nil, fmt.Errorf("failed to get wireguard interface address - %w", err)
	}

	ifaceAddr0Str := addr0.Addr().String()

	for str, forward := range appConfig.Forwarders {
		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			host:     &forward.ListenAddr,
			ifAddr0:  ifaceAddr0Str,
			wgConfig: appConfig.Wireguard,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to replace listen address for %q - %w",
				str, err)
		}

		err = replaceWgAddrShortcuts(replaceWgAddrShortcutsArgs{
			host:     &forward.DialAddr,
			ifAddr0:  ifaceAddr0Str,
			wgConfig: appConfig.Wireguard,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to replace dial address for %q - %w",
				str, err)
		}
	}

	return appConfig, nil
}

type Config struct {
	IsAutoAddrPlanningMode bool
	OptLogLevel            string
	Forwarders             map[string]*ForwarderSpec
	Wireguard              *wgconfig.Config
}

func (o *Config) parseAppOptions(options *ini.Section) error {
	autoAddrPlanning, _ := options.FirstParam(AutoAddrPlanningModeConfigOpt)
	if autoAddrPlanning != nil {
		enabled, err := strconv.ParseBool(autoAddrPlanning.Value)
		if err != nil {
			return fmt.Errorf("failed to parse automatic address planning mode value: %q - %w",
				autoAddrPlanning.Value, err)
		}

		o.IsAutoAddrPlanningMode = enabled
	}

	logLevel, _ := options.FirstParam(LogLevelConfigOpt)
	if logLevel != nil {
		o.OptLogLevel = logLevel.Value
	}

	return nil
}

func (o *Config) parseForwarder(fwdSection *ini.Section) error {
	name, err := fwdSection.FirstParam("Name")
	if err != nil {
		return err
	}

	_, alreadyHasIt := o.Forwarders[name.Value]
	if alreadyHasIt {
		return fmt.Errorf("forward config already specified: %q", name.Value)
	}

	fwdSpec, err := parseForwarder(fwdSection, name.Value)
	if err != nil {
		return fmt.Errorf("failed to parse forwarder: %q - %w", name.Value, err)
	}

	if o.Forwarders == nil {
		o.Forwarders = make(map[string]*ForwarderSpec)
	}

	o.Forwarders[name.Value] = fwdSpec

	return nil
}

func doAutoAddrPlanning(cfg *wgconfig.Config) error {
	ourAutoAddrPrefix, err := PublicKeyToV6Addr(cfg.Interface.PublicKey[:])
	if err != nil {
		return fmt.Errorf("failed to convert our public key to v6 addr: %q - %w",
			wgkeys.NoisePublicKeyToString(cfg.Interface.PublicKey), err)
	}

	ourAutoAddr := netip.PrefixFrom(ourAutoAddrPrefix, 128)

	cfg.Interface.Addresses = append(cfg.Interface.Addresses, ourAutoAddr)

	for _, peer := range cfg.Peers {
		peerAddr, err := PublicKeyToV6Addr(peer.PublicKey[:])
		if err != nil {
			return fmt.Errorf("failed to convert peer public key to v6 addr: %q - %w",
				wgkeys.NoisePublicKeyToString(cfg.Interface.PublicKey), err)
		}

		peer.AllowedIPs = append(peer.AllowedIPs, netip.PrefixFrom(peerAddr, 128))
	}

	return nil
}

func PublicKeyToV6Addr(pub []byte) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(pub[len(pub)-16:])
	if !ok {
		return netip.Addr{}, errors.New("netip.AddrFromSlice returned false")
	}

	return addr, nil
}

type replaceWgAddrShortcutsArgs struct {
	host     *Addr
	ifAddr0  string
	wgConfig *wgconfig.Config
}

func replaceWgAddrShortcuts(args replaceWgAddrShortcutsArgs) error {
	origHostStr := args.host.Host()

	if !strings.HasPrefix(origHostStr, "@") {
		return nil
	}

	if origHostStr == "@us" {
		args.host.SetHost(args.ifAddr0)

		return nil
	}

	withoutUsIndexPrefix := strings.TrimPrefix(origHostStr, "@us")
	if len(withoutUsIndexPrefix) != len(origHostStr) {
		index, err := strconv.ParseUint(withoutUsIndexPrefix, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse interface index string: %q - %w",
				withoutUsIndexPrefix, err)
		}

		addr, err := args.wgConfig.Interface.AddressByIndex(index)
		if err != nil {
			return fmt.Errorf("failed to lookup address index number %d - %w",
				index, err)
		}

		args.host.SetHost(addr.Addr().String())

		return nil
	}

	name := args.host.Host()
	name = name[1:]

	actualPeer, hasIt := args.wgConfig.NamedPeer[name]
	if !hasIt {
		return fmt.Errorf("unknown peer nickname: %q", name)
	}

	addr, err := singleAddrPrefix(actualPeer.AllowedIPs)
	if err != nil {
		return fmt.Errorf("failed to get address for peer with nickname %q - %w",
			name, err)
	}

	args.host.SetHost(addr.String())

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
