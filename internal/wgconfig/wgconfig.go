package wgconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"gitlab.com/stephen-fox/wgu/internal/ini"
	"gitlab.com/stephen-fox/wgu/internal/wgkeys"
	"golang.zx2c4.com/wireguard/device"
)

func Parse(r io.Reader) (*Config, error) {
	iniConfig, err := ini.Parse(r)
	if err != nil {
		return nil, err
	}

	return FromINI(iniConfig), nil
}

func FromINI(iniConfig *ini.INI) *Config {
	return &Config{INI: iniConfig}
}

type Config struct {
	INI *ini.INI
}

func (o *Config) String() string {
	return o.INI.String()
}

func (o *Config) IPCConfig() (string, error) {
	buf := bytes.NewBuffer(nil)

	for _, section := range o.INI.Sections {
		err := sectionToIpcString(section, buf)
		if err != nil {
			return "", fmt.Errorf("failed to convert section %q to ipc config - %w",
				section.Name, err)
		}
	}

	return buf.String(), nil
}

func (o *Config) OurPublicKey() ([]byte, error) {
	privateKeyParam, err := o.INI.FirstParamInFirstSection("PrivateKey", "Interface")
	if err != nil {
		return nil, err
	}

	privateKey, err := parsePrivateKey(privateKeyParam.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard private key - %w", err)
	}

	pub := wgkeys.NoisePublicKeyFromPrivate(privateKey)

	return pub[:], nil
}

func (o *Config) OurAddr() (netip.Prefix, error) {
	addrParam, err := o.INI.FirstParamInFirstSection("Address", "Interface")
	if err != nil {
		return netip.Prefix{}, err
	}

	ourAddr, err := netip.ParsePrefix(addrParam.Value)
	if err != nil {
		return netip.Prefix{}, err
	}

	return ourAddr, nil
}

func (o *Config) OurMtuOr(defMtu int) (int, error) {
	mtuParam, optErr := o.INI.FirstParamInFirstSection("MTU", "Interface")
	if optErr != nil {
		return defMtu, nil
	}

	mtu, err := strconv.Atoi(mtuParam.Value)
	if err != nil {
		return 0, err
	}

	return mtu, nil
}

func (o *Config) PeerWithPublicKeyBase64(base64PublicKey string) (interface{}, bool) {
	err := o.INI.IterateSections("Peer", func(section *ini.Section) error {
		err := section.IterateParams("PublicKey", func(param *ini.Param) error {
			if param.Value == base64PublicKey {
				return ini.ErrStopIterating
			}

			return errors.New("nope")
		})
		if err != nil {
			return err
		}

		return ini.ErrStopIterating
	})
	if err != nil {
		return nil, false
	}

	return nil, true
}

func sectionToIpcString(section *ini.Section, b *bytes.Buffer) error {
	// For param names, refer to:
	// https://www.wireguard.com/xplatform/#configuration-protocol

	// This sucks, but the library expects the public key param to
	// appear first for each peer.
	sortedParams := make([]*ini.Param, len(section.Params))
	copy(sortedParams, section.Params)

	sort.SliceStable(sortedParams, func(i, j int) bool {
		return sortedParams[i].Name == "PublicKey"
	})

	for _, param := range sortedParams {
		var ipcParamName string
		var optIpcValue string

		switch section.Name {
		case "Interface":
			switch param.Name {
			case "PrivateKey":
				ipcParamName = "private_key"

				privateKey, err := parsePrivateKey(param.Value)
				if err != nil {
					return err
				}

				optIpcValue = hex.EncodeToString(privateKey[:])
			case "Address":
				// Not needed for ipc.
				continue
			case "MTU":
				ipcParamName = "mtu"
			case "ListenPort":
				ipcParamName = "listen_port"
			}
		case "Peer":
			switch param.Name {
			case "Endpoint":
				ipcParamName = "endpoint"
			case "PublicKey":
				ipcParamName = "public_key"

				raw, err := base64.StdEncoding.DecodeString(param.Value)
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
				param, section.Name)
		}

		b.WriteString(ipcParamName)
		b.WriteString("=")
		if optIpcValue == "" {
			b.WriteString(param.Value)
		} else {
			b.WriteString(optIpcValue)
		}
		b.WriteString("\n")
	}

	return nil
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
