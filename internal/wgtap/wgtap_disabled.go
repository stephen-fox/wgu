//go:build !tap_enabled

package wgtap

import (
	"context"
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

func Setup(context.Context, tun.Device, TapConfig) (tun.Device, error) {
	return nil, errors.New("compiled without tap support - please recompile from source to use the tap feature")
}
