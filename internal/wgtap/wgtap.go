package wgtap

import (
	"errors"
)

// TapConfig configures a TappedDevice.
type TapConfig struct {
	// Protocol is the network protocol to use when creating
	// the net.Listener. It is recommended to use "unix" here
	// for security.
	//
	// Refer to Go's net library for a list of supported values.
	Protocol string

	// Address is the network address to use when creating
	// the listener socket.
	Address string
}

func (o TapConfig) validate() error {
	if o.Protocol == "" {
		return errors.New("protocol is empty string")
	}

	if o.Address == "" {
		return errors.New("address is empty string")
	}

	return nil
}
