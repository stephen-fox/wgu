//go:build tap_enabled

package wgtap

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Setup wraps a tun.Device with a TappedDevice. The tap is stopped
// when the provided context.Context is marked as done.
//
// Warning: Only use this when debugging! This type *by design* exposes
// the unencrypted network traffic that traverses a WireGuard tunnel to
// unauthenticated clients.
func Setup(ctx context.Context, dev tun.Device, config TapConfig) (*TappedDevice, error) {
	err := config.validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate tap config - %w", err)
	}

	if config.Protocol == "unix" {
		_ = os.Remove(config.Address)
	}

	listener, err := net.Listen(config.Protocol, config.Address)
	if err != nil {
		return nil, err
	}

	tap := &Tap{
		listener:  listener,
		acceptErr: make(chan error, 1),
		accepts:   make(chan net.Conn),
		packets:   make(chan []byte, 10),
		done:      make(chan struct{}),
	}

	go tap.acceptClientsLoop()

	go tap.loop(ctx)

	return &TappedDevice{
		tap:       tap,
		tunDevice: dev,
	}, nil
}

// TappedDevice proxies a tun.Device implementation such as the one returned
// by netstack.CreateNetTUN. TappedDevice creates and manages a net.Listener
// that writes unencrypted tunnel packets to clients for debugging purposes.
//
// Warning: Only use this when debugging! This type *by design* exposes
// the unencrypted network traffic that traverses a WireGuard tunnel to
// unauthenticated clients.
//
// This function implements the tun.Device interface from the wireguard-go
// library.
type TappedDevice struct {
	tap       *Tap
	tunDevice tun.Device
}

// File returns the file descriptor of the device.
func (o *TappedDevice) File() *os.File {
	return o.tunDevice.File()
}

// Read one or more packets from the Device (without any additional headers).
// On a successful read it returns the number of packets read, and sets
// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
// A nonzero offset can be used to instruct the Device on where to begin
// reading into each element of the bufs slice.
func (o *TappedDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := o.tunDevice.Read(bufs, sizes, offset)

	for i := 0; i < n; i++ {
		buf := bufs[i]
		size := sizes[i]

		packet := buf[offset:size]
		if len(packet) == 0 {
			continue
		}

		_, _ = o.tap.Write(packet)
	}

	return n, err
}

// Write one or more packets to the device (without any additional headers).
// On a successful write it returns the number of packets written. A nonzero
// offset can be used to instruct the Device on where to begin writing from
// each packet contained within the bufs slice.
func (o *TappedDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		_, _ = o.tap.Write(packet)
	}

	return o.tunDevice.Write(bufs, offset)
}

// MTU returns the MTU of the Device.
func (o *TappedDevice) MTU() (int, error) {
	return o.tunDevice.MTU()
}

// Name returns the current name of the Device.
func (o *TappedDevice) Name() (string, error) {
	return o.tunDevice.Name()
}

// Events returns a channel of type Event, which is fed Device events.
func (o *TappedDevice) Events() <-chan tun.Event {
	return o.tunDevice.Events()
}

// Close stops the Device and closes the Event channel.
func (o *TappedDevice) Close() error {
	return o.tunDevice.Close()
}

// BatchSize returns the preferred/max number of packets that can be read or
// written in a single read/write call. BatchSize must not change over the
// lifetime of a Device.
func (o *TappedDevice) BatchSize() int {
	return o.tunDevice.BatchSize()
}

type Tap struct {
	listener  net.Listener
	acceptErr chan error
	accepts   chan net.Conn
	packets   chan []byte
	done      chan struct{}
	err       error
}

func (o *Tap) acceptClientsLoop() {
	defer o.listener.Close()

	for {
		conn, err := o.listener.Accept()
		if err != nil {
			o.acceptErr <- err

			return
		}

		select {
		case <-o.done:
			_ = conn.Close()

			return
		case o.accepts <- conn:
			// Keep going.
		}
	}
}

func (o *Tap) loop(ctx context.Context) {
	activeClients := make(map[net.Conn]struct{})

	defer func() {
		_ = o.listener.Close()

		for conn := range activeClients {
			conn.Close()

			delete(activeClients, conn)
		}

		close(o.done)
	}()

	queue := list.New()

	writeToClientFn := func(packet []byte, conn net.Conn) bool {
		packetLen := len(packet)

		// header: 8 bytes (timestamp) + 4 bytes (len)
		msg := make([]byte, 8+4+packetLen)

		ts := uint64(time.Now().UnixMilli())
		binary.LittleEndian.PutUint64(msg[0:8], ts)

		binary.LittleEndian.PutUint32(msg[8:12], uint32(packetLen))

		copy(msg[12:], packet)

		conn.SetDeadline(time.Now().Add(time.Second))

		_, err := conn.Write(msg)
		if err != nil {
			conn.Close()

			delete(activeClients, conn)

			return false
		}

		conn.SetDeadline(time.Time{})

		return true
	}

	for {
		select {
		case <-ctx.Done():
			o.err = ctx.Err()

			return
		case err := <-o.acceptErr:
			o.err = err

			return
		case conn := <-o.accepts:
			activeClients[conn] = struct{}{}

			if queue.Len() > 0 {
				for e := queue.Front(); e != nil; e = e.Next() {
					// TODO: how to remove element (e) from the list inside the for loop
					data := e.Value.([]byte)

					if !writeToClientFn(data, conn) {
						break
					}
				}

				queue.Init()
			}
		case packet := <-o.packets:
			if len(activeClients) == 0 {
				// TODO: upperlimit for how bit the queue can get, and dropping things from the queue
				queue.PushBack(packet)

				continue
			}

			for conn := range activeClients {
				writeToClientFn(packet, conn)
			}
		}
	}
}

func (o *Tap) Write(b []byte) (int, error) {
	if o.err != nil {
		return len(b), nil
	}

	cp := make([]byte, len(b))

	copy(cp, b)

	select {
	case <-o.done:
	case o.packets <- cp:
	}

	return len(b), nil
}
