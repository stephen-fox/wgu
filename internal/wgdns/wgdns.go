package wgdns

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"gitlab.com/stephen-fox/wgu/internal/wgconfig"
	"golang.zx2c4.com/wireguard/device"
)

func MonitorPeers(ctx context.Context, peers []*wgconfig.Peer, device *device.Device, errs chan<- error, logger *log.Logger) {
	for _, peer := range peers {
		if peer.Endpoint == nil {
			continue
		}

		_, isIp := peer.Endpoint.IsIP()
		if isIp {
			continue
		}

		monitor := MonitorPeer(ctx, peer, device, logger)

		go func() {
			<-monitor.Done()
			errs <- monitor.Err()
		}()
	}
}

func MonitorPeer(ctx context.Context, config *wgconfig.Peer, device *device.Device, logger *log.Logger) *PeerMonitor {
	name := config.Endpoint.Host()

	monitor := &PeerMonitor{
		config: config,
		device: device,
		name:   name,
		logger: log.New(logger.Writer(),
			logger.Prefix()+" [dns-peer-monitor "+name+"] ",
			logger.Flags()),
		done: make(chan struct{}),
	}

	go monitor.loop(ctx)

	return monitor
}

type PeerMonitor struct {
	config *wgconfig.Peer
	device *device.Device
	name   string
	logger *log.Logger
	done   chan struct{}
	err    error
}

func (o *PeerMonitor) Name() string {
	return o.name
}

func (o *PeerMonitor) Done() <-chan struct{} {
	return o.done
}

func (o *PeerMonitor) Err() error {
	return o.err
}

func (o *PeerMonitor) loop(ctx context.Context) {
	o.err = fmt.Errorf("%s - %w", o.name, o.loopWithError(ctx))
	close(o.done)
}

func (o *PeerMonitor) loopWithError(ctx context.Context) error {
	hostname := o.config.Endpoint.Host()
	var lastResolvedAddr string
	doLookup := time.NewTimer(time.Millisecond)
	netResolver := net.Resolver{}

	o.logger.Printf("starting...")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doLookup.C:
			addrs, err := netResolver.LookupHost(ctx, hostname)
			if err != nil {
				doLookup.Reset(time.Minute)
				o.logger.Printf("failed to resolve %q - %s", hostname, err)
				continue
			}

			if len(addrs) == 0 {
				doLookup.Reset(time.Minute)
				o.logger.Printf("failed to resolve %q - it has no addresses", hostname)
				continue
			}

			// TODO: Doesn't seem like wireguard supports multiple endpoints.
			//  For now we will just use the first address.
			currentAddr := addrs[0]
			if currentAddr == lastResolvedAddr {
				doLookup.Reset(10 * time.Minute)
				continue
			}

			newAddrPort := wgconfig.AddrPortFrom(currentAddr, o.config.Endpoint.Port())
			o.config.Endpoint = &newAddrPort

			buf := bytes.NewBuffer(nil)
			err = o.config.IPCString(buf)
			if err != nil {
				doLookup.Reset(time.Minute)
				o.logger.Printf("failed to create ipc string - %s", err)
				continue
			}

			err = o.device.IpcSetOperation(buf)
			if err != nil {
				doLookup.Reset(time.Minute)
				o.logger.Printf("failed to set ipc config - %s", err)
				continue
			}

			doLookup.Reset(10 * time.Minute)
			lastResolvedAddr = currentAddr

			o.logger.Printf("new address is: %q", currentAddr)
		}
	}
}
