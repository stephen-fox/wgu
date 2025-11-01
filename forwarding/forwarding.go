package forwarding

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"gitlab.com/stephen-fox/wgu/config"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type StartForwardersArgs struct {
	TunNet      *netstack.Net
	StrsToSpecs map[string]*config.ForwarderSpec
	Loggers     Loggers
}

type Loggers struct {
	Info  *log.Logger
	Err   *log.Logger
	Debug *log.Logger
}

func StartForwarders(ctx context.Context, args StartForwardersArgs) (*sync.WaitGroup, error) {
	waitGroup := &sync.WaitGroup{}
	var localNetOp = &LocalNetOp{}
	var tunnelNetOp = &TunnelNetOp{args.TunNet}

	for fwdStr, spec := range args.StrsToSpecs {
		var listenNet NetOp
		switch spec.ListenNet {
		case config.HostNetStackT:
			listenNet = localNetOp
		case config.TunNetStackT:
			listenNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported listen net stack: %q", spec.ListenNet)
		}

		var dialNet NetOp
		switch spec.DialNet {
		case config.HostNetStackT:
			dialNet = localNetOp
		case config.TunNetStackT:
			dialNet = tunnelNetOp
		default:
			return nil, fmt.Errorf("unsupported dial net stack: %q", spec.DialNet)
		}

		if args.Loggers.Info != nil {
			args.Loggers.Info.Printf("starting %q (%s)...", spec.Name, spec.String())
		}

		var err error

		switch {
		case spec.ListenAddr.Protocol().IsStream():
			err = forwardStream(ctx, forwardStreamArgs{
				waitg:   waitGroup,
				spec:    spec,
				lNet:    listenNet,
				dNet:    dialNet,
				loggers: args.Loggers,
			})
		case spec.ListenAddr.Protocol().IsDatagram():
			err = forwardDatagram(ctx, forwardDatagramArgs{
				waitg:   waitGroup,
				spec:    spec,
				lNet:    listenNet,
				dNet:    dialNet,
				loggers: args.Loggers,
			})
		default:
			err = fmt.Errorf("unsupported listen protocol: %q", spec.ListenAddr.Protocol())
		}

		if err != nil {
			return nil, fmt.Errorf("failed to forward %q - %w", fwdStr, err)
		}
	}

	return waitGroup, nil
}

type NetOp interface {
	Dial(ctx context.Context, network string, address string) (net.Conn, error)
	Listen(ctx context.Context, network string, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error)
}

type LocalNetOp struct{}

func (o *LocalNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, network, address)
}

func (o *LocalNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	var l net.ListenConfig

	return l.Listen(ctx, network, address)
}

func (o *LocalNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	var l net.ListenConfig

	return l.ListenPacket(ctx, network, address)
}

type TunnelNetOp struct {
	tun *netstack.Net
}

func (o *TunnelNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	return o.tun.DialContext(ctx, network, address)
}

func (o *TunnelNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return o.tun.ListenTCP(addr)
}

func (o *TunnelNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return o.tun.ListenUDP(addr)
}

type retryDialer struct {
	DialFn func(ctx context.Context, network string, address string) (net.Conn, error)
}

func (o *retryDialer) dial(ctx context.Context, network string, addr string, timeout time.Duration) (net.Conn, error) {
	wctx, cancelFn := context.WithTimeout(ctx, timeout)
	defer cancelFn()

	sleep := time.Second
	scale := time.Duration(2)
	attempts := 0

	for {
		attempts++

		conn, err := o.DialFn(wctx, network, addr)
		if err == nil {
			return conn, nil
		}

		select {
		case <-wctx.Done():
			return nil, fmt.Errorf("gave up connecting after %d attempt(s) - %w (last error: %v)",
				attempts, wctx.Err(), err)
		case <-time.After(sleep):
			// 1 * 2
			// 1 * 5
			// 1 * 8
			// 1 * 11
			sleep = sleep * scale

			scale = scale + 3
		}
	}
}
