package forwarding

import (
	"context"
	"net"
	"sync"
	"time"

	"gitlab.com/stephen-fox/wgu/config"
)

type forwardDatagramArgs struct {
	waitg   *sync.WaitGroup
	spec    *config.ForwarderSpec
	lNet    NetOp
	dNet    NetOp
	loggers Loggers
}

func forwardDatagram(ctx context.Context, args forwardDatagramArgs) error {
	localConn, err := args.lNet.ListenPacket(ctx, string(args.spec.ListenAddr.Protocol()), args.spec.ListenAddr.String())
	if err != nil {
		return err
	}

	srcToDstConns := newConnMap()

	go func() {
		<-ctx.Done()

		if args.loggers.Info != nil {
			args.loggers.Info.Printf("[%s] stopping datagram forwarder...",
				args.spec.Name)
		}

		localConn.Close()

		srcToDstConns.do(func(m map[string]net.Conn) {
			for addr, c := range m {
				c.Close()
				delete(m, addr)
			}
		})
	}()

	args.waitg.Add(1)
	go func() {
		defer args.waitg.Done()

		const bufSizeBytes = 1392
		buffer := make([]byte, bufSizeBytes)

		dAddrStr := args.spec.DialAddr.String()

		for {
			n, srcAddr, err := localConn.ReadFrom(buffer)
			if err != nil {
				if args.loggers.Debug != nil {
					args.loggers.Debug.Printf("[%s] error reading from datagram listener - %#v",
						args.spec.Name, err)
				}

				return
			}

			srcAddrStr := srcAddr.String()

			remote, hasIt := srcToDstConns.lookup(srcAddrStr)
			if hasIt {
				n, err = remote.Write(buffer[:n])
				if err != nil {
					if args.loggers.Err != nil {
						args.loggers.Err.Printf("[%s] error writing to remote %s - %s",
							args.spec.Name, srcAddrStr, err)
					}

					continue
				}

				continue
			}

			go dialAndCopyDatagram(ctx, dialAndCopyDatagramArgs{
				name:           args.spec.Name,
				localConn:      localConn,
				srcAddr:        srcAddr,
				srcAddrStr:     srcAddrStr,
				dNet:           args.dNet,
				dProto:         args.spec.DialAddr.Protocol(),
				dAddrStr:       dAddrStr,
				bufSizeByte:    bufSizeBytes,
				remoteConns:    srcToDstConns,
				optDialTimeout: args.spec.OptDialTimeout,
				loggers:        args.loggers,
			})
		}
	}()

	if args.loggers.Info != nil {
		args.loggers.Info.Printf("[%s] datagram forwarder started",
			args.spec.Name)
	}

	return nil
}

type dialAndCopyDatagramArgs struct {
	name           string
	localConn      net.PacketConn
	srcAddr        net.Addr
	srcAddrStr     string
	dNet           NetOp
	dProto         config.ProtocolT
	dAddrStr       string
	bufSizeByte    int
	remoteConns    *connMap
	optDialTimeout time.Duration
	loggers        Loggers
}

func dialAndCopyDatagram(ctx context.Context, args dialAndCopyDatagramArgs) {
	var remote net.Conn
	var err error

	if args.optDialTimeout > 0 {
		retrier := retryDialer{args.dNet.Dial}

		remote, err = retrier.dial(
			ctx,
			string(args.dProto),
			args.dAddrStr,
			args.optDialTimeout)
	} else {
		remote, err = args.dNet.Dial(
			ctx,
			string(args.dProto),
			args.dAddrStr)
	}

	if err != nil {
		if args.loggers.Err != nil {
			args.loggers.Err.Printf("[%s] error connecting to remote - %s",
				args.name, err)
		}

		return
	}

	args.remoteConns.set(args.srcAddrStr, remote)

	defer args.remoteConns.delete(args.srcAddrStr)

	buffer := make([]byte, args.bufSizeByte)

	for {
		remote.SetReadDeadline(time.Now().Add(2 * time.Minute))

		n, err := remote.Read(buffer)
		if err != nil {
			if args.loggers.Debug != nil {
				args.loggers.Debug.Printf("[%s] error reading from socket - %s",
					args.name, err)
			}

			return
		}

		_, err = args.localConn.WriteTo(buffer[:n], args.srcAddr)
		if err != nil {
			if args.loggers.Debug != nil {
				args.loggers.Debug.Printf("[%s] error writing to local - %s",
					args.name, err)
			}

			return
		}
	}
}

func newConnMap() *connMap {
	return &connMap{
		conns: make(map[string]net.Conn),
	}
}

type connMap struct {
	rwMu  sync.RWMutex
	conns map[string]net.Conn
}

func (o *connMap) set(addr string, conn net.Conn) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	o.conns[addr] = conn
}

func (o *connMap) do(fn func(m map[string]net.Conn)) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	fn(o.conns)
}

func (o *connMap) lookup(addr string) (net.Conn, bool) {
	o.rwMu.RLock()
	defer o.rwMu.RUnlock()

	conn, ok := o.conns[addr]

	return conn, ok
}

func (o *connMap) delete(addr string) {
	o.rwMu.Lock()
	defer o.rwMu.Unlock()

	delete(o.conns, addr)
}
