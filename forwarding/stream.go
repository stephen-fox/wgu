package forwarding

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"gitlab.com/stephen-fox/wgu/config"
)

type forwardStreamArgs struct {
	waitg   *sync.WaitGroup
	spec    *config.ForwarderSpec
	lNet    NetOp
	dNet    NetOp
	loggers Loggers
}

func forwardStream(ctx context.Context, args forwardStreamArgs) error {
	listener, err := args.lNet.Listen(ctx, string(args.spec.ListenAddr.Protocol()), args.spec.ListenAddr.String())
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		if args.loggers.Info != nil {
			args.loggers.Info.Printf("[%s] stopping forwarder...",
				args.spec.Name)
		}

		listener.Close()
	}()

	args.waitg.Add(1)
	go func() {
		defer args.waitg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if args.loggers.Err != nil {
					args.loggers.Err.Printf("[%s] error accepting connection - %s",
						args.spec.Name, err)
				}

				return
			}

			if args.loggers.Debug != nil {
				args.loggers.Debug.Printf("[%s] accepted connection from %s",
					args.spec.Name, conn.RemoteAddr())
			}

			go dialAndCopyStream(ctx, dialAndCopyStreamArgs{
				src:     conn,
				dNet:    args.dNet,
				spec:    args.spec,
				loggers: args.loggers,
			})
		}
	}()

	if args.loggers.Info != nil {
		args.loggers.Info.Printf("[%s] stream forwarder started",
			args.spec.Name)
	}

	return nil
}

type dialAndCopyStreamArgs struct {
	src     net.Conn
	dNet    NetOp
	spec    *config.ForwarderSpec
	loggers Loggers
}

func dialAndCopyStream(ctx context.Context, args dialAndCopyStreamArgs) {
	defer args.src.Close()

	var dst net.Conn
	var err error

	if args.spec.OptDialTimeout > 0 {
		retrier := retryDialer{args.dNet.Dial}

		dst, err = retrier.dial(
			ctx,
			string(args.spec.DialAddr.Protocol()),
			args.spec.DialAddr.String(),
			args.spec.OptDialTimeout)
	} else {
		dst, err = args.dNet.Dial(
			ctx,
			string(args.spec.DialAddr.Protocol()),
			args.spec.DialAddr.String())
	}

	if err != nil {
		if args.loggers.Err != nil {
			args.loggers.Err.Printf("[%s] error connecting to remote - %s",
				args.spec.Name, err)
		}

		return
	}
	defer dst.Close()

	if args.loggers.Debug != nil {
		args.loggers.Debug.Printf("[%s] new stream connection forwarded",
			args.spec.Name)
	}

	done := make(chan string, 2)

	go func() {
		_, err := io.Copy(dst, args.src)

		if args.loggers.Debug != nil {
			done <- fmt.Sprintf("error copying from %s: %v",
				args.spec.DialAddr.String(), err)
		} else {
			done <- ""
		}
	}()

	go func() {
		_, err := io.Copy(args.src, dst)

		if args.loggers.Debug != nil {
			done <- fmt.Sprintf("error copying to %s: %v",
				args.src.RemoteAddr(), err)
		} else {
			done <- ""
		}
	}()

	select {
	case <-ctx.Done():
		return
	case reason := <-done:
		if reason != "" {
			args.loggers.Debug.Printf("[%s] connection from %s closed - %s",
				args.spec.Name, args.src.RemoteAddr(), reason)
		}
	}
}
