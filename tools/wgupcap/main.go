package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	appName = "wgupcap"

	usage = `SYNOPSIS

  ` + appName + ` [options] [PCAP-OUTPUT-PATH]

DESCRIPTION
  ` + appName + ` connects to a wgu TappedDevice listener and generates
  a pcap stream that can be parsed by tools like tcpdump and Wirshark.


EXAMPLES
  Capture using tcpdump: 
    $ wgupcap /usr/local/etc/wgu/tap.sock | tcpdump -r -

  Capture using Wireshark on macOS:
    $ wgupcap ~/.wgu/tap.sock \
       | /Applications/Wireshark.app/Contents/MacOS/Wireshark -ki -  

OPTIONS
`

	helpArg       = "h"
	protoArg      = "p"
	pcapOutputArg = "o"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	help := flag.Bool(
		helpArg,
		false,
		"Display this information")

	proto := flag.String(
		protoArg,
		"unix",
		"The socket protocol to use")

	pcapOutputPath := flag.String(
		pcapOutputArg,
		"-",
		"Where to write the capture to (use '-' for stdout)")

	flag.Parse()

	if *help {
		out := os.Stderr

		info, _ := os.Stdout.Stat()
		if info != nil && info.Mode()&os.ModeNamedPipe != 0 {
			out = os.Stdout

			flag.CommandLine.SetOutput(os.Stdout)
		}

		out.WriteString(usage)

		flag.PrintDefaults()

		os.Exit(1)
	}

	packetsSocketAddr := flag.Arg(0)

	if packetsSocketAddr == "" {
		return errors.New("please specify an address to capture from")
	}

	if flag.NArg() > 1 {
		return errors.New("please specify only one socket to capture from" +
			" - more than one non-flag argument was provided")
	}

	var pcapOutput io.Writer

	switch *pcapOutputPath {
	case "":
		return errors.New("pcap output path is an empty string")
	case "-":
		pcapOutput = os.Stdout
	default:
		file, err := os.OpenFile(*pcapOutputPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()

		pcapOutput = file
	}

	conn, err := net.Dial(*proto, packetsSocketAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to tap socket %q - %q - %w",
			*proto, packetsSocketAddr, err)
	}
	defer conn.Close()

	pcapWriter := pcapgo.NewWriter(pcapOutput)

	reader := bufio.NewReader(conn)

	msgBuf := make([]byte, uint16(0xffff))

	// From https://www.tcpdump.org/linktypes/LINKTYPE_RAW.html:
	//
	//   LINKTYPE_RAW - Packets are IPv4 or IPv6 datagrams;
	//   the packet begins with an IPv4 or IPv6 header, with
	//   theversion field of the header indicating whether
	//   it's an IPv4 or IPv6 packet.
	pcapWriter.WriteFileHeader(0xffff, layers.LinkTypeRaw)

	for {
		_, err := reader.Read(msgBuf[0:2])
		if err != nil {
			return err
		}

		packetSize := binary.LittleEndian.Uint16(msgBuf[0:2])

		_, err = reader.Read(msgBuf[0:packetSize])
		if err != nil {
			return err
		}

		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: int(packetSize),
			Length:        int(packetSize),
		}, msgBuf[0:packetSize])
		if err != nil {
			return fmt.Errorf("failed to write packet to pcap writer - %w", err)
		}
	}
}
