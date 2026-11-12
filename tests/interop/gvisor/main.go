// Development-only TCP peer. This program has no host networking entry point:
// complete IP packets travel over length-prefixed stdin/stdout, not a TUN or
// socket. It is neither linked into nor distributed with gp-proxy.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const mtu = 1400

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer s.Wait()
	defer s.Close()
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min: 4096, Default: 16 * 1024, Max: 16 * 1024,
	}); err != nil {
		return fmt.Errorf("memory TCP receive limit: %s", err)
	}
	autotune := tcpip.TCPModerateReceiveBufferOption(false)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &autotune); err != nil {
		return fmt.Errorf("memory TCP receive tuning: %s", err)
	}
	// This NIC is a gVisor memory object attached only to a Go channel.
	ep := channel.New(64, mtu, "")
	defer ep.Close()
	if err := s.CreateNIC(1, ep); err != nil {
		return fmt.Errorf("memory NIC: %s", err)
	}
	address := tcpip.AddrFrom4([4]byte{10, 77, 0, 1})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: address, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("memory address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: address, Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	defer listener.Close()
	var opened, closed, bytes, failures atomic.Uint64
	var workers sync.WaitGroup
	// The test admits <= 8 connections. The peer also enforces its own bound.
	slots := make(chan struct{}, 8)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				failures.Add(1)
				conn.Close()
				continue
			}
			opened.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots; closed.Add(1); conn.Close() }()
				conn.SetDeadline(time.Now().Add(80 * time.Second))
				// Force actual receive-window closure before draining it. The
				// Rust test counts zero-window packets in both directions.
				time.Sleep(350 * time.Millisecond)
				n, err := io.CopyBuffer(conn, conn, make([]byte, 16*1024))
				bytes.Add(uint64(n))
				if err != nil {
					failures.Add(1)
					return
				}
				if err := conn.(*gonet.TCPConn).CloseWrite(); err != nil {
					failures.Add(1)
				}
			}()
		}
	}()
	// Ready sentinel, written before the packet writer starts.
	if err := binary.Write(os.Stdout, binary.BigEndian, uint16(0)); err != nil {
		return err
	}
	writerDone := make(chan error, 1)
	go func() {
		for {
			packet := ep.ReadContext(ctx)
			if packet == nil {
				writerDone <- nil
				return
			}
			view := packet.ToView()
			packet.DecRef()
			payload := view.AsSlice()
			if len(payload) < 20 || len(payload) > mtu {
				view.Release()
				writerDone <- fmt.Errorf("invalid outbound memory IP length")
				return
			}
			err := binary.Write(os.Stdout, binary.BigEndian, uint16(len(payload)))
			if err == nil {
				_, err = os.Stdout.Write(payload)
			}
			view.Release()
			if err != nil {
				writerDone <- err
				return
			}
		}
	}()
	inputDone := make(chan error, 1)
	go func() {
		for {
			var length uint16
			if err := binary.Read(os.Stdin, binary.BigEndian, &length); err != nil {
				if err == io.EOF {
					err = nil
				}
				inputDone <- err
				return
			}
			if length < 20 || length > mtu {
				inputDone <- fmt.Errorf("invalid inbound memory IP length")
				return
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(os.Stdin, payload); err != nil {
				inputDone <- err
				return
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
			ep.InjectInbound(ipv4.ProtocolNumber, packet)
			packet.DecRef()
		}
	}()
	select {
	case err = <-inputDone:
	case err = <-writerDone:
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()
	listener.Close()
	s.Close()
	<-acceptDone
	workers.Wait()
	if outputErr := json.NewEncoder(os.Stderr).Encode(map[string]uint64{
		"opened": opened.Load(), "closed": closed.Load(), "echoed_bytes": bytes.Load(), "errors": failures.Load(),
	}); err == nil {
		err = outputErr
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
