package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Sink commands: the first byte a client sends through the proxy.
const (
	cmdEcho     = 'E' // echo everything back (idle tunnels, RTT probes)
	cmdDownload = 'D' // write as fast as possible
	cmdPaced    = 'P' // + 8-byte big-endian rate in bytes/s: write at that rate
	cmdUpload   = 'U' // read and discard
	cmdRequest  = 'R' // answer replySize bytes, then close (the sink closes first)
)

const (
	replySize = 64
	chunkSize = 32 * 1024
)

func cmdSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	cfg := fs.String("cfg", "/cfg", "directory with cert.pem and key.pem")
	fs.Parse(args)
	cert, err := tls.LoadX509KeyPair(filepath.Join(*cfg, "cert.pem"), filepath.Join(*cfg, "key.pem"))
	if err != nil {
		return err
	}
	tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", sinkPort))
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	tlsLn, err := tls.Listen("tcp", fmt.Sprintf(":%d", sinkTLS), tlsConf)
	if err != nil {
		return err
	}
	// The REALITY target: a TLS 1.3 server (h2, http/1.1) that only completes
	// handshakes. A REALITY server contacts it on every connection.
	targetLn, err := tls.Listen("tcp", fmt.Sprintf(":%d", targetPort), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return err
	}
	go serve(tcpLn, func(c net.Conn) { handleSink(c, false) })
	go serve(tlsLn, handleSinkTLS)
	go serve(targetLn, func(c net.Conn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		if err := c.(*tls.Conn).Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, c)
	})
	fmt.Fprintf(os.Stderr, "sink: tcp :%d, tls :%d, reality target :%d\n", sinkPort, sinkTLS, targetPort)
	select {}
}

func serve(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go h(c)
	}
}

var junk = func() []byte {
	b := make([]byte, chunkSize)
	rand.Read(b) // incompressible, though nothing here compresses
	return b
}()

// sinkReady is the byte the TLS sink writes after its handshake, and the
// acknowledgement of an upload command on it.
const sinkReady = 'K'

// handleSinkTLS serves the inner-TLS variant (reality-tlsin). Xray's Vision
// client switches a stream's upload to direct copy only when one of its
// reads from the local socket holds nothing but whole TLS application-data
// records. The bench client's writes are kept apart so that this happens on
// every stream, not at random: the sink writes sinkReady once its handshake
// is done, which the client waits for before it sends the command (so the
// client's Finished flight and the command record are not read together),
// and acknowledges an upload command with sinkReady before the bulk data
// (so the command record is read alone, and Vision goes direct with it).
func handleSinkTLS(c net.Conn) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte{sinkReady}); err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	handleSink(c, true)
}

func handleSink(c net.Conn, ack bool) {
	defer c.Close()
	var cmd [1]byte
	if _, err := io.ReadFull(c, cmd[:]); err != nil {
		return
	}
	switch cmd[0] {
	case cmdEcho:
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	case cmdDownload:
		for {
			if _, err := c.Write(junk); err != nil {
				return
			}
		}
	case cmdPaced:
		var r [8]byte
		if _, err := io.ReadFull(c, r[:]); err != nil {
			return
		}
		pacedWrite(c, int64(binary.BigEndian.Uint64(r[:])), nil)
	case cmdUpload:
		if ack {
			if _, err := c.Write([]byte{sinkReady}); err != nil {
				return
			}
		}
		io.Copy(io.Discard, c)
	case cmdRequest:
		var reply [replySize]byte
		c.Write(reply[:])
	}
}

// pacedWrite writes chunks to w at rate bytes/s until a write fails or stop
// is closed. counter, if set, receives the bytes written.
func pacedWrite(w io.Writer, rate int64, stop <-chan struct{}) {
	const chunk = 16 * 1024
	start := time.Now()
	var sent int64
	for {
		if stop != nil {
			select {
			case <-stop:
				return
			default:
			}
		}
		due := start.Add(time.Duration(float64(sent) / float64(rate) * float64(time.Second)))
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		n, err := w.Write(junk[:chunk])
		sent += int64(n)
		if err != nil {
			return
		}
	}
}
