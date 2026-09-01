// Package clamav is a minimal clamd client for the optional upload malware
// scan. It speaks the clamd INSTREAM protocol directly over TCP (the native
// interface every ClamAV deployment exposes), so no extra dependency or REST
// wrapper is needed. The scan is a deployment seam: services call Scan only
// when an endpoint is configured, and skip it entirely otherwise.
package clamav

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// Verdict is the scan outcome for one payload.
type Verdict struct {
	// Clean is true when clamd answered "stream: OK".
	Clean bool
	// Signature is the matched malware signature name when not clean.
	Signature string
}

// dialTimeout bounds the connection attempt; scanTimeout bounds the whole
// scan exchange (clamd applies its own internal limits as well).
const (
	dialTimeout = 5 * time.Second
	scanTimeout = 60 * time.Second
)

// chunkSize is the INSTREAM chunk payload size.
const chunkSize = 1 << 15 // 32 KiB

// Scan streams data to clamd at addr (host:port) using the INSTREAM command
// and returns its verdict. Any transport or protocol failure returns an error
// — the caller decides whether that fails the request or degrades gracefully.
func Scan(ctx context.Context, addr string, data []byte) (Verdict, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Verdict{}, fmt.Errorf("clamav: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(scanTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Verdict{}, fmt.Errorf("clamav: set deadline: %w", err)
	}

	// zINSTREAM: null-terminated command, then length-prefixed chunks, then a
	// zero-length chunk to terminate.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return Verdict{}, fmt.Errorf("clamav: send command: %w", err)
	}
	var size [4]byte
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		binary.BigEndian.PutUint32(size[:], uint32(end-off))
		if _, err := conn.Write(size[:]); err != nil {
			return Verdict{}, fmt.Errorf("clamav: send chunk header: %w", err)
		}
		if _, err := conn.Write(data[off:end]); err != nil {
			return Verdict{}, fmt.Errorf("clamav: send chunk: %w", err)
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	if _, err := conn.Write(size[:]); err != nil {
		return Verdict{}, fmt.Errorf("clamav: terminate stream: %w", err)
	}

	// One reply line, null- (z-mode) terminated: "stream: OK" or
	// "stream: <signature> FOUND".
	reply := make([]byte, 0, 128)
	buf := make([]byte, 128)
	for {
		n, err := conn.Read(buf)
		reply = append(reply, buf[:n]...)
		if idx := strings.IndexByte(string(reply), 0); idx >= 0 {
			reply = reply[:idx]

			break
		}
		if err != nil {
			return Verdict{}, fmt.Errorf("clamav: read reply: %w", err)
		}
	}

	line := strings.TrimSpace(string(reply))
	switch {
	case strings.HasSuffix(line, "OK"):
		return Verdict{Clean: true}, nil
	case strings.HasSuffix(line, "FOUND"):
		sig := strings.TrimSuffix(strings.TrimPrefix(line, "stream:"), "FOUND")

		return Verdict{Clean: false, Signature: strings.TrimSpace(sig)}, nil
	default:
		return Verdict{}, fmt.Errorf("clamav: unexpected reply %q", line)
	}
}
