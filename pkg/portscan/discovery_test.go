package portscan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestScanWithTCPDiscoveryTreatsConnRefusedAsAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	opts := DefaultOptions()
	opts.Targets = []string{"127.0.0.1", "127.0.0.2"}
	opts.Ports = portStr
	opts.Timeout = 200 * time.Millisecond
	opts.Retries = 0
	opts.RateLimit = 100
	opts.SkipDiscovery = false
	opts.DiscoveryMethod = "tcp"
	opts.Quiet = true
	opts.LogDiscoveredHosts = false

	found := make(chan struct{}, 1)
	opts.OnResult = func(r *ScanResult) {
		if r.Host == "127.0.0.1" && r.Port == port {
			select {
			case found <- struct{}{}:
			default:
			}
		}
	}

	sc, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sc.Scan(ctx); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	select {
	case <-found:
	default:
		t.Fatalf("expected open port result for 127.0.0.1:%d", port)
	}
}

func TestVerifyPortHTTPOnRandomPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()

	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	sc.options.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, banner := sc.verifyPort(ctx, "127.0.0.1", port)
	if !ok {
		t.Fatalf("expected verify ok")
	}
	if banner == "" {
		t.Fatalf("expected banner")
	}

	<-done
}
