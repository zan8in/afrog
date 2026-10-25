package portscan

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// 存活主机结果行与 port-scan / web-probe 同一语法：序号 + [alive] + 目标 + 方括号属性。
func TestFormatAliveHost(t *testing.T) {
	strip := func(s string) string { return ansiRe.ReplaceAllString(s, "") }

	cases := []struct {
		seq   int
		host  string
		proto string
		want  string
	}{
		{1, "127.0.0.1", "icmp", "001 [alive] 127.0.0.1 [icmp]"},
		{12, "example.com", "tcp", "012 [alive] example.com [tcp]"},
		{3, "10.0.0.9", "", "003 [alive] 10.0.0.9"},
		{0, "10.0.0.9", "ping", "[alive] 10.0.0.9 [ping]"}, // n<=0 退化为不带序号的普通结果行
	}
	for _, tc := range cases {
		if got := strip(formatAliveHost(tc.seq, tc.host, tc.proto)); got != tc.want {
			t.Fatalf("formatAliveHost(%d,%q,%q)=%q，期望 %q", tc.seq, tc.host, tc.proto, got, tc.want)
		}
	}
}

// 存活行是「结果」而非过程日志：门控关闭时既不出行，也不该占用序号。
func TestPrintAliveHostGatedOff(t *testing.T) {
	opts := DefaultOptions()
	opts.Quiet = true
	opts.LogDiscoveredHosts = false
	opts.Debug = false

	printAliveHost("10.0.0.1", "icmp", opts)

	if got := atomic.LoadUint64(&opts.aliveSeq); got != 0 {
		t.Fatalf("被门控关闭时不该占用序号，实际 %d", got)
	}
}

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

	ok, info := sc.verifyPort(ctx, "127.0.0.1", port)
	if !ok {
		t.Fatalf("expected verify ok")
	}
	if info.Banner == "" {
		t.Fatalf("expected banner")
	}

	<-done
}
