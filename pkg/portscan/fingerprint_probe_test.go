package portscan

import (
	"net"
	"testing"
	"time"
)

// startTCPServer 起一个回环端口的服务端，handle 在每次 accept 后接管连接。
func startTCPServer(t *testing.T, handle func(net.Conn)) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		handle(conn)
	}()
	t.Cleanup(func() { <-done })
	return ln.Addr()
}

func dialForGrab(t *testing.T, addr net.Addr) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestGrabPassiveBanner 验证被动阶段能复用已建立的连接直接识别主动吐 banner 的服务。
func TestGrabPassiveBanner(t *testing.T) {
	addr := startTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"))
		// 保持连接打开，让客户端的读取窗口自然结束。
		time.Sleep(400 * time.Millisecond)
	})

	fp := newTestFingerprinter(t, "")
	g := NewGrabber(fp, time.Second, false)

	info := g.Grab(dialForGrab(t, addr), "127.0.0.1", 22)
	if info.Service != "ssh" {
		t.Fatalf("Service = %q, want ssh", info.Service)
	}
	if info.Version != "9.6p1" {
		t.Errorf("Version = %q, want 9.6p1", info.Version)
	}
	if info.Confidence != ConfidenceCertain {
		t.Errorf("Confidence = %s, want certain", info.Confidence)
	}
}

// TestGrabActiveProbesOnlyWhenEnabled 验证主动探针的开关语义：
// 关闭时只能靠端口先验推测，开启后才能通过主动 payload 拿到实证。
func TestGrabActiveProbesOnlyWhenEnabled(t *testing.T) {
	echoPong := func(conn net.Conn) {
		buf := make([]byte, 512)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
			if _, err := conn.Write([]byte("+PONG\r\n")); err != nil {
				return
			}
		}
	}

	t.Run("disabled", func(t *testing.T) {
		addr := startTCPServer(t, echoPong)
		fp := newTestFingerprinter(t, "")
		info := NewGrabber(fp, time.Second, false).Grab(dialForGrab(t, addr), "127.0.0.1", 6379)
		if info.Service != "redis" {
			t.Errorf("Service = %q, want redis (from the port prior)", info.Service)
		}
		if info.Confidence != ConfidencePortOnly {
			t.Errorf("Confidence = %s, want port", info.Confidence)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		addr := startTCPServer(t, echoPong)
		fp := newTestFingerprinter(t, "")
		info := NewGrabber(fp, time.Second, true).Grab(dialForGrab(t, addr), "127.0.0.1", 6379)
		if info.Service != "redis" {
			t.Fatalf("Service = %q, want redis", info.Service)
		}
		if info.Confidence != ConfidenceCertain {
			t.Errorf("Confidence = %s, want certain", info.Confidence)
		}
		if info.RuleID != "redis" {
			t.Errorf("RuleID = %q, want redis", info.RuleID)
		}
	})
}
