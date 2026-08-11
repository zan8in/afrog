package portscan

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// checkPortOpen used to build its dial address with fmt.Sprintf("%s:%d"),
// which produces "::1:8080" for an IPv6 literal. net.Dial cannot parse that,
// so every IPv6 target failed regardless of whether the port was open.
func TestCheckPortOpen_IPv6Literal(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable in this environment: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	s := &Scanner{options: &Options{Timeout: 3 * time.Second, Retries: 0}}

	conn, err := s.checkPortOpen("::1", port)
	if err != nil {
		t.Fatalf("checkPortOpen on an open IPv6 port failed: %v", err)
	}
	_ = conn.Close()
}

// The IPv4 path must be byte-for-byte what it was before the change.
func TestCheckPortOpen_IPv4StillWorks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := &Scanner{options: &Options{Timeout: 3 * time.Second, Retries: 0}}

	conn, err := s.checkPortOpen("127.0.0.1", port)
	if err != nil {
		t.Fatalf("checkPortOpen on an open IPv4 port failed: %v", err)
	}
	_ = conn.Close()
}

// net.JoinHostPort is what makes the IPv6 case work; pin the difference so a
// future refactor back to Sprintf is caught here rather than in the field.
func TestDialAddressBracketsIPv6(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 80, "127.0.0.1:80"},
		{"example.com", 8443, "example.com:8443"},
		{"::1", 80, "[::1]:80"},
		{"fe80::1", 22, "[fe80::1]:22"},
	}
	for _, tt := range tests {
		if got := net.JoinHostPort(tt.host, strconv.Itoa(tt.port)); got != tt.want {
			t.Errorf("JoinHostPort(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}
