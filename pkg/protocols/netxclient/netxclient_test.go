package netxclient

import (
	"net"
	"testing"
	"time"
)

func TestUnescapeCommon(t *testing.T) {
	got := unescapeCommon(`\\r\\n`)
	if got != "\r\n" {
		t.Fatalf("expected CRLF, got %q", got)
	}
}

func TestConnSessionReceiveUntil(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = c.Write([]byte("hello\r\nworld\r\n"))
		_ = c.Close()
	}()

	vars := map[string]any{}
	sess, err := NewConnSession(ln.Addr().String(), Config{Network: "tcp", ReadTimeout: time.Second}, vars)
	if err != nil {
		t.Fatalf("NewConnSession: %v", err)
	}
	defer sess.Close()

	data, err := sess.ReceiveUntil(1024, time.Second, `\r\n`)
	if err != nil {
		t.Fatalf("ReceiveUntil: %v", err)
	}
	if string(data) != "hello\r\n" {
		t.Fatalf("expected %q, got %q", "hello\r\n", string(data))
	}

	<-serverDone
}
