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
	// YAML 双引号 "\r\n" 解析后本身就是真实 CRLF，必须原样保留
	if got := unescapeCommon("\r\n"); got != "\r\n" {
		t.Fatalf("expected raw CRLF preserved, got %q", got)
	}
	// 分隔符的尾部空格有语义："220 " 不能退化成 "220"
	if got := unescapeCommon("220 "); got != "220 " {
		t.Fatalf("expected trailing space preserved, got %q", got)
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

// 多行 banner 场景：分隔符里带真实空白（YAML 双引号写法）时，
// 必须对齐到最后一行并在该处截断，不能退化成整块读取。
func TestConnSessionReceiveUntilWhitespaceDelimiter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = c.Write([]byte("220-FileZilla Server ready\r\n220 Ready for new user.\r\n"))
		_ = c.Close()
	}()

	sess, err := NewConnSession(ln.Addr().String(), Config{Network: "tcp", ReadTimeout: time.Second}, map[string]any{})
	if err != nil {
		t.Fatalf("NewConnSession: %v", err)
	}
	defer sess.Close()

	data, err := sess.ReceiveUntil(4096, time.Second, "220 ")
	if err != nil {
		t.Fatalf("ReceiveUntil: %v", err)
	}
	if string(data) != "220-FileZilla Server ready\r\n220 " {
		t.Fatalf("expected banner aligned at final \"220 \" line, got %q", string(data))
	}
}
