package js

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startFakeSSHServer 启动一个最小服务端：连接建立后立即发送指定的 SSH 标识串。
func startFakeSSHServer(t *testing.T, banner string) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner + "\r\n"))
				// 保持连接短暂存活，等待客户端读取
				buf := make([]byte, 128)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestExecuteSSHInfoMode(t *testing.T) {
	host, port := startFakeSSHServer(t, "SSH-2.0-Serv-U_15.2.3.742")

	vars := map[string]any{}
	code := `
		var m = require("afrog/ssh");
		var c = m.SSHClient();
		var info = c.ConnectSSHInfoMode(Host, Port);
		Export(info.ServerID.Raw);
	`
	args := map[string]any{"Host": host, "Port": strconv.Itoa(port)}

	if err := Execute(nil, "", code, "", args, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, _ := vars["response_text"].(string)
	if got != "SSH-2.0-Serv-U_15.2.3.742" {
		t.Fatalf("unexpected response_text: %q", got)
	}
	if !strings.Contains(got, "SSH-2.0-Serv-U") {
		t.Fatalf("banner mismatch: %q", got)
	}
}

func TestExecutePreConditionSkip(t *testing.T) {
	// 未监听的端口，pre-condition 为假，code 不应执行
	vars := map[string]any{}
	code := `Export("should-not-run")`
	pre := `isPortOpen(Host, Port)`
	args := map[string]any{"Host": "127.0.0.1", "Port": "1"}

	if err := Execute(nil, "", code, pre, args, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "" {
		t.Fatalf("expected empty response when pre-condition false, got %q", got)
	}
}

func TestExecutePreConditionPass(t *testing.T) {
	host, port := startFakeSSHServer(t, "SSH-2.0-OpenSSH_9.0")

	vars := map[string]any{}
	code := `Export("ran")`
	pre := `isPortOpen(Host, Port)`
	args := map[string]any{"Host": host, "Port": strconv.Itoa(port)}

	if err := Execute(nil, "", code, pre, args, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "ran" {
		t.Fatalf("expected code to run, got %q", got)
	}
}

func TestExecuteToJSON(t *testing.T) {
	vars := map[string]any{}
	code := `
		var obj = { name: "afrog", nested: { ok: true } };
		Export(to_json(obj));
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, _ := vars["response_text"].(string)
	if !strings.Contains(got, `"name":"afrog"`) {
		t.Fatalf("unexpected json: %q", got)
	}
}

func TestExecuteNetModule(t *testing.T) {
	host, port := startFakeSSHServer(t, "SSH-2.0-OpenSSH_9.6")

	vars := map[string]any{}
	code := `
		var net = require("afrog/net");
		var c = net.TCPClient();
		c.Connect(Host, Port);
		var banner = c.RecvUntil("\r\n");
		c.Close();
		Export(banner);
	`
	args := map[string]any{"Host": host, "Port": strconv.Itoa(port)}

	if err := Execute(nil, "", code, "", args, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, _ := vars["response_text"].(string)
	// RecvUntil 与 afrog tcp read-until 语义一致：返回内容包含分隔符
	if got != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("unexpected net banner: %q", got)
	}
}

func TestExecuteContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	vars := map[string]any{}
	start := time.Now()
	err := Execute(ctx, "", `while (true) {}`, "", nil, vars, 0)
	if err == nil {
		t.Fatalf("expected error from cancelled script")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("script was not interrupted promptly: %v", elapsed)
	}
}

func TestExecuteTimeoutCap(t *testing.T) {
	vars := map[string]any{}
	start := time.Now()
	err := Execute(nil, "", `while (true) {}`, "", nil, vars, 200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error from timed out script")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("maxTimeout not enforced promptly: %v", elapsed)
	}
}
