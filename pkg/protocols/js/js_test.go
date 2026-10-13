package js

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
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

func TestExecuteExportAs(t *testing.T) {
	vars := map[string]any{}
	code := `
		ExportAs("banner", "SSH-2.0-OpenSSH_9.6");
		ExportAs("code", 220);
		Export("done");
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["banner"].(string); got != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("unexpected banner: %#v", vars["banner"])
	}
	if got, _ := vars["code"].(int64); got != 220 {
		t.Fatalf("unexpected code: %#v", vars["code"])
	}
	if got, _ := vars["response_text"].(string); got != "done" {
		t.Fatalf("unexpected response_text: %q", got)
	}
}

func TestExecuteExportAsInvalidKey(t *testing.T) {
	vars := map[string]any{}
	if err := Execute(nil, "", `ExportAs("bad-key", 1)`, "", nil, vars, 0); err == nil {
		t.Fatalf("expected error for invalid ExportAs key")
	}
}

func TestExecuteContextCancelInterruptsNetRead(t *testing.T) {
	// 服务端接受连接但长时间不发数据，客户端的 Recv 会阻塞；
	// ctx 取消后应立刻中断，而不是等到模块级 SetTimeout 超时。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())

	vars := map[string]any{}
	code := `
		var net = require("afrog/net");
		var c = net.TCPClient();
		c.SetTimeout(10);
		c.Connect(Host, Port);
		try { c.Recv(64); } catch (e) {}
		c.Close();
		Export("finished");
	`
	args := map[string]any{"Host": "127.0.0.1", "Port": strconv.Itoa(addr.Port)}

	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_ = Execute(ctx, "", code, "", args, vars, 0)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("blocked net read not interrupted by ctx cancel: %v", elapsed)
	}
}

func TestNetConnectNoThrowOnFailure(t *testing.T) {
	// 连接失败不应抛异常：Connect 返回 false，原因由 LastError() 给出
	vars := map[string]any{}
	code := `
		var net = require("afrog/net");
		var c = net.TCPClient();
		c.SetTimeout(1);
		var ok = c.Connect("127.0.0.1", 1);
		Export(ok ? "true" : "false");
		ExportAs("lasterr", c.LastError());
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "false" {
		t.Fatalf("expected connect=false, got %q", got)
	}
	if got, _ := vars["lasterr"].(string); got == "" {
		t.Fatalf("expected LastError to be populated")
	}
}

func TestExecStateCloseAll(t *testing.T) {
	// 未显式关闭的资源在脚本结束时兜底释放；已显式释放的不重复处理
	s := &execState{}
	closed := 0
	s.track("a", func() { closed++ })
	s.track("b", func() { closed++ })
	s.untrack("a")
	s.closeAll()

	if closed != 1 {
		t.Fatalf("expected 1 cleanup, got %d", closed)
	}
	// 再次调用不应重复释放
	s.closeAll()
	if closed != 1 {
		t.Fatalf("closeAll should be idempotent, got %d", closed)
	}
}

func TestExecuteStructsModule(t *testing.T) {
	vars := map[string]any{}
	code := `
		var structs = require("afrog/structs");
		var packed = structs.Pack(">HI", 258, 65536);
		var vals = structs.Unpack(">HI", packed);
		var le = structs.Unpack("<H", structs.Pack("<H", 258))[0];
		Export(vals[0] + "," + vals[1] + "," + structs.CalcSize(">HI") + "," + le);
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "258,65536,6,258" {
		t.Fatalf("unexpected structs result: %q", got)
	}
}

func TestStructsPackBytes(t *testing.T) {
	// 直接校验打包出的字节序列：>H 258 -> 01 02，>I 65536 -> 00 01 00 00
	b, err := structPack(">HI", []any{int64(258), int64(65536)})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if got := hex.EncodeToString(b); got != "010200010000" {
		t.Fatalf("unexpected bytes: %s", got)
	}

	// 's' 定长字符串补零
	b2, err := structPack(">4s", []any{"ab"})
	if err != nil {
		t.Fatalf("pack s: %v", err)
	}
	if got := hex.EncodeToString(b2); got != "61620000" {
		t.Fatalf("unexpected 4s bytes: %s", got)
	}

	// 值个数不匹配应报错
	if _, err := structPack(">HI", []any{int64(1)}); err == nil {
		t.Fatalf("expected error for value count mismatch")
	}
	// 数据不足应报错
	if _, err := structUnpack(">I", []byte{1, 2}); err == nil {
		t.Fatalf("expected error for short data")
	}
}

func TestExecuteBytesModule(t *testing.T) {
	vars := map[string]any{}
	code := `
		var bytes = require("afrog/bytes");
		var b = bytes.NewBuffer("A");
		b.WriteString("B").WriteHex("0x43");
		b.WriteUint8(68);
		b.WriteUint16(0x0102);
		Export(b.Hex() + "|" + b.Len());
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "414243440102|6" {
		t.Fatalf("unexpected bytes result: %q", got)
	}
}

func TestExecuteUnknownModuleThrows(t *testing.T) {
	vars := map[string]any{}
	if err := Execute(nil, "", `require("afrog/nope")`, "", nil, vars, 0); err == nil {
		t.Fatalf("expected error for unknown module")
	}
}

func TestExecuteModulePolicy(t *testing.T) {
	vars := map[string]any{}
	deny := func(name string, level capability.Level) bool { return false }
	if err := Execute(nil, "", `require("afrog/net")`, "", nil, vars, 0, deny); err == nil {
		t.Fatalf("expected error when module is denied by policy")
	}

	allow := func(name string, level capability.Level) bool { return true }
	if err := Execute(nil, "", `var net = require("afrog/net"); Export("ok")`, "", nil, vars, 0, allow); err != nil {
		t.Fatalf("expected allow policy to permit module, got %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "ok" {
		t.Fatalf("unexpected response_text: %q", got)
	}
}

// buildTestMySQLHandshake 构造一个 MySQL v10 握手包（含 4 字节包头）。
func buildTestMySQLHandshake(version string, threadID uint32, plugin string, salt []byte) []byte {
	var p []byte
	p = append(p, 0x0a) // protocol version
	p = append(p, []byte(version)...)
	p = append(p, 0x00)

	tid := make([]byte, 4)
	binary.LittleEndian.PutUint32(tid, threadID)
	p = append(p, tid...)

	part1 := make([]byte, 8)
	copy(part1, salt)
	p = append(p, part1...) // auth-plugin-data-part-1
	p = append(p, 0x00)     // filler

	capLow := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLow, uint16(mysqlClientProtocol41|mysqlClientSecureConnection))
	p = append(p, capLow...)
	p = append(p, 33)         // charset
	p = append(p, 0x02, 0x00) // status flags
	capHigh := make([]byte, 2)
	binary.LittleEndian.PutUint16(capHigh, uint16(mysqlClientPluginAuth>>16))
	p = append(p, capHigh...)          // capability upper: CLIENT_PLUGIN_AUTH
	p = append(p, byte(len(salt)+1))   // auth plugin data len
	p = append(p, make([]byte, 10)...) // reserved

	part2 := make([]byte, 13)
	if len(salt) > 8 {
		copy(part2, salt[8:])
	}
	p = append(p, part2...)
	p = append(p, []byte(plugin)...)
	p = append(p, 0x00)

	return mysqlBuildPacket(p, 0)
}

func TestParseMySQLHandshake(t *testing.T) {
	salt := []byte("abcdefghijklmnopqrst") // 20 字节
	raw := buildTestMySQLHandshake("8.0.35", 1234, "mysql_native_password", salt)

	hs, err := parseMySQLHandshake(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hs.Version != "8.0.35" {
		t.Fatalf("version = %q", hs.Version)
	}
	if hs.ThreadID != 1234 {
		t.Fatalf("threadID = %d", hs.ThreadID)
	}
	if hs.AuthPlugin != "mysql_native_password" {
		t.Fatalf("plugin = %q", hs.AuthPlugin)
	}
	if string(hs.Salt) != string(salt) {
		t.Fatalf("salt = %q, want %q", hs.Salt, salt)
	}
}

func TestMySQLNativePasswordToken(t *testing.T) {
	salt := []byte("abcdefghijklmnopqrst")
	if got := mysqlNativePasswordToken("", salt); len(got) != 0 {
		t.Fatalf("empty password should yield empty token, got %d bytes", len(got))
	}
	tok := mysqlNativePasswordToken("secret", salt)
	if len(tok) != 20 {
		t.Fatalf("token length = %d, want 20", len(tok))
	}
	// 相同输入必须稳定
	if again := mysqlNativePasswordToken("secret", salt); !bytes.Equal(tok, again) {
		t.Fatalf("token not deterministic")
	}
	// 密码不同则 token 不同
	if other := mysqlNativePasswordToken("secret2", salt); bytes.Equal(tok, other) {
		t.Fatalf("different passwords produced same token")
	}
}

func TestExecuteMySQLModuleOffline(t *testing.T) {
	// 连接失败不抛异常，Handshake 返回空版本，LastError 有值
	vars := map[string]any{}
	code := `
		var mysql = require("afrog/mysql");
		var c = mysql.MySQLClient();
		c.SetTimeout(1);
		var ok = c.Connect("127.0.0.1", 1);
		Export(ok ? "true" : "false");
		ExportAs("version", c.Handshake().Version);
		ExportAs("err", c.LastError());
	`
	if err := Execute(nil, "", code, "", nil, vars, 0); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := vars["response_text"].(string); got != "false" {
		t.Fatalf("expected connect=false, got %q", got)
	}
	if got, _ := vars["version"].(string); got != "" {
		t.Fatalf("expected empty version, got %q", got)
	}
	if got, _ := vars["err"].(string); got == "" {
		t.Fatalf("expected LastError to be populated")
	}
}

func TestMySQLReadLenEnc(t *testing.T) {
	cases := []struct {
		in      []byte
		want    uint64
		wantLen int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0xfc, 0x34, 0x12}, 0x1234, 3},
		{[]byte{0xfd, 0x56, 0x34, 0x12}, 0x123456, 4},
		{[]byte{0xfe, 1, 0, 0, 0, 0, 0, 0, 0}, 1, 9},
	}
	for _, tc := range cases {
		got, n, ok := readLenEncInt(tc.in, 0)
		if !ok || got != tc.want || n != tc.wantLen {
			t.Fatalf("readLenEncInt(%v) = (%d, %d, %v), want (%d, %d, true)", tc.in, got, n, ok, tc.want, tc.wantLen)
		}
	}
	if _, _, ok := readLenEncInt([]byte{0xfc, 0x01}, 0); ok {
		t.Fatalf("truncated lenenc int should fail")
	}
}

func TestMySQLReadLenEncString(t *testing.T) {
	v, n, isNull, ok := readLenEncString([]byte{0x03, 'a', 'b', 'c'}, 0)
	if !ok || isNull || v != "abc" || n != 4 {
		t.Fatalf("got (%q, %d, %v, %v)", v, n, isNull, ok)
	}
	// 0xfb 表示 NULL
	if _, n, isNull, ok := readLenEncString([]byte{0xfb}, 0); !ok || !isNull || n != 1 {
		t.Fatalf("expected NULL string")
	}
	if _, _, _, ok := readLenEncString([]byte{0x05, 'a'}, 0); ok {
		t.Fatalf("truncated string should fail")
	}
}

func TestMySQLOKAndErrPacket(t *testing.T) {
	affected, lastID, err := parseMySQLOKPacket([]byte{0x00, 0x02, 0x2a}) // affected=2, lastInsertID=42
	if err != nil || affected != 2 || lastID != 42 {
		t.Fatalf("OK packet parse: affected=%d lastID=%d err=%v", affected, lastID, err)
	}
	if _, _, err := parseMySQLOKPacket([]byte{0xff, 0x00, 0x00}); err == nil {
		t.Fatalf("expected error for non-OK packet")
	}

	errPkt := append([]byte{0xff, 0x28, 0x04}, []byte("#42000You have an error")...) // code 1064
	code, msg := parseMySQLErrPacket(errPkt)
	if code != 1064 {
		t.Fatalf("err code = %d, want 1064", code)
	}
	if msg != "You have an error" {
		t.Fatalf("err msg = %q", msg)
	}
}

func TestMySQLColumnNameAndEOF(t *testing.T) {
	var col []byte
	for _, s := range []string{"def", "information_schema", "", "", "version()"} {
		col = append(col, byte(len(s)))
		col = append(col, []byte(s)...)
	}
	col = append(col, make([]byte, 12)...) // charset/length/type/... 对解析无影响
	if got := parseMySQLColumnName(col); got != "version()" {
		t.Fatalf("column name = %q", got)
	}

	if !isMySQLEOFPacket([]byte{0xfe, 0x00, 0x00, 0x02, 0x00}) {
		t.Fatalf("expected EOF packet")
	}
	// 长度 >= 9 的 0xfe 是长度编码数据，不是 EOF
	if isMySQLEOFPacket(append([]byte{0xfe}, make([]byte, 9)...)) {
		t.Fatalf("long 0xfe packet is not EOF")
	}
}
