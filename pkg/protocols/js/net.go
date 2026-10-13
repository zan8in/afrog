package js

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/gologger"
)

// 模块级超时基准。实际取值与 afrog 全局 -timeout 取较小者，
// 使 javascript PoC 与 tcp/ssl PoC 的超时口径一致。
const (
	netDialBaseTimeout  = 3 * time.Second
	netReadBaseTimeout  = 6 * time.Second
	netWriteBaseTimeout = 3 * time.Second
	defaultNetReadSize  = 4096
)

// minTimeout 取 afrog 全局超时（-timeout）与模块基准值中的较小者。
func minTimeout(base time.Duration) time.Duration {
	if g := retryhttpclient.GetDefaultTimeout(); g > 0 && g < base {
		return g
	}
	return base
}

// tcpClient 是 afrog/net 模块暴露给 JS 的网络客户端，支持 tcp 与 tls。
//
// 约定：模块方法不抛异常。连接失败、读写超时等预期内错误会记录到
// LastError()，方法本身返回零值（false / 0 / ""）。只有用错 API 才抛异常。
//
// 用法：
//
//	var net = require("afrog/net");
//	var c = net.TCPClient();
//	if (!c.Connect(Host, Port)) { log(c.LastError()); }
//	var banner = c.RecvUntil("\r\n");
//	c.Close();
type tcpClient struct {
	state     *execState
	conn      net.Conn
	reader    *bufio.Reader
	timeout   time.Duration // SetTimeout 设置；0 表示取模块基准与全局超时中较小者
	readSize  int
	useTLS    bool
	stopWatch func()
	lastErr   error
}

func buildNetModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()
	if err := obj.Set("TCPClient", func() *tcpClient {
		return &tcpClient{state: state, readSize: defaultNetReadSize}
	}); err != nil {
		return nil, err
	}
	if err := obj.Set("TLSClient", func() *tcpClient {
		return &tcpClient{state: state, readSize: defaultNetReadSize, useTLS: true}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func (c *tcpClient) context() context.Context {
	if c.state != nil && c.state.ctx != nil {
		return c.state.ctx
	}
	return context.Background()
}

func (c *tcpClient) setErr(err error) {
	if err == nil {
		return
	}
	c.lastErr = err
	gologger.Debug().Msgf("[JS] afrog/net: %v", err)
}

// LastError 返回最近一次方法的错误描述；无错误时返回空串。
func (c *tcpClient) LastError() string {
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

func (c *tcpClient) dialTimeout() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return minTimeout(netDialBaseTimeout)
}

func (c *tcpClient) readTimeout() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return minTimeout(netReadBaseTimeout)
}

func (c *tcpClient) writeTimeout() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return minTimeout(netWriteBaseTimeout)
}

// deadline 返回本次读写应使用的截止时间：取模块超时与 ctx 截止时间中较早者，
// 使网络 I/O 跟随扫描任务级超时。
func (c *tcpClient) deadline(d time.Duration) time.Time {
	t := time.Now().Add(d)
	if dl, ok := c.context().Deadline(); ok && dl.Before(t) {
		t = dl
	}
	return t
}

func (c *tcpClient) setReadDeadline() {
	if c.conn != nil {
		_ = c.conn.SetReadDeadline(c.deadline(c.readTimeout()))
	}
}

func (c *tcpClient) setWriteDeadline() {
	if c.conn != nil {
		_ = c.conn.SetWriteDeadline(c.deadline(c.writeTimeout()))
	}
}

// startWatch 在 ctx 取消时把连接 deadline 归零，从而中断阻塞中的读写。
// goja 的 Interrupt 无法抢占阻塞在原生调用里的脚本，这里补上这一层。
func (c *tcpClient) startWatch(conn net.Conn) {
	ctx := c.context()
	if ctx.Done() == nil {
		return
	}
	done := make(chan struct{})
	c.stopWatch = func() { close(done) }
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
}

func (c *tcpClient) stopWatching() {
	if c.stopWatch != nil {
		c.stopWatch()
		c.stopWatch = nil
	}
}

// closeConn 释放底层连接，可重复调用。
func (c *tcpClient) closeConn() {
	c.stopWatching()
	if c.conn == nil {
		return
	}
	_ = c.conn.Close()
	c.conn = nil
	c.reader = nil
}

func (c *tcpClient) sizeOf(fallback ...int) int {
	if len(fallback) > 0 && fallback[0] > 0 {
		return fallback[0]
	}
	if c.readSize > 0 {
		return c.readSize
	}
	return defaultNetReadSize
}

// SetTimeout 设置连接与读写的超时时间（秒）。
func (c *tcpClient) SetTimeout(sec int) {
	if sec > 0 {
		c.timeout = time.Duration(sec) * time.Second
	}
}

// SetReadSize 设置 Recv/RecvUntil 默认读取上限（字节）。
func (c *tcpClient) SetReadSize(n int) {
	if n > 0 {
		c.readSize = n
	}
}

// Connect 建立连接，成功返回 true。失败返回 false，原因见 LastError()。
func (c *tcpClient) Connect(host string, port any) bool {
	p, ok := toInt(port)
	if !ok || p <= 0 {
		c.setErr(fmt.Errorf("net: invalid port"))
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		c.setErr(fmt.Errorf("net: empty host"))
		return false
	}

	ctx := c.context()
	// 与 tcp/ssl PoC 一致：先过一次目标闸门（限速 + 跟随 ctx 取消）
	if err := retryhttpclient.WaitHostPort(ctx, host, strconv.Itoa(p)); err != nil {
		c.setErr(err)
		return false
	}

	addr := net.JoinHostPort(host, strconv.Itoa(p))
	conn, err := (&net.Dialer{Timeout: c.dialTimeout()}).DialContext(ctx, "tcp", addr)
	if err != nil {
		c.setErr(err)
		return false
	}
	if c.useTLS {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			c.setErr(err)
			return false
		}
		conn = tlsConn
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.lastErr = nil
	c.startWatch(conn)
	if c.state != nil {
		// 脚本若忘记 Close，由 Execute 结束时兜底释放
		c.state.track(c, c.closeConn)
	}
	return true
}

// Send 发送字符串数据，返回写入字节数；失败返回 0。
func (c *tcpClient) Send(data string) int {
	if c.conn == nil {
		c.setErr(fmt.Errorf("net: not connected"))
		return 0
	}
	c.setWriteDeadline()
	n, err := c.conn.Write([]byte(data))
	if err != nil {
		c.setErr(err)
		return 0
	}
	return n
}

// SendHex 发送十六进制字符串表示的二进制数据，返回写入字节数；失败返回 0。
func (c *tcpClient) SendHex(data string) int {
	decoded, err := hex.DecodeString(cleanHex(data))
	if err != nil {
		c.setErr(err)
		return 0
	}
	if c.conn == nil {
		c.setErr(fmt.Errorf("net: not connected"))
		return 0
	}
	c.setWriteDeadline()
	n, err := c.conn.Write(decoded)
	if err != nil {
		c.setErr(err)
		return 0
	}
	return n
}

// Recv 读取一次响应（最多 size 字节，缺省用 SetReadSize）。
// 失败或超时返回已读到的内容（可能为空串），原因见 LastError()。
func (c *tcpClient) Recv(size ...any) string {
	if c.reader == nil {
		c.setErr(fmt.Errorf("net: not connected"))
		return ""
	}
	n := c.sizeOf()
	if len(size) > 0 {
		if v, ok := toInt(size[0]); ok && v > 0 {
			n = v
		}
	}
	c.setReadDeadline()
	buf := make([]byte, n)
	m, err := c.reader.Read(buf)
	if err != nil {
		c.setErr(err)
	}
	return string(buf[:m])
}

// RecvUntil 持续读取直到遇到分隔符 delim（或读满 size / 超时），返回内容包含分隔符。
func (c *tcpClient) RecvUntil(delim string, size ...any) string {
	if c.reader == nil {
		c.setErr(fmt.Errorf("net: not connected"))
		return ""
	}
	maxSize := c.sizeOf()
	if len(size) > 0 {
		if v, ok := toInt(size[0]); ok && v > 0 {
			maxSize = v
		}
	}
	c.setReadDeadline()

	var sb strings.Builder
	for sb.Len() < maxSize {
		b, err := c.reader.ReadByte()
		if err != nil {
			c.setErr(err)
			break
		}
		sb.WriteByte(b)
		if delim != "" && strings.HasSuffix(sb.String(), delim) {
			break
		}
	}
	return sb.String()
}

// Close 关闭连接，已连接过并成功关闭返回 true。
func (c *tcpClient) Close() bool {
	if c.conn == nil {
		return false
	}
	c.closeConn()
	if c.state != nil {
		c.state.untrack(c)
	}
	return true
}

func init() {
	registerModule(moduleDef{name: "net", summary: "任意 TCP / TLS 读写", level: capability.Network, build: buildNetModule})
}
