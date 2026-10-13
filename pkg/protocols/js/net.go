package js

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

const defaultNetTimeout = 10 * time.Second

// tcpClient 是 afrog/net 模块暴露给 JS 的网络客户端，支持 tcp 与 tls。
// 用法：
//
//	var net = require("afrog/net");
//	var c = net.TCPClient();
//	c.Connect(Host, Port);
//	var banner = c.RecvUntil("\r\n");
//	c.Close();
type tcpClient struct {
	conn     net.Conn
	reader   *bufio.Reader
	timeout  time.Duration
	readSize int
	useTLS   bool
}

func buildNetModule(vm *goja.Runtime) (goja.Value, error) {
	obj := vm.NewObject()
	if err := obj.Set("TCPClient", func() *tcpClient {
		return &tcpClient{timeout: defaultNetTimeout, readSize: 4096}
	}); err != nil {
		return nil, err
	}
	if err := obj.Set("TLSClient", func() *tcpClient {
		return &tcpClient{timeout: defaultNetTimeout, readSize: 4096, useTLS: true}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func (c *tcpClient) timeoutOf() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return defaultNetTimeout
}

func (c *tcpClient) sizeOf(fallback ...int) int {
	if len(fallback) > 0 && fallback[0] > 0 {
		return fallback[0]
	}
	if c.readSize > 0 {
		return c.readSize
	}
	return 4096
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

// Connect 建立连接，返回是否成功。
func (c *tcpClient) Connect(host string, port any) (bool, error) {
	p, ok := toInt(port)
	if !ok || p <= 0 {
		return false, fmt.Errorf("net: invalid port")
	}
	addr := net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(p))
	dialer := &net.Dialer{Timeout: c.timeoutOf()}

	var (
		conn net.Conn
		err  error
	)
	if c.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return false, err
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return true, nil
}

// Send 发送字符串数据，返回写入字节数。
func (c *tcpClient) Send(data string) (int, error) {
	if c.conn == nil {
		return 0, fmt.Errorf("net: not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeoutOf()))
	return c.conn.Write([]byte(data))
}

// SendHex 发送十六进制字符串表示的二进制数据，返回写入字节数。
func (c *tcpClient) SendHex(data string) (int, error) {
	clean := strings.NewReplacer("0x", "", " ", "", "\r", "", "\n", "", "\t", "").Replace(strings.TrimSpace(data))
	if len(clean)%2 == 1 {
		clean = "0" + clean
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return 0, err
	}
	if c.conn == nil {
		return 0, fmt.Errorf("net: not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeoutOf()))
	return c.conn.Write(decoded)
}

// Recv 读取一次响应（最多 size 字节，缺省用 SetReadSize）。
func (c *tcpClient) Recv(size ...any) (string, error) {
	if c.reader == nil {
		return "", fmt.Errorf("net: not connected")
	}
	n := c.sizeOf()
	if len(size) > 0 {
		if v, ok := toInt(size[0]); ok && v > 0 {
			n = v
		}
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(c.timeoutOf()))
	buf := make([]byte, n)
	m, err := c.reader.Read(buf)
	if err != nil && m == 0 {
		return "", err
	}
	return string(buf[:m]), nil
}

// RecvUntil 持续读取直到遇到分隔符 delim（或读满 size / 超时）。
func (c *tcpClient) RecvUntil(delim string, size ...any) (string, error) {
	if c.reader == nil {
		return "", fmt.Errorf("net: not connected")
	}
	maxSize := c.sizeOf()
	if len(size) > 0 {
		if v, ok := toInt(size[0]); ok && v > 0 {
			maxSize = v
		}
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(c.timeoutOf()))

	var sb strings.Builder
	for sb.Len() < maxSize {
		b, err := c.reader.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		sb.WriteByte(b)
		if delim != "" && strings.HasSuffix(sb.String(), delim) {
			break
		}
	}
	return sb.String(), nil
}

// Close 关闭连接。
func (c *tcpClient) Close() (bool, error) {
	if c.conn == nil {
		return false, nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.reader = nil
	return err == nil, err
}
