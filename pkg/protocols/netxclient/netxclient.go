package netxclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"crypto/tls"
	"net"

	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/pins/netx"
)

type Config struct {
	Network      string
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	RetryDelay   time.Duration
	ReadSize     int
	MaxRetries   int
}

type NetClient struct {
	address string
	config  netx.Config
	netx    *netx.Client
}

type Session struct {
	address string
	config  netx.Config
	client  *netx.Client
}

type ConnSession struct {
	address string
	network string
	conn    net.Conn
	config  Config
}

func (nc *NetClient) Config() *netx.Config {
	return &nc.config
}

func NewNetClient(address string, conf Config) (*NetClient, error) {
	netxconf := netx.Config{}

	globalTimeout := retryhttpclient.GetDefaultTimeout()
	dialBase := 3 * time.Second
	writeBase := 3 * time.Second
	readBase := 6 * time.Second
	if _, port, ok := parseHostPort(address); ok && port == "445" {
		dialBase = 5 * time.Second
		writeBase = 5 * time.Second
		readBase = 10 * time.Second
	}

	dialDefault := minDuration(globalTimeout, dialBase)
	writeDefault := minDuration(globalTimeout, writeBase)
	readDefault := minDuration(globalTimeout, readBase)

	if conf.MaxRetries != 0 {
		netxconf.MaxRetries = conf.MaxRetries
	}

	if conf.Network != "" {
		netxconf.Network = conf.Network
	}

	if conf.DialTimeout != 0 {
		netxconf.DialTimeout = conf.DialTimeout
	} else {
		netxconf.DialTimeout = dialDefault
	}

	if conf.WriteTimeout != 0 {
		netxconf.WriteTimeout = conf.WriteTimeout
	} else {
		netxconf.WriteTimeout = writeDefault
	}

	if conf.ReadTimeout != 0 {
		netxconf.ReadTimeout = conf.ReadTimeout
	} else {
		netxconf.ReadTimeout = readDefault
	}

	if conf.RetryDelay != 0 {
		netxconf.RetryDelay = conf.RetryDelay
	}
	if conf.ReadSize != 0 {
		netxconf.ReadSize = conf.ReadSize
	} else {
		netxconf.ReadSize = 20480
	}

	return &NetClient{address: address, config: netxconf}, nil
}

func NewSession(address string, conf Config, variableMap map[string]any) (*Session, error) {
	netxconf := netx.Config{}
	address = setVariableMap(address, variableMap)

	globalTimeout := retryhttpclient.GetDefaultTimeout()
	dialBase := 3 * time.Second
	writeBase := 3 * time.Second
	readBase := 6 * time.Second
	if _, port, ok := parseHostPort(address); ok && port == "445" {
		dialBase = 5 * time.Second
		writeBase = 5 * time.Second
		readBase = 10 * time.Second
	}

	dialDefault := minDuration(globalTimeout, dialBase)
	writeDefault := minDuration(globalTimeout, writeBase)
	readDefault := minDuration(globalTimeout, readBase)

	if conf.MaxRetries != 0 {
		netxconf.MaxRetries = conf.MaxRetries
	}

	if conf.Network != "" {
		netxconf.Network = conf.Network
	}

	if conf.DialTimeout != 0 {
		netxconf.DialTimeout = conf.DialTimeout
	} else {
		netxconf.DialTimeout = dialDefault
	}

	if conf.WriteTimeout != 0 {
		netxconf.WriteTimeout = conf.WriteTimeout
	} else {
		netxconf.WriteTimeout = writeDefault
	}

	if conf.ReadTimeout != 0 {
		netxconf.ReadTimeout = conf.ReadTimeout
	} else {
		netxconf.ReadTimeout = readDefault
	}

	if conf.RetryDelay != 0 {
		netxconf.RetryDelay = conf.RetryDelay
	}

	if conf.ReadSize != 0 {
		netxconf.ReadSize = conf.ReadSize
	} else {
		netxconf.ReadSize = 20480
	}

	if host, port, ok := parseHostPort(address); ok {
		timeout := netxconf.DialTimeout
		if timeout <= 0 {
			timeout = retryhttpclient.GetDefaultTimeout()
		}
		baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseCtx, timeout)
		if err := retryhttpclient.WaitHostPort(ctx, host, port); err != nil {
			cancel()
			return nil, err
		}
		cancel()
	}

	retryhttpclient.AddNetInflight(1)

	client, err := netx.NewClient(address, netxconf)
	if err != nil {
		retryhttpclient.AddNetInflight(-1)
		return nil, err
	}

	return &Session{
		address: address,
		config:  netxconf,
		client:  client,
	}, nil
}

func NewConnSession(address string, conf Config, variableMap map[string]any) (*ConnSession, error) {
	address = setVariableMap(address, variableMap)
	network := strings.ToLower(strings.TrimSpace(conf.Network))
	if network == "" {
		network = "tcp"
	}

	globalTimeout := retryhttpclient.GetDefaultTimeout()
	dialBase := 3 * time.Second
	writeBase := 3 * time.Second
	readBase := 6 * time.Second
	if _, port, ok := parseHostPort(address); ok && port == "445" {
		dialBase = 5 * time.Second
		writeBase = 5 * time.Second
		readBase = 10 * time.Second
	}

	dialDefault := minDuration(globalTimeout, dialBase)
	writeDefault := minDuration(globalTimeout, writeBase)
	readDefault := minDuration(globalTimeout, readBase)

	cfg := conf
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = dialDefault
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = writeDefault
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = readDefault
	}
	if cfg.ReadSize <= 0 {
		cfg.ReadSize = 20480
	}

	if host, port, ok := parseHostPort(address); ok {
		timeout := cfg.DialTimeout
		if timeout <= 0 {
			timeout = retryhttpclient.GetDefaultTimeout()
		}
		baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseCtx, timeout)
		if err := retryhttpclient.WaitHostPort(ctx, host, port); err != nil {
			cancel()
			return nil, err
		}
		cancel()
	}

	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	var c net.Conn
	var err error

	if network == "ssl" {
		tlsCfg := &tls.Config{InsecureSkipVerify: true}
		if host, _, ok := parseHostPort(address); ok {
			if host != "" && net.ParseIP(host) == nil {
				tlsCfg.ServerName = host
			}
		}
		c, err = tls.DialWithDialer(dialer, "tcp", address, tlsCfg)
	} else {
		c, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return nil, err
	}

	retryhttpclient.AddNetInflight(1)
	return &ConnSession{address: address, network: network, conn: c, config: cfg}, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func (nc *NetClient) Request(data, dataType string, variableMap map[string]any) error {
	nc.address = setVariableMap(nc.address, variableMap)
	data = setVariableMap(data, variableMap)

	if len(dataType) > 0 {
		dataType = strings.ToLower(dataType)
		if dataType == "hex" {
			data = fromHex(data)
		}
	}

	variableMap["request"] = nil
	variableMap["response"] = nil

	if host, port, ok := parseHostPort(nc.address); ok {
		timeout := nc.config.DialTimeout
		if timeout <= 0 {
			timeout = retryhttpclient.GetDefaultTimeout()
		}
		baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseCtx, timeout)
		if err := retryhttpclient.WaitHostPort(ctx, host, port); err != nil {
			cancel()
			return err
		}
		cancel()
	}

	retryhttpclient.AddNetInflight(1)
	defer retryhttpclient.AddNetInflight(-1)

	// SSL/TLS 走独立实现，避免非预期的明文连接
	if strings.ToLower(nc.config.Network) == "ssl" {
		body, err := nc.sendReceiveTLS([]byte(data))
		if err != nil {
			return err
		}
		variableMap["request"] = &proto.Request{Raw: []byte(nc.address + "\r\n" + data)}
		variableMap["response"] = &proto.Response{Raw: body, Body: body}
		variableMap["fulltarget"] = nc.address
		return nil
	}

	if strings.ToLower(nc.config.Network) == "tcp" {
		body, err := nc.sendReceiveTCP([]byte(data))
		if err != nil {
			return err
		}
		variableMap["request"] = &proto.Request{Raw: []byte(nc.address + "\r\n" + data)}
		variableMap["response"] = &proto.Response{Raw: body, Body: body}
		variableMap["fulltarget"] = nc.address
		return nil
	}

	var err error
	nc.netx, err = netx.NewClient(nc.address, nc.config)
	if err != nil {
		return err
	}
	defer nc.netx.Close()

	err = nc.netx.Send([]byte(data))
	if err != nil {
		return err
	}

	body, err := nc.netx.Receive()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() && len(body) > 0 {
			err = nil
		} else {
			return err
		}
	}

	variableMap["request"] = &proto.Request{
		Raw: []byte(nc.address + "\r\n" + data),
	}

	variableMap["response"] = &proto.Response{
		Raw:  body,
		Body: body,
	}

	variableMap["fulltarget"] = nc.address

	// fmt.Println(variableMap["request"])
	// fmt.Println(variableMap["response"])

	return nil
}

func (s *ConnSession) Address() string {
	if s == nil {
		return ""
	}
	return s.address
}

func (s *ConnSession) Send(payload []byte) error {
	if s == nil || s.conn == nil {
		return fmt.Errorf("nil session")
	}
	if s.config.WriteTimeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := s.conn.Write(payload)
	return err
}

func (s *ConnSession) Receive(readSize int, readTimeout time.Duration) ([]byte, error) {
	if s == nil || s.conn == nil {
		return nil, fmt.Errorf("nil session")
	}
	if readSize <= 0 {
		readSize = s.config.ReadSize
	}
	if readSize <= 0 {
		readSize = 20480
	}
	if readTimeout <= 0 {
		readTimeout = s.config.ReadTimeout
	}
	if readTimeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(readTimeout))
	}

	chunk := 4096
	if chunk > readSize {
		chunk = readSize
	}
	buf := make([]byte, chunk)
	out := make([]byte, 0, chunk)
	for {
		remaining := readSize - len(out)
		if remaining <= 0 {
			break
		}
		if remaining < len(buf) {
			buf = buf[:remaining]
		}
		n, rerr := s.conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				break
			}
			if len(out) > 0 {
				break
			}
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}
	return out, nil
}

func (s *ConnSession) ReceiveUntil(readSize int, readTimeout time.Duration, until string) ([]byte, error) {
	if s == nil || s.conn == nil {
		return nil, fmt.Errorf("nil session")
	}
	if strings.TrimSpace(until) == "" {
		return s.Receive(readSize, readTimeout)
	}
	if readSize <= 0 {
		readSize = s.config.ReadSize
	}
	if readSize <= 0 {
		readSize = 20480
	}
	if readTimeout <= 0 {
		readTimeout = s.config.ReadTimeout
	}
	if readTimeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(readTimeout))
	}

	until = unescapeCommon(until)
	delim := []byte(until)
	if len(delim) == 0 {
		return s.Receive(readSize, readTimeout)
	}

	chunk := 4096
	if chunk > readSize {
		chunk = readSize
	}
	buf := make([]byte, chunk)
	out := make([]byte, 0, chunk)
	for {
		if bytes.Contains(out, delim) {
			idx := bytes.Index(out, delim)
			if idx >= 0 {
				end := idx + len(delim)
				if end < len(out) {
					out = out[:end]
				}
			}
			break
		}

		remaining := readSize - len(out)
		if remaining <= 0 {
			break
		}
		if remaining < len(buf) {
			buf = buf[:remaining]
		}
		n, rerr := s.conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				break
			}
			if len(out) > 0 {
				break
			}
			return nil, rerr
		}
		break
	}
	return out, nil
}

func (s *ConnSession) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	retryhttpclient.AddNetInflight(-1)
	return err
}

func (nc *NetClient) sendReceiveTCP(payload []byte) ([]byte, error) {
	dialer := &net.Dialer{}
	if nc.config.DialTimeout != 0 {
		dialer.Timeout = nc.config.DialTimeout
	}

	conn, err := dialer.Dial("tcp", nc.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if nc.config.WriteTimeout != 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(nc.config.WriteTimeout))
	}
	if len(payload) > 0 {
		if _, err = conn.Write(payload); err != nil {
			return nil, err
		}
	}

	if nc.config.ReadTimeout != 0 {
		_ = conn.SetReadDeadline(time.Now().Add(nc.config.ReadTimeout))
	}

	maxSize := nc.config.ReadSize
	if maxSize <= 0 {
		maxSize = 20480
	}

	chunk := 4096
	if chunk > maxSize {
		chunk = maxSize
	}
	buf := make([]byte, chunk)
	out := make([]byte, 0, chunk)
	for {
		remaining := maxSize - len(out)
		if remaining <= 0 {
			break
		}
		if remaining < len(buf) {
			buf = buf[:remaining]
		}

		n, rerr := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() && len(out) > 0 {
				break
			}
			if len(out) > 0 {
				break
			}
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}
	return out, nil
}

func (s *Session) Address() string {
	return s.address
}

func (s *Session) Send(data []byte) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("nil session")
	}
	return s.client.Send(data)
}

func (s *Session) Receive() ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("nil session")
	}
	return s.client.Receive()
}

func (s *Session) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	err := s.client.Close()
	s.client = nil
	retryhttpclient.AddNetInflight(-1)
	return err
}

func (nc *NetClient) sendReceiveTLS(payload []byte) ([]byte, error) {
	dialer := &net.Dialer{}
	if nc.config.DialTimeout != 0 {
		dialer.Timeout = nc.config.DialTimeout
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if host, _, ok := parseHostPort(nc.address); ok {
		if host != "" && net.ParseIP(host) == nil {
			tlsCfg.ServerName = host
		}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", nc.address, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if nc.config.WriteTimeout != 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(nc.config.WriteTimeout))
	}
	if len(payload) > 0 {
		if _, err = conn.Write(payload); err != nil {
			return nil, err
		}
	}

	if nc.config.ReadTimeout != 0 {
		_ = conn.SetReadDeadline(time.Now().Add(nc.config.ReadTimeout))
	}

	maxSize := nc.config.ReadSize
	if maxSize <= 0 {
		maxSize = 20480
	}

	chunk := 4096
	if chunk > maxSize {
		chunk = maxSize
	}
	buf := make([]byte, chunk)
	out := make([]byte, 0, chunk)
	for {
		remaining := maxSize - len(out)
		if remaining <= 0 {
			break
		}
		if remaining < len(buf) {
			buf = buf[:remaining]
		}

		n, rerr := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() && len(out) > 0 {
				break
			}
			if len(out) > 0 {
				break
			}
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}
	return out, nil
}

func (nc *NetClient) Close() error {
	if nc.netx != nil {
		return nc.netx.Close()
	}
	return nil
}

func setVariableMap(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		_, isMap := v.(map[string]string)
		if isMap {
			continue
		}
		newstr := fmt.Sprintf("%v", v)
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, newstr)
	}
	return find
}

func Render(find string, variableMap map[string]any) string {
	return setVariableMap(find, variableMap)
}

func fromHex(data string) string {
	new, err := hex.DecodeString(data)
	if err == nil {
		return string(new)
	}
	return data
}

func unescapeCommon(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	return s
}

func parseHostPort(address string) (string, string, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", false
	}

	if strings.Contains(address, "://") {
		if u, err := url.Parse(address); err == nil && u.Host != "" {
			address = u.Host
		}
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}
