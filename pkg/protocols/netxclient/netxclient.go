package netxclient

import (
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

func (nc *NetClient) Config() *netx.Config {
	return &nc.config
}

func NewNetClient(address string, conf Config) (*NetClient, error) {
	netxconf := netx.Config{}

	if conf.MaxRetries != 0 {
		netxconf.MaxRetries = conf.MaxRetries
	}

	if conf.Network != "" {
		netxconf.Network = conf.Network
	}
	if conf.DialTimeout != 0 {
		netxconf.DialTimeout = conf.DialTimeout
	}
	if conf.WriteTimeout != 0 {
		netxconf.WriteTimeout = conf.WriteTimeout
	}
	if conf.ReadTimeout != 0 {
		netxconf.ReadTimeout = conf.ReadTimeout
	}
	if conf.RetryDelay != 0 {
		netxconf.RetryDelay = conf.RetryDelay
	}
	if conf.ReadSize != 0 {
		netxconf.ReadSize = conf.ReadSize
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
		return err
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

	conn, err := tls.DialWithDialer(dialer, "tcp", nc.address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if nc.config.WriteTimeout != 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(nc.config.WriteTimeout))
	}
	if _, err = conn.Write(payload); err != nil {
		return nil, err
	}

	if nc.config.ReadTimeout != 0 {
		_ = conn.SetReadDeadline(time.Now().Add(nc.config.ReadTimeout))
	}

	size := nc.config.ReadSize
	if size <= 0 {
		size = 20480
	}
	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
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

func fromHex(data string) string {
	new, err := hex.DecodeString(data)
	if err == nil {
		return string(new)
	}
	return data
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
