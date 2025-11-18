package netxclient

import (
    "encoding/hex"
    "fmt"
    "strings"
    "time"

    "github.com/zan8in/afrog/v3/pkg/proto"
    "github.com/zan8in/pins/netx"
    "crypto/tls"
    "net"
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
