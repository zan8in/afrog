package netxclient

import (
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/pins/netx"
)

type Config struct {
	Network      string
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	RetryDelay   time.Duration
	ReadSize     int
}

type NetClient struct {
	address string
	config  netx.Config
	netx    *netx.Client
}

func NewNetClient(address string, conf Config) (*NetClient, error) {
	netxconf := netx.Config{}

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

func (nc *NetClient) Request(data string, variableMap map[string]any) error {
	nc.address = setVariableMap(nc.address, variableMap)
	data = setVariableMap(data, variableMap)

	var err error
	nc.netx, err = netx.NewClient(nc.address, nc.config)
	if err != nil {
		return err
	}
	defer nc.netx.Close()

	variableMap["request"] = nil
	variableMap["response"] = nil

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
		Raw: body,
	}

	variableMap["fulltarget"] = nc.address

	fmt.Println(variableMap["request"])
	fmt.Println(variableMap["response"])

	return nil
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
