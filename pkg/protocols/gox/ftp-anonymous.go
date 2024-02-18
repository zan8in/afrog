package gox

import (
	"bytes"
	"fmt"

	"github.com/zan8in/afrog/pkg/protocols/netxclient"
	"github.com/zan8in/pins/netx"

	urlutil "github.com/zan8in/pins/url"
)

func ftp_anonymous(target string, variableMap map[string]any) error {
	var err error

	variableMap["request"] = nil
	variableMap["response"] = nil

	hostname, err := urlutil.Hostname(target)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s:%s", hostname, "21")

	data, err := ftp_login(host, variableMap)
	if err != nil {
		host2, err := urlutil.Host(target)
		if err != nil {
			return err
		}

		data2, err := ftp_login(host2, variableMap)
		if err != nil {
			return err
		}

		setResponse(data2, variableMap)
		setRequest(host2, variableMap)
		setFullTarget(host2, variableMap)

		return nil

	}

	setResponse(data, variableMap)
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)

	return nil
}

func ftp_login(host string, variableMap map[string]any) (string, error) {
	nc, err := netxclient.NewNetClient(host, netxclient.Config{})
	if err != nil {
		return "", err
	}

	client, err := netx.NewClient(host, *nc.Config())
	if err != nil {
		return "", err
	}
	defer client.Close()

	err = client.Send([]byte("USER anonymous\r\n"))
	if err != nil {
		return "", err
	}

	_, err = client.Receive()
	if err != nil {
		return "", err
	}

	err = client.Send([]byte("PASS anonymous\r\n"))
	if err != nil {
		return "", err
	}

	data, err := client.Receive()
	if err != nil {
		return "", err
	}

	if bytes.Contains(data, []byte("331")) {
		err = client.Send([]byte("PASS anonymous\r\n"))
		if err != nil {
			return "", err
		}

		data, err = client.Receive()
		if err != nil {
			return "", err
		}

		return string(data), nil
	}

	return string(data), nil
}

func init() {
	funcMap["ftp-anonymous"] = ftp_anonymous
}
