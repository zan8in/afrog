package gox

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-zookeeper/zk"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["zookeeper-digest-weak-login"] = zookeeper_digest_weak_login
}

func zookeeper_digest_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveZooKeeperAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"admin", "zookeeper", "zk", "root", "super", "test", "user"}
	passwords := []string{"admin", "zookeeper", "zk", "root", "super", "123456", "12345678", "password", "P@ssw0rd", "test", "user", "111111", "000000", "123123"}

	maxTries := 100
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	timeoutSec := 6
	if v := variableMap["timeout_sec"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			timeoutSec = n
		}
	}

	connectTimeoutSec := 3
	if v := variableMap["connect_timeout_sec"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			connectTimeoutSec = n
		}
	}

	unauthOK, unauthNoAuth, _ := zookeeperCreateEphemeral(host, "", time.Duration(connectTimeoutSec)*time.Second, time.Duration(timeoutSec)*time.Second)
	if unauthOK || !unauthNoAuth {
		setResponse("fail;reason=not_applicable;tried=0", variableMap)
		setRequest(host, variableMap)
		setTarget(host, variableMap)
		setFullTarget(host, variableMap)
		return nil
	}

	tried := 0
	for _, u := range usernames {
		for _, p := range passwords {
			if maxTries > 0 && tried >= maxTries {
				setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
				setRequest(host, variableMap)
				setTarget(host, variableMap)
				setFullTarget(host, variableMap)
				return nil
			}
			tried++

			ok, _, _ := zookeeperCreateEphemeral(host, u+":"+p, time.Duration(connectTimeoutSec)*time.Second, time.Duration(timeoutSec)*time.Second)
			if ok {
				setResponse(fmt.Sprintf("success;user=%s;pass=%s", u, p), variableMap)
				setRequest(host, variableMap)
				setTarget(host, variableMap)
				setFullTarget(host, variableMap)
				return nil
			}
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)
	return nil
}

func resolveZooKeeperAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 2181), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 2181), nil
	}
	return host, nil
}

func zookeeperCreateEphemeral(host string, digest string, connectTimeout, sessionTimeout time.Duration) (bool, bool, error) {
	conn, events, err := zk.Connect([]string{host}, sessionTimeout, zk.WithDialer(func(network, address string, timeout time.Duration) (net.Conn, error) {
		d := &net.Dialer{Timeout: connectTimeout}
		return d.Dial(network, address)
	}), zk.WithLogger(zkNoopLogger{}))
	if err != nil {
		return false, false, err
	}
	defer conn.Close()

	if err := zookeeperWaitConnected(events, connectTimeout); err != nil {
		return false, false, err
	}

	if digest != "" {
		if err := conn.AddAuth("digest", []byte(digest)); err != nil {
			return false, false, err
		}
	}

	path := "/afrog-" + RandLower(10)
	_, err = conn.Create(path, []byte(""), zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
	if err == nil {
		return true, false, nil
	}
	if errors.Is(err, zk.ErrNoAuth) || errors.Is(err, zk.ErrAuthFailed) {
		return false, true, nil
	}
	return false, false, err
}

func zookeeperWaitConnected(events <-chan zk.Event, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return errors.New("zookeeper events closed")
			}
			if ev.State == zk.StateConnected || ev.State == zk.StateHasSession {
				return nil
			}
			if ev.State == zk.StateAuthFailed {
				return zk.ErrAuthFailed
			}
		case <-timer.C:
			return errors.New("zookeeper connect timeout")
		}
	}
}

type zkNoopLogger struct{}

func (zkNoopLogger) Printf(string, ...any) {}
