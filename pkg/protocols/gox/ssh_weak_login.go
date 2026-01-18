package gox

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["ssh-weak-login"] = ssh_weak_login
}

func ssh_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveSSHAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"root", "admin", "administrator", "ubuntu", "test", "user", "pi", "git", "oracle", "postgres"}
	passwords := []string{"", "root", "admin", "123456", "12345678", "password", "toor", "1qaz2wsx", "qwer1234", "000000", "111111", "123123"}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
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
			if sshAuthAttempt(host, u, p) {
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

func sshAuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		return false
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false
	}
	_ = session.Close()
	return true
}

func resolveSSHAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 22), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 22), nil
	}
	return host, nil
}
