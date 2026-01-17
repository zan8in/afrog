package gox

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["redis-weak-login"] = redis_weak_login
}

func redis_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveRedisAddress(target)
	if err != nil {
		return err
	}

	passwords := []string{
		"",
		"123456", "redis", "root", "password", "admin",
		"12345", "12345678", "123456789", "123123", "foobared",
		"qwer", "qwerty", "test", "admin123", "pass",
	}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	tried := 0

	isAuthRequired, err := redisIsAuthRequired(host)
	if err != nil {
		setResponse("fail;reason=connect_error", variableMap)
		setRequest(host, variableMap)
		setTarget(host, variableMap)
		setFullTarget(host, variableMap)
		return nil
	}

	if !isAuthRequired {
		setResponse("success;user=;pass=<empty>", variableMap)
		setRequest(host, variableMap)
		setTarget(host, variableMap)
		setFullTarget(host, variableMap)
		return nil
	}

	for _, p := range passwords {
		if p == "" {
			continue
		}

		if maxTries > 0 && tried >= maxTries {
			setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
			setRequest(host, variableMap)
			setTarget(host, variableMap)
			setFullTarget(host, variableMap)
			return nil
		}
		tried++

		if redisAuthAttempt(host, p) {
			setResponse(fmt.Sprintf("success;user=;pass=%s", p), variableMap)
			setRequest(host, variableMap)
			setTarget(host, variableMap)
			setFullTarget(host, variableMap)
			return nil
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)
	return nil
}

func redisIsAuthRequired(address string) (bool, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	fmt.Fprintf(conn, "PING\r\n")

	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	if strings.Contains(line, "PONG") {
		return false, nil
	}

	if strings.Contains(line, "NOAUTH") {
		return true, nil
	}

	if strings.Contains(line, "WRONGPASS") {
		return true, nil
	}

	return true, nil
}

func redisAuthAttempt(address, password string) bool {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
	fmt.Fprint(conn, cmd)

	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	if strings.HasPrefix(line, "+OK") {
		return true
	}

	return false
}

func resolveRedisAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 6379), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 6379), nil
	}
	return host, nil
}
