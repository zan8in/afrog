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
	funcMap["pop3-weak-login"] = pop3_weak_login
}

func pop3_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolvePOP3Address(target)
	if err != nil {
		return err
	}

	usernames := []string{"admin", "administrator", "root", "test", "user", "webmaster", "info", "service", "mail"}
	passwords := []string{"123456", "password", "12345678", "admin", "root", "test", "12345", "webmaster", "123456789"}

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
			if pop3AuthAttempt(host, u, p) {
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

func resolvePOP3Address(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 110), nil
	}
	if !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, 110), nil
	}
	return host, nil
}

func pop3AuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadlines to prevent hanging
	// Give enough time for the full interaction (banner + user + pass)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)

	// Read banner
	// +OK POP3 server ready
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "+OK") {
		return false
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", username)
	
	// Read USER response
	// +OK User name accepted, password please
	line, err = reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "+OK") {
		return false
	}

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", password)

	// Read PASS response
	// +OK Mailbox open
	// -ERR Authentication failed
	line, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	if strings.HasPrefix(line, "+OK") {
		return true
	}

	return false
}
