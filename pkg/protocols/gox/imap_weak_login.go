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
	funcMap["imap-weak-login"] = imap_weak_login
}

func imap_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveIMAPAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"admin", "administrator", "root", "test", "user", "webmaster", "info", "service"}
	passwords := []string{"123456", "password", "12345678", "admin", "root", "test", "12345", "webmaster"}

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
			if imapAuthAttempt(host, u, p) {
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

func imapAuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadlines to prevent hanging
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)

	// Read banner
	// * OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "* OK") {
		return false
	}

	// Send LOGIN
	fmt.Fprintf(conn, "a001 LOGIN %s %s\r\n", username, password)

	// Read response
	// a001 OK Logged in.
	// a001 NO Authentication failed.
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return false
		}
		if strings.HasPrefix(line, "a001 OK") {
			return true
		}
		if strings.HasPrefix(line, "a001 NO") || strings.HasPrefix(line, "a001 BAD") {
			return false
		}
	}
}

func resolveIMAPAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 143), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 143), nil
	}
	return host, nil
}
