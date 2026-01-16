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
	funcMap["ftp-weak-login"] = ftp_weak_login
}

func ftp_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveFTPAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"ftp", "anonymous", "root", "admin", "user", "administrator", "webadmin", "www", "test"}
	passwords := []string{"ftp", "anonymous", "root", "admin", "123456", "password", "12345678", "12345", "test", "webadmin"}

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
			if ftpAuthAttempt(host, u, p) {
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

func ftpAuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read welcome message
	// 220 Service ready for new user.
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220") {
		return false
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", username)
	line, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	// 331 User name okay, need password.
	if strings.HasPrefix(line, "331") {
		// Send PASS
		fmt.Fprintf(conn, "PASS %s\r\n", password)
		line, err = reader.ReadString('\n')
		if err != nil {
			return false
		}
	}

	// 230 User logged in, proceed.
	if strings.HasPrefix(line, "230") {
		return true
	}

	return false
}

func resolveFTPAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 21), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 21), nil
	}
	return host, nil
}
