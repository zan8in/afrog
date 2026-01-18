package gox

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["telnet-weak-login"] = telnet_weak_login
}

func telnet_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveTelnetAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"root", "admin", "administrator", "user", "test", "guest", "support"}
	passwords := []string{"", "root", "admin", "123456", "12345678", "password", "toor", "guest", "111111", "000000", "123123"}

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
			if telnetAuthAttempt(host, u, p) {
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

func telnetAuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	reader := bufio.NewReader(conn)

	bannerRaw, _ := telnetReadSome(conn, reader, 4096, 1500*time.Millisecond)
	banner := telnetSanitizeText(bannerRaw)

	if strings.TrimSpace(banner) == "" {
		_, _ = fmt.Fprintf(conn, "\r\n")
		moreRaw, _ := telnetReadSome(conn, reader, 4096, 1500*time.Millisecond)
		banner += "\n" + telnetSanitizeText(moreRaw)
	}

	if telnetLooksLikeShell(banner) {
		return true
	}

	needUser := telnetHasLoginPrompt(banner) || (!telnetHasPasswordPrompt(banner) && !telnetHasLoginPrompt(banner))
	if needUser {
		_, _ = fmt.Fprintf(conn, "%s\r\n", username)
	}

	pwRaw, _ := telnetReadSome(conn, reader, 4096, 2000*time.Millisecond)
	pwText := telnetSanitizeText(pwRaw)
	if !telnetHasPasswordPrompt(pwText) && !telnetHasPasswordPrompt(banner) {
		_, _ = fmt.Fprintf(conn, "\r\n")
		pwRaw2, _ := telnetReadSome(conn, reader, 4096, 1500*time.Millisecond)
		pwText += "\n" + telnetSanitizeText(pwRaw2)
	}

	_, _ = fmt.Fprintf(conn, "%s\r\n", password)

	afterRaw, _ := telnetReadSome(conn, reader, 8192, 2500*time.Millisecond)
	after := telnetSanitizeText(afterRaw)

	if telnetHasFailure(after) || telnetHasLoginPrompt(after) || telnetHasPasswordPrompt(after) {
		return false
	}

	_, _ = fmt.Fprintf(conn, "\r\n")
	promptRaw, _ := telnetReadSome(conn, reader, 8192, 1500*time.Millisecond)
	prompt := telnetSanitizeText(promptRaw)

	return telnetLooksLikeShell(after + "\n" + prompt)
}

func telnetReadSome(conn net.Conn, reader *bufio.Reader, maxBytes int, extraWait time.Duration) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4096
	}

	buf := make([]byte, 0, maxBytes)
	tmp := make([]byte, 1024)

	deadline := time.Now().Add(extraWait)
	_ = conn.SetReadDeadline(deadline)

	for len(buf) < maxBytes {
		n, err := reader.Read(tmp)
		if n > 0 {
			clean := telnetFilterAndReply(conn, tmp[:n])
			if len(clean) > 0 {
				remain := maxBytes - len(buf)
				if len(clean) > remain {
					clean = clean[:remain]
				}
				buf = append(buf, clean...)
			}
		}
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
	}

	return buf, nil
}

func telnetFilterAndReply(conn net.Conn, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	const (
		iac  = 255
		dont = 254
		do   = 253
		wont = 252
		will = 251
		sb   = 250
		se   = 240
	)

	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] != iac {
			out = append(out, data[i])
			i++
			continue
		}

		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case do, dont, will, wont:
			if i+2 >= len(data) {
				i = len(data)
				break
			}
			opt := data[i+2]
			if cmd == do {
				_, _ = conn.Write([]byte{iac, wont, opt})
			} else if cmd == will {
				_, _ = conn.Write([]byte{iac, dont, opt})
			}
			i += 3
		case sb:
			i += 2
			for i < len(data) {
				if data[i] == iac && i+1 < len(data) && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
		case iac:
			out = append(out, iac)
			i += 2
		default:
			i += 2
		}
	}

	return out
}

func telnetSanitizeText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := string(bytes.ReplaceAll(b, []byte{0}, []byte{}))
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n\n", "\n")
	return s
}

func telnetHasLoginPrompt(s string) bool {
	u := strings.ToLower(s)
	return strings.Contains(u, "login:") || strings.Contains(u, "username:") || strings.Contains(u, "user:")
}

func telnetHasPasswordPrompt(s string) bool {
	u := strings.ToLower(s)
	return strings.Contains(u, "password:") || strings.Contains(u, "pass:")
}

func telnetHasFailure(s string) bool {
	u := strings.ToLower(s)
	bad := []string{
		"login incorrect",
		"authentication failed",
		"invalid password",
		"incorrect password",
		"incorrect",
		"failed",
		"denied",
		"bad password",
	}
	for _, b := range bad {
		if strings.Contains(u, b) {
			return true
		}
	}
	return false
}

func telnetLooksLikeShell(s string) bool {
	u := strings.ToLower(strings.TrimSpace(s))
	if u == "" {
		return false
	}
	if telnetHasFailure(u) || telnetHasLoginPrompt(u) || telnetHasPasswordPrompt(u) {
		return false
	}
	lines := strings.Split(u, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "#") || strings.HasSuffix(line, "$") || strings.HasSuffix(line, ">") {
			return true
		}
		if strings.Contains(line, "welcome") || strings.Contains(line, "last login") {
			return true
		}
		break
	}
	return false
}

func resolveTelnetAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 23), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 23), nil
	}
	return host, nil
}

