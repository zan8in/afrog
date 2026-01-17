package gox

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["smtp-weak-login"] = smtp_weak_login
}

func smtp_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveSMTPAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"admin", "administrator", "root", "test", "user", "mail", "smtp"}
	passwords := []string{"", "admin", "123456", "12345678", "password", "root", "toor", "1qaz2wsx", "qwer1234", "000000", "111111", "123123"}

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
			if smtpAuthAttempt(host, u, p) {
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

func smtpAuthAttempt(host, username, password string) bool {
	conn, err := smtpDial(host)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	code, _, err := readSMTPResponse(reader)
	if err != nil || code != 220 {
		return false
	}

	_, ehloLines, err := smtpEHLO(conn, reader, "afrog")
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HELO afrog\r\n")
		code, _, err = readSMTPResponse(reader)
		if err != nil || code != 250 {
			return false
		}
		ehloLines = nil
	}

	if !smtpHasAuth(ehloLines) && len(ehloLines) > 0 {
		return false
	}

	if !smtpIsTLS(conn) && smtpHasStartTLS(ehloLines) {
		tlsConn, tlsReader, ok := smtpStartTLS(conn, reader, host)
		if !ok {
			return false
		}
		conn = tlsConn
		reader = tlsReader
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		ehloLines, err = smtpReEHLO(conn, reader, "afrog")
		if err != nil {
			return false
		}
		if !smtpHasAuth(ehloLines) {
			return false
		}
	}

	if smtpAuthPlain(conn, reader, username, password) {
		return true
	}
	if smtpAuthLogin(conn, reader, username, password) {
		return true
	}

	return false
}

func smtpDial(host string) (net.Conn, error) {
	h, p, err := splitHostPortBestEffort(host)
	if err != nil {
		return nil, err
	}
	if p == 465 {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12})
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	return net.DialTimeout("tcp", host, 5*time.Second)
}

func smtpIsTLS(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}

func smtpEHLO(conn net.Conn, reader *bufio.Reader, heloName string) (int, []string, error) {
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", heloName); err != nil {
		return 0, nil, err
	}
	return readSMTPResponse(reader)
}

func smtpReEHLO(conn net.Conn, reader *bufio.Reader, heloName string) ([]string, error) {
	code, lines, err := smtpEHLO(conn, reader, heloName)
	if err != nil || code != 250 {
		return nil, errors.New("ehlo failed")
	}
	return lines, nil
}

func smtpStartTLS(conn net.Conn, reader *bufio.Reader, host string) (net.Conn, *bufio.Reader, bool) {
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return conn, reader, false
	}
	code, _, err := readSMTPResponse(reader)
	if err != nil || code != 220 {
		return conn, reader, false
	}

	h, _, err := splitHostPortBestEffort(host)
	if err != nil {
		return conn, reader, false
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return conn, reader, false
	}
	return tlsConn, bufio.NewReader(tlsConn), true
}

func smtpAuthPlain(conn net.Conn, reader *bufio.Reader, username, password string) bool {
	msg := "\x00" + username + "\x00" + password
	enc := base64.StdEncoding.EncodeToString([]byte(msg))

	if _, err := fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", enc); err != nil {
		return false
	}
	code, _, err := readSMTPResponse(reader)
	if err != nil {
		return false
	}

	if code == 235 {
		return true
	}
	if code != 334 {
		return false
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", enc); err != nil {
		return false
	}
	code, _, err = readSMTPResponse(reader)
	if err != nil {
		return false
	}
	return code == 235
}

func smtpAuthLogin(conn net.Conn, reader *bufio.Reader, username, password string) bool {
	if _, err := fmt.Fprintf(conn, "AUTH LOGIN\r\n"); err != nil {
		return false
	}
	code, _, err := readSMTPResponse(reader)
	if err != nil || code != 334 {
		return false
	}

	u := base64.StdEncoding.EncodeToString([]byte(username))
	if _, err := fmt.Fprintf(conn, "%s\r\n", u); err != nil {
		return false
	}
	code, _, err = readSMTPResponse(reader)
	if err != nil || code != 334 {
		return false
	}

	p := base64.StdEncoding.EncodeToString([]byte(password))
	if _, err := fmt.Fprintf(conn, "%s\r\n", p); err != nil {
		return false
	}
	code, _, err = readSMTPResponse(reader)
	if err != nil {
		return false
	}
	return code == 235
}

func readSMTPResponse(reader *bufio.Reader) (int, []string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, []string{line}, errors.New("invalid smtp response")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, []string{line}, err
	}

	lines := []string{line}
	if len(line) >= 4 && line[3] == '-' {
		for {
			l, err := reader.ReadString('\n')
			if err != nil {
				return code, lines, err
			}
			l = strings.TrimRight(l, "\r\n")
			lines = append(lines, l)
			if len(l) >= 4 && strings.HasPrefix(l, fmt.Sprintf("%03d ", code)) {
				break
			}
		}
	}
	return code, lines, nil
}

func smtpHasAuth(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(strings.ToUpper(l), "AUTH") {
			return true
		}
	}
	return false
}

func smtpHasStartTLS(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(strings.ToUpper(l), "STARTTLS") {
			return true
		}
	}
	return false
}

func splitHostPortBestEffort(hostport string) (string, int, error) {
	if !hasPort(hostport) {
		return hostport, 0, errors.New("missing port")
	}
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	pi, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, pi, nil
}

func resolveSMTPAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 25), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 25), nil
	}
	return host, nil
}
