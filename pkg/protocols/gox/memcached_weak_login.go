package gox

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["memcached-weak-login"] = memcached_weak_login
}

func memcached_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveMemcachedAddress(target)
	if err != nil {
		return err
	}

	// 1. Check for Unauthorized Access (No Auth required)
	// This is effectively a "weak login" (null login).
	if memcachedUnauthAttempt(host) {
		setResponse("success;user=unauthorized;pass=none", variableMap)
		setRequest(host, variableMap)
		setTarget(host, variableMap)
		setFullTarget(host, variableMap)
		return nil
	}

	// 2. Check for Weak Credentials (SASL PLAIN)
	usernames := []string{"", "memcached", "admin", "root", "test", "app"}
	passwords := []string{"123456", "password", "12345678", "admin", "root", "memcached", "test", "app"}

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
			if memcachedSASLAuthAttempt(host, u, p) {
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

func resolveMemcachedAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 11211), nil
	}
	if !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, 11211), nil
	}
	return host, nil
}

// memcachedUnauthAttempt tries to get stats without authentication
func memcachedUnauthAttempt(host string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadlines to prevent hanging
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send "stats" command (Text Protocol)
	fmt.Fprintf(conn, "stats\r\n")

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check for successful response (starts with STAT)
	// If auth is required, it might return "CLIENT_ERROR" or close connection.
	if strings.HasPrefix(line, "STAT") {
		return true
	}

	return false
}

// memcachedSASLAuthAttempt tries to authenticate using SASL PLAIN
func memcachedSASLAuthAttempt(host, username, password string) bool {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadlines to prevent hanging
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Construct SASL PLAIN packet
	mechanism := "PLAIN"
	authData := fmt.Sprintf("\x00%s\x00%s", username, password)

	keyLen := len(mechanism)
	bodyLen := keyLen + len(authData)

	buf := new(bytes.Buffer)
	buf.WriteByte(0x80)                                  // Magic: Request
	buf.WriteByte(0x21)                                  // Opcode: SASL Auth
	binary.Write(buf, binary.BigEndian, uint16(keyLen))  // Key Length
	buf.WriteByte(0x00)                                  // Extras Length
	buf.WriteByte(0x00)                                  // Data Type
	binary.Write(buf, binary.BigEndian, uint16(0))       // Reserved
	binary.Write(buf, binary.BigEndian, uint32(bodyLen)) // Body Length
	binary.Write(buf, binary.BigEndian, uint32(0))       // Opaque
	binary.Write(buf, binary.BigEndian, uint64(0))       // CAS
	buf.WriteString(mechanism)                           // Key
	buf.WriteString(authData)                            // Value (Payload)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return false
	}

	// Read Response Header (24 bytes)
	header := make([]byte, 24)
	_, err = ioReadFull(conn, header)
	if err != nil {
		return false
	}

	// Check Magic (0x81) and Opcode (0x21)
	if header[0] != 0x81 || header[1] != 0x21 {
		return false
	}

	// Check Status (Bytes 6-7)
	status := binary.BigEndian.Uint16(header[6:8])

	// Status 0x0000 is Success
	return status == 0x0000
}

func ioReadFull(r net.Conn, buf []byte) (n int, err error) {
	return io.ReadFull(r, buf)
}
