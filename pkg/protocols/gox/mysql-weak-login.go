package gox

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

const (
	clientLongPassword     uint32 = 0x00000001
	clientLongFlag         uint32 = 0x00000004
	clientProtocol41       uint32 = 0x00000200
	clientTransactions     uint32 = 0x00002000
	clientSecureConnection uint32 = 0x00008000
	clientMultiResults     uint32 = 0x00020000
	clientPluginAuth       uint32 = 0x00080000
)

type mysqlHandshake struct {
	serverCaps uint32
	charset    byte
	scramble   []byte
	plugin     string
}

func mysql_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveMySQLAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"root", "admin", "mysql", "test"}
	passwords := []string{"", "root", "123456", "12345678", "admin", "password", "mysql", "toor", "1qaz2wsx", "qwer1234", "000000", "111111", "123123"}

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
			if mysqlAuthAttempt(host, u, p, variableMap) {
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

func resolveMySQLAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 3306), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 3306), nil
	}
	return host, nil
}

func mysqlAuthAttempt(host, username, password string, variableMap map[string]any) bool {
	conn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	rawHandshake, err := readMySQLPacket(conn, 3*time.Second)
	if err != nil {
		return false
	}

	hs, err := parseMySQLHandshake(rawHandshake)
	if err != nil {
		return false
	}

	loginPacket, err := buildMySQLHandshakeResponse(username, password, hs, 1)
	if err != nil {
		return false
	}

	if err := writeAll(conn, loginPacket, 3*time.Second); err != nil {
		return false
	}

	firstRespRaw, err := readMySQLPacket(conn, 3*time.Second)
	if err != nil {
		return false
	}

	ok, _ := handleMySQLAuthFlow(conn, firstRespRaw, username, password, hs)
	return ok
}

func writeAll(conn net.Conn, payload []byte, timeout time.Duration) error {
	if conn == nil {
		return errors.New("nil conn")
	}
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	if len(payload) == 0 {
		return nil
	}
	written := 0
	for written < len(payload) {
		n, err := conn.Write(payload[written:])
		if n > 0 {
			written += n
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readMySQLPacket(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("nil conn")
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	payloadLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if payloadLen < 0 || payloadLen > 16*1024*1024 {
		return nil, errors.New("invalid mysql packet length")
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}
	return append(header, payload...), nil
}

func hasPort(host string) bool {
	if strings.Count(host, ":") == 0 {
		return false
	}
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
		return true
	}
	if strings.Count(host, ":") == 1 {
		return true
	}
	return false
}

func handleMySQLAuthFlow(conn net.Conn, firstRespRaw []byte, username, password string, hs mysqlHandshake) (bool, error) {
	payload, seq, err := firstPacketPayload(firstRespRaw)
	if err != nil || len(payload) == 0 {
		return false, err
	}

	switch payload[0] {
	case 0x00:
		return true, nil
	case 0xff:
		return false, nil
	case 0xfe:
		if len(payload) < 2 {
			return false, nil
		}
		plugin, scramble := parseAuthSwitchRequest(payload)
		if strings.TrimSpace(plugin) == "" {
			plugin = hs.plugin
		}
		if len(scramble) == 0 {
			scramble = hs.scramble
		}
		token, tokErr := buildAuthToken(plugin, password, scramble)
		if tokErr != nil {
			return false, tokErr
		}
		resp := buildPacket(token, seq+1)
		if err := writeAll(conn, resp, 3*time.Second); err != nil {
			return false, err
		}
		nextRaw, err := readMySQLPacket(conn, 3*time.Second)
		if err != nil {
			return false, err
		}
		return handleMySQLAuthFlow(conn, nextRaw, username, password, hs)
	case 0x01:
		if len(payload) >= 2 && payload[1] == 0x03 {
			nextRaw, err := readMySQLPacket(conn, 3*time.Second)
			if err != nil {
				return false, err
			}
			return handleMySQLAuthFlow(conn, nextRaw, username, password, hs)
		}
		return false, nil
	default:
		return false, nil
	}
}

func firstPacketPayload(raw []byte) ([]byte, byte, error) {
	if len(raw) < 4 {
		return nil, 0, errors.New("short packet")
	}
	payloadLen := int(uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16)
	seq := raw[3]
	if payloadLen < 0 || len(raw) < 4+payloadLen {
		return nil, 0, errors.New("incomplete packet")
	}
	return raw[4 : 4+payloadLen], seq, nil
}

func parseMySQLHandshake(raw []byte) (mysqlHandshake, error) {
	payload, _, err := firstPacketPayload(raw)
	if err != nil {
		return mysqlHandshake{}, err
	}
	if len(payload) < 1 {
		return mysqlHandshake{}, errors.New("empty handshake payload")
	}

	i := 0
	_ = payload[i]
	i++
	_, i, ok := readNullTerm(payload, i)
	if !ok {
		return mysqlHandshake{}, errors.New("invalid server version")
	}
	if i+4 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid connection id")
	}
	i += 4
	if i+8 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid auth plugin data part1")
	}
	auth1 := payload[i : i+8]
	i += 8
	if i+1 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid filler")
	}
	i++
	if i+2 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid capability lower")
	}
	capLow := binary.LittleEndian.Uint16(payload[i : i+2])
	i += 2
	if i+1 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid charset")
	}
	charset := payload[i]
	i++
	if i+2 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid status")
	}
	i += 2
	if i+2 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid capability upper")
	}
	capHigh := binary.LittleEndian.Uint16(payload[i : i+2])
	i += 2
	serverCaps := uint32(capLow) | (uint32(capHigh) << 16)
	if i+1 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid auth len")
	}
	authDataLen := int(payload[i])
	i++
	if i+10 > len(payload) {
		return mysqlHandshake{}, errors.New("invalid reserved")
	}
	i += 10

	auth2Len := 13
	if authDataLen > 8 {
		if v := authDataLen - 8; v > auth2Len {
			auth2Len = v
		}
	}
	if i+auth2Len > len(payload) {
		auth2Len = len(payload) - i
		if auth2Len < 0 {
			auth2Len = 0
		}
	}
	auth2 := payload[i : i+auth2Len]
	i += auth2Len
	scramble := append(append([]byte{}, auth1...), auth2...)
	scramble = bytes.TrimRight(scramble, "\x00")
	if len(scramble) > 20 {
		scramble = scramble[:20]
	}

	plugin := ""
	if (serverCaps&clientPluginAuth) != 0 && i < len(payload) {
		if payload[i] == 0x00 {
			i++
		}
		s, _, ok := readNullTerm(payload, i)
		if ok {
			plugin = s
		}
	}

	return mysqlHandshake{
		serverCaps: serverCaps,
		charset:    charset,
		scramble:   scramble,
		plugin:     plugin,
	}, nil
}

func buildMySQLHandshakeResponse(username, password string, hs mysqlHandshake, seq byte) ([]byte, error) {
	clientCaps := clientLongPassword | clientLongFlag | clientProtocol41 | clientSecureConnection | clientMultiResults
	if (hs.serverCaps & clientTransactions) != 0 {
		clientCaps |= clientTransactions
	}
	plugin := strings.TrimSpace(hs.plugin)
	if plugin == "" {
		plugin = "mysql_native_password"
	}
	if (hs.serverCaps & clientPluginAuth) != 0 {
		clientCaps |= clientPluginAuth
	}

	token, err := buildAuthToken(plugin, password, hs.scramble)
	if err != nil {
		return nil, err
	}

	charset := hs.charset
	if charset == 0 {
		charset = 33
	}

	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, clientCaps)
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	_ = payload.WriteByte(charset)
	_, _ = payload.Write(make([]byte, 23))
	_, _ = payload.WriteString(username)
	_ = payload.WriteByte(0x00)
	_ = payload.WriteByte(byte(len(token)))
	if len(token) > 0 {
		_, _ = payload.Write(token)
	}
	if (clientCaps & clientPluginAuth) != 0 {
		_, _ = payload.WriteString(plugin)
		_ = payload.WriteByte(0x00)
	}

	return buildPacket(payload.Bytes(), seq), nil
}

func buildAuthToken(plugin, password string, scramble []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(plugin)) {
	case "mysql_native_password", "":
		return mysqlNativePasswordToken(password, scramble), nil
	case "caching_sha2_password":
		return cachingSha2PasswordToken(password, scramble), nil
	default:
		return nil, fmt.Errorf("unsupported auth plugin: %s", plugin)
	}
}

func mysqlNativePasswordToken(password string, scramble []byte) []byte {
	if password == "" {
		return []byte{}
	}
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	_, _ = h.Write(scramble)
	_, _ = h.Write(s2[:])
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := 0; i < len(s1); i++ {
		out[i] = s3[i] ^ s1[i]
	}
	return out
}

func cachingSha2PasswordToken(password string, scramble []byte) []byte {
	if password == "" {
		return []byte{}
	}
	s1 := sha256.Sum256([]byte(password))
	s2 := sha256.Sum256(s1[:])
	h := sha256.New()
	_, _ = h.Write(s2[:])
	_, _ = h.Write(scramble)
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := 0; i < len(s1); i++ {
		out[i] = s3[i] ^ s1[i]
	}
	return out
}

func parseAuthSwitchRequest(payload []byte) (string, []byte) {
	if len(payload) < 2 {
		return "", nil
	}
	i := 1
	plugin, next, ok := readNullTerm(payload, i)
	if !ok {
		return "", nil
	}
	i = next
	scramble := append([]byte{}, payload[i:]...)
	scramble = bytes.TrimRight(scramble, "\x00")
	if len(scramble) > 20 {
		scramble = scramble[:20]
	}
	return plugin, scramble
}

func readNullTerm(b []byte, start int) (string, int, bool) {
	if start < 0 || start >= len(b) {
		return "", start, false
	}
	idx := bytes.IndexByte(b[start:], 0x00)
	if idx < 0 {
		return "", start, false
	}
	end := start + idx
	return string(b[start:end]), end + 1, true
}

func buildPacket(payload []byte, seq byte) []byte {
	l := len(payload)
	out := make([]byte, 4+l)
	out[0] = byte(l)
	out[1] = byte(l >> 8)
	out[2] = byte(l >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

func init() {
	funcMap["mysql-weak-login"] = mysql_weak_login
}
