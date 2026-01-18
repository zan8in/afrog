package gox

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["vnc-weak-login"] = vnc_weak_login
}

func vnc_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveVNCAddress(target)
	if err != nil {
		return err
	}

	passwords := []string{"", "123456", "12345678", "password", "admin", "root", "vnc", "letmein", "qwerty", "111111", "000000", "123123"}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	tried := 0
	for _, p := range passwords {
		if maxTries > 0 && tried >= maxTries {
			setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
			setRequest(host, variableMap)
			setTarget(host, variableMap)
			setFullTarget(host, variableMap)
			return nil
		}
		tried++

		ok, none := vncAuthAttempt(host, p)
		if ok {
			if none {
				setResponse("success;user=;pass=<none>", variableMap)
			} else {
				setResponse(fmt.Sprintf("success;user=;pass=%s", p), variableMap)
			}
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

func vncAuthAttempt(host, password string) (bool, bool) {
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	serverProto := make([]byte, 12)
	if _, err := io.ReadFull(conn, serverProto); err != nil {
		return false, false
	}
	if !bytes.HasPrefix(serverProto, []byte("RFB ")) {
		return false, false
	}

	if _, err := conn.Write(serverProto); err != nil {
		return false, false
	}

	protoStr := string(serverProto)
	is33 := strings.Contains(protoStr, "003.003")

	if is33 {
		var secType uint32
		if err := binary.Read(conn, binary.BigEndian, &secType); err != nil {
			return false, false
		}
		if secType == 1 {
			return vncReadSecurityResult(conn), true
		}
		if secType == 2 {
			return vncDoVNCAuth(conn, password), false
		}
		return false, false
	}

	nTypes := make([]byte, 1)
	if _, err := io.ReadFull(conn, nTypes); err != nil {
		return false, false
	}
	if nTypes[0] == 0 {
		return false, false
	}
	types := make([]byte, int(nTypes[0]))
	if _, err := io.ReadFull(conn, types); err != nil {
		return false, false
	}

	hasNone := bytes.Contains(types, []byte{1})
	hasVNC := bytes.Contains(types, []byte{2})

	if hasNone {
		if _, err := conn.Write([]byte{1}); err != nil {
			return false, false
		}
		if vncReadSecurityResult(conn) {
			return true, true
		}
	}

	if !hasVNC {
		return false, false
	}

	if _, err := conn.Write([]byte{2}); err != nil {
		return false, false
	}
	return vncDoVNCAuth(conn, password), false
}

func vncReadSecurityResult(conn net.Conn) bool {
	var res uint32
	if err := binary.Read(conn, binary.BigEndian, &res); err != nil {
		return false
	}
	return res == 0
}

func vncDoVNCAuth(conn net.Conn, password string) bool {
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return false
	}

	resp, err := vncEncryptChallenge(challenge, password)
	if err != nil {
		return false
	}
	if _, err := conn.Write(resp); err != nil {
		return false
	}

	return vncReadSecurityResult(conn)
}

func vncEncryptChallenge(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, errors.New("invalid challenge length")
	}

	key := make([]byte, 8)
	copy(key, []byte(password))
	for i := 0; i < 8; i++ {
		key[i] = reverseByte(key[i])
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 16)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out, nil
}

func reverseByte(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func resolveVNCAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 5900), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 5900), nil
	}
	return host, nil
}

