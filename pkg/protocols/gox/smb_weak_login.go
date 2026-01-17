package gox

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["smb-weak-login"] = smb_weak_login
}

func smb_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveSMBAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"administrator", "admin", "guest", "root", "test", "user", "smb"}
	passwords := []string{"", "admin", "123456", "12345678", "password", "root", "guest", "toor", "1qaz2wsx", "qwer1234", "000000", "111111", "123123"}

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
			if smbAuthAttempt(host, u, p) {
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

func smbAuthAttempt(host, username, password string) bool {
	user, domain := splitSMBUser(username)

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: password,
			Domain:   domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return false
	}
	defer s.Logoff()

	share, err := s.Mount("IPC$")
	if err != nil {
		return false
	}
	_ = share.Umount()

	return true
}

func splitSMBUser(username string) (string, string) {
	if username == "" {
		return "", ""
	}
	if i := strings.Index(username, `\`); i >= 0 {
		return username[i+1:], username[:i]
	}
	if i := strings.Index(username, `/`); i >= 0 {
		return username[i+1:], username[:i]
	}
	return username, ""
}

func resolveSMBAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 445), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 445), nil
	}
	return host, nil
}
