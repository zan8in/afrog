package gox

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["winrm-weak-login"] = winrm_weak_login
}

func winrm_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	endpoint, err := resolveWinRMEndpoint(target)
	if err != nil {
		return err
	}

	usernames := []string{"administrator", "admin", "guest", "user", "test"}
	passwords := []string{"", "admin", "administrator", "123456", "12345678", "password", "P@ssw0rd", "123123", "111111", "000000"}

	maxTries := 50
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	timeoutSec := 6
	if v := variableMap["timeout_sec"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			timeoutSec = n
		}
	}

	connectTimeoutSec := 3
	if v := variableMap["connect_timeout_sec"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			connectTimeoutSec = n
		}
	}

	headerTimeoutSec := 4
	if v := variableMap["header_timeout_sec"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			headerTimeoutSec = n
		}
	}

	clients, err := newWinRMClients(endpoint, time.Duration(connectTimeoutSec)*time.Second, time.Duration(headerTimeoutSec)*time.Second)
	if err != nil {
		return err
	}

	mode, ok := winrmPreflight(clients.basic, endpoint, time.Duration(timeoutSec)*time.Second)
	if ok && mode == winrmAuthNone {
		setResponse("success;user=unauthorized;pass=none", variableMap)
		setRequest(endpoint, variableMap)
		setTarget(endpoint, variableMap)
		setFullTarget(endpoint, variableMap)
		return nil
	}

	tried := 0
	for _, u := range usernames {
		for _, p := range passwords {
			if maxTries > 0 && tried >= maxTries {
				setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
				setRequest(endpoint, variableMap)
				setTarget(endpoint, variableMap)
				setFullTarget(endpoint, variableMap)
				return nil
			}
			tried++
			if winrmAuthAttempt(clients, endpoint, u, p, mode, time.Duration(timeoutSec)*time.Second) {
				setResponse(fmt.Sprintf("success;user=%s;pass=%s", u, p), variableMap)
				setRequest(endpoint, variableMap)
				setTarget(endpoint, variableMap)
				setFullTarget(endpoint, variableMap)
				return nil
			}
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(endpoint, variableMap)
	setTarget(endpoint, variableMap)
	setFullTarget(endpoint, variableMap)
	return nil
}

type winrmAuthMode int

const (
	winrmAuthUnknown winrmAuthMode = iota
	winrmAuthNone
	winrmAuthBasic
	winrmAuthNTLM
)

type winrmClients struct {
	basic *http.Client
	ntlm  *http.Client
}

func newWinRMClients(endpoint string, dialTimeout, headerTimeout time.Duration) (*winrmClients, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid winrm endpoint: %s", endpoint)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   2,
	}
	if u.Scheme == "https" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}

	return &winrmClients{
		basic: &http.Client{Transport: tr},
		ntlm:  &http.Client{Transport: &ntlmssp.Negotiator{RoundTripper: tr}},
	}, nil
}

func winrmPreflight(client *http.Client, endpoint string, timeout time.Duration) (winrmAuthMode, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(winrmIdentifyEnvelope(endpoint, "")))
	if err != nil {
		return winrmAuthUnknown, false
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Accept", "application/soap+xml, application/xml, text/xml, */*")
	req.Header.Set("User-Agent", "afrog")

	resp, err := client.Do(req)
	if err != nil {
		return winrmAuthUnknown, false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		b := strings.ToLower(string(body))
		if strings.Contains(b, "identifyresponse") || strings.Contains(b, "wsmanidentity.xsd") {
			return winrmAuthNone, true
		}
		return winrmAuthUnknown, true
	}

	if resp.StatusCode == http.StatusUnauthorized {
		h := strings.ToLower(resp.Header.Get("Www-Authenticate"))
		if strings.Contains(h, "basic") {
			return winrmAuthBasic, true
		}
		if strings.Contains(h, "ntlm") || strings.Contains(h, "negotiate") {
			return winrmAuthNTLM, true
		}
		return winrmAuthUnknown, true
	}

	return winrmAuthUnknown, true
}

func winrmAuthAttempt(clients *winrmClients, endpoint, username, password string, mode winrmAuthMode, timeout time.Duration) bool {
	msgID, _ := generateUUID()
	envelope := winrmIdentifyEnvelope(endpoint, msgID)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(envelope))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Accept", "application/soap+xml, application/xml, text/xml, */*")
	req.Header.Set("User-Agent", "afrog")
	req.SetBasicAuth(username, password)

	var client *http.Client
	if mode == winrmAuthBasic {
		client = clients.basic
	} else {
		client = clients.ntlm
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	b := strings.ToLower(string(body))
	return strings.Contains(b, "identifyresponse") || strings.Contains(b, "wsmanidentity.xsd")
}

func winrmIdentifyEnvelope(to string, msgID string) string {
	if msgID == "" {
		return fmt.Sprintf(
			`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header><wsa:To>%s</wsa:To><wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Identify</wsa:Action><wsman:ResourceURI>http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd</wsman:ResourceURI><wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize><wsman:OperationTimeout>PT5S</wsman:OperationTimeout></s:Header><s:Body><wsmid:Identify/></s:Body></s:Envelope>`,
			to,
		)
	}
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header><wsa:To>%s</wsa:To><wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Identify</wsa:Action><wsa:MessageID>uuid:%s</wsa:MessageID><wsman:ResourceURI>http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd</wsman:ResourceURI><wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize><wsman:OperationTimeout>PT5S</wsman:OperationTimeout></s:Header><s:Body><wsmid:Identify/></s:Body></s:Envelope>`,
		to,
		msgID,
	)
}

func resolveWinRMEndpoint(target string) (string, error) {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", err
		}
		scheme := u.Scheme
		if scheme == "" {
			scheme = "http"
		}
		host := u.Host
		if host == "" {
			host = u.Path
			u.Path = ""
		}
		hn := u.Hostname()
		if hn == "" {
			if strings.Contains(host, "/") {
				host = strings.Split(host, "/")[0]
			}
			hn = host
		}
		port := u.Port()
		if port == "" {
			if scheme == "https" {
				host = fmt.Sprintf("%s:%d", hn, 5986)
			} else {
				host = fmt.Sprintf("%s:%d", hn, 5985)
			}
		}
		path := u.Path
		if path == "" || path == "/" {
			path = "/wsman"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return fmt.Sprintf("%s://%s%s", scheme, host, path), nil
	}

	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("http://%s:%d/wsman", hostname, 5985), nil
	}
	if !hasPort(host) {
		host = fmt.Sprintf("%s:%d", host, 5985)
	}

	scheme := "http"
	if h, p, err := net.SplitHostPort(host); err == nil && h != "" && p == "5986" {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s/wsman", scheme, host), nil
}
