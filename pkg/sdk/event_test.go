package sdk

import (
	"strings"
	"testing"
)

func TestRedactExchange(t *testing.T) {
	names := toSet(DefaultRedactedHeaders)

	ex := Exchange{
		Request: "GET /admin HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Authorization: Bearer super-secret-token\r\n" +
			"Cookie: session=abc123\r\n" +
			"User-Agent: afrog\r\n" +
			"\r\n" +
			"Authorization: this-is-body-not-a-header\r\n",
		Response: "HTTP/1.1 200 OK\r\n" +
			"Set-Cookie: session=xyz789; HttpOnly\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<html>ok</html>",
		RequestHeaders:  map[string]string{"authorization": "Bearer super-secret-token", "user-agent": "afrog"},
		ResponseHeaders: map[string]string{"set-cookie": "session=xyz789", "content-type": "text/html"},
	}

	redactExchange(&ex, names)

	for _, secret := range []string{"super-secret-token", "abc123", "xyz789"} {
		if strings.Contains(ex.Request, secret) {
			t.Errorf("request still contains %q:\n%s", secret, ex.Request)
		}
		if strings.Contains(ex.Response, secret) {
			t.Errorf("response still contains %q:\n%s", secret, ex.Response)
		}
	}
	if ex.RequestHeaders["authorization"] != redactedValue {
		t.Errorf("request header not redacted: %q", ex.RequestHeaders["authorization"])
	}
	if ex.ResponseHeaders["set-cookie"] != redactedValue {
		t.Errorf("response header not redacted: %q", ex.ResponseHeaders["set-cookie"])
	}

	// Non-sensitive data must survive untouched.
	if !strings.Contains(ex.Request, "User-Agent: afrog") {
		t.Errorf("redaction removed a harmless header:\n%s", ex.Request)
	}
	if !strings.Contains(ex.Response, "<html>ok</html>") {
		t.Errorf("redaction damaged the response body:\n%s", ex.Response)
	}
	// A header-looking line inside the body must not be rewritten, because
	// redaction stops at the blank line that ends the headers.
	if !strings.Contains(ex.Request, "this-is-body-not-a-header") {
		t.Errorf("redaction leaked past the header section:\n%s", ex.Request)
	}
}

func TestRedactExchange_NoNamesIsNoOp(t *testing.T) {
	original := Exchange{
		Request:        "GET / HTTP/1.1\r\nAuthorization: keep-me\r\n\r\n",
		RequestHeaders: map[string]string{"authorization": "keep-me"},
	}
	ex := original
	redactExchange(&ex, nil)

	if ex.Request != original.Request {
		t.Errorf("request changed with no redaction configured:\n%s", ex.Request)
	}
	if ex.RequestHeaders["authorization"] != "keep-me" {
		t.Errorf("header changed with no redaction configured: %q", ex.RequestHeaders["authorization"])
	}
}

func TestStats_Duration(t *testing.T) {
	var s Stats
	s.StartTime = s.StartTime.Add(0)

	// A running scan measures up to now, so the duration must be non-negative
	// rather than the huge negative value a zero EndTime would produce.
	if d := s.Duration(); d < 0 {
		t.Errorf("Duration() = %v, want >= 0 while the scan is running", d)
	}
}
