package fingerprint

import "testing"

func TestKeyFromTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"empty", "", ""},
		{"http default port", "http://example.com", "example.com:80"},
		{"https default port", "https://example.com", "example.com:443"},
		{"explicit port", "http://example.com:8080", "example.com:8080"},
		{"https explicit port", "https://example.com:8443", "example.com:8443"},
		{"with path", "http://example.com/path", "example.com:80"},
		{"with query", "http://example.com?a=1", "example.com:80"},
		{"ip address", "http://192.168.1.1:8080", "192.168.1.1:8080"},
		{"trailing slash", "https://example.com/", "example.com:443"},
		{"no scheme", "example.com", ""},
		{"invalid url", "://bad", ""},
		{"whitespace", "  http://example.com:8080  ", "example.com:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyFromTarget(tt.target)
			if got != tt.want {
				t.Errorf("KeyFromTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}
