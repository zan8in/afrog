package runner

import "testing"

func TestEnsureURLScheme(t *testing.T) {
	tests := []struct {
		target string
		scheme string
		want   string
	}{
		{"127.0.0.1:3306", "http://", "http://127.0.0.1:3306"},
		{"example.com", "https://", "https://example.com"},
		{"http://a.example", "https://", "http://a.example"},
		{"https://a.example", "http://", "https://a.example"},
	}
	for _, tc := range tests {
		if got := ensureURLScheme(tc.target, tc.scheme); got != tc.want {
			t.Fatalf("ensureURLScheme(%q, %q) = %q, want %q", tc.target, tc.scheme, got, tc.want)
		}
	}
}

// 非 HTTP PoC 的目标是 host:port，解析 Host/Port 不能依赖 scheme 是否存在。
func TestSplitHostPortWithoutScheme(t *testing.T) {
	for _, target := range []string{"127.0.0.1:13306", "https://127.0.0.1:13306", "mysql.example.com:3306"} {
		host, port := splitHostPort(target)
		if host == "" || port == "" {
			t.Fatalf("splitHostPort(%q) = (%q, %q), want non-empty host and port", target, host, port)
		}
	}
}
