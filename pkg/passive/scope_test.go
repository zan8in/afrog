package passive

import "testing"

func TestMatchScope(t *testing.T) {
	cases := []struct {
		pattern string
		s       string
		want    bool
	}{
		// 不含 * -> 包含匹配（不区分大小写）
		{"logout", "/user/logout", true},
		{"Logout", "/user/logout", true},
		{"logout", "/user/login", false},
		{"example.com", "www.example.com", true},
		// 含 * -> 通配
		{"*google*", "www.google-analytics.com", true},
		{"*google*", "www.example.com", false},
		{"*.gov.cn", "www.test.gov.cn", true},
		{"*.gov.cn", "www.test.gov.com", false},
		{"api.*", "api.example.com", true},
		{"api.*", "xapi.example.com", false},
		{"a*b", "axxxb", true},
		{"a*b", "xaxxxb", false},
		{"a*b", "axxxby", false},
		{"*", "anything", true},
		// 空 pattern 不该变成「排除一切」
		{"", "/user/logout", false},
		{"  ", "/user/logout", false},
	}
	for _, c := range cases {
		if got := matchScope(c.pattern, c.s); got != c.want {
			t.Fatalf("matchScope(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestScopeEmptyAllowsAll(t *testing.T) {
	var s Scope
	if !s.Empty() {
		t.Fatalf("零值 Scope 应为空")
	}
	if !s.AllowsHost("evil.example.com") {
		t.Fatalf("空 Scope 必须放行所有 Host")
	}
	if !s.AllowsPath("/user/logout") {
		t.Fatalf("空 Scope 必须放行所有路径")
	}
}

func TestScopeHostAllowIsWhitelist(t *testing.T) {
	s := Scope{HostAllow: []string{"target.com"}}
	if !s.AllowsHost("api.target.com") {
		t.Fatalf("白名单内的 Host 必须放行")
	}
	if s.AllowsHost("analytics.third-party.com") {
		t.Fatalf("白名单外的 Host 必须被排除")
	}
	// 白名单非空时，拿不到 Host 仍放行——避免因信息缺失而误伤。
	if !s.AllowsHost("") {
		t.Fatalf("空 Host 应放行，交由后续环节判定")
	}
}

func TestScopeHostDenyWins(t *testing.T) {
	// Deny 优先级高于 Allow：同一个 Host 同时命中两条时以排除为准。
	s := Scope{HostAllow: []string{"example.com"}, HostDeny: []string{"*cdn*"}}
	if s.AllowsHost("cdn.example.com") {
		t.Fatalf("HostDeny 必须优先于 HostAllow")
	}
	if !s.AllowsHost("www.example.com") {
		t.Fatalf("未命中 Deny 的白名单 Host 应放行")
	}
}

func TestScopePathDeny(t *testing.T) {
	s := Scope{PathDeny: []string{"logout", "/pay", "*/search*"}}
	if s.AllowsPath("/user/logout") {
		t.Fatalf("含 logout 的路径必须被排除")
	}
	if s.AllowsPath("/api/pay/confirm") {
		t.Fatalf("含 /pay 的路径必须被排除")
	}
	if s.AllowsPath("/v1/search/items") {
		t.Fatalf("命中通配的路径必须被排除")
	}
	if !s.AllowsPath("/api/user?id=1") {
		t.Fatalf("未命中规则的路径必须放行")
	}
}
