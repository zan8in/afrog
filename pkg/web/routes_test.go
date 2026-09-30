package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 浏览器地址栏导航与刷新时发送的 Accept。
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// XHR / fetch 不显式设置 Accept 时的默认值。
const xhrAccept = "*/*"

// 根路径别名与新前端页面同名的路径。
var conflictedPaths = []string{"/reports", "/pocs", "/projects", "/ledger", "/assets", "/schedules"}

func mustRouter(t *testing.T) http.Handler {
	t.Helper()
	h, err := setupHandler()
	if err != nil {
		t.Fatalf("setupHandler: %v", err)
	}
	return h
}

// probe 用指定 Accept 发起 GET，返回状态码与 Content-Type。
func probe(t *testing.T, h http.Handler, path, accept string) (int, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec.Code, rec.Header().Get("Content-Type")
}

// TestSPAPagesWinOverLegacyAliases 锁定同名冲突的判定：
// 浏览器导航必须拿到页面，而不是裸 JSON。
func TestSPAPagesWinOverLegacyAliases(t *testing.T) {
	h := mustRouter(t)

	for _, path := range conflictedPaths {
		code, ct := probe(t, h, path, browserAccept)
		if code != http.StatusOK {
			t.Errorf("%s (browser) status = %d, want 200", path, code)
		}
		if !strings.Contains(ct, "text/html") {
			t.Errorf("%s (browser) content-type = %q, want text/html", path, ct)
		}
	}
}

// TestLegacyAliasesStillAnswerPrograms 旧前端（XHR）必须继续命中根路径接口。
// 这些请求没有 token，因此断言的期望是 401 JSON 而非 200。
func TestLegacyAliasesStillAnswerPrograms(t *testing.T) {
	h := mustRouter(t)

	for _, path := range conflictedPaths {
		code, ct := probe(t, h, path, xhrAccept)
		if code != http.StatusUnauthorized {
			t.Errorf("%s (xhr) status = %d, want 401", path, code)
		}
		if !strings.Contains(ct, "application/json") {
			t.Errorf("%s (xhr) content-type = %q, want application/json", path, ct)
		}
	}
}

// TestNonConflictingAliasesKeepJSON 未与页面重名的别名不参与判定，
// 即使直接用浏览器打开也应看到 JSON，便于排查。
func TestNonConflictingAliasesKeepJSON(t *testing.T) {
	h := mustRouter(t)

	for _, path := range []string{"/me", "/server/info", "/nav/badges", "/vulns"} {
		code, ct := probe(t, h, path, browserAccept)
		if code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", path, code)
		}
		if !strings.Contains(ct, "application/json") {
			t.Errorf("%s content-type = %q, want application/json", path, ct)
		}
	}
}

// TestAPIPrefixedRoutesUnaffected /api/* 是唯一正式入口，不受该判定影响。
func TestAPIPrefixedRoutesUnaffected(t *testing.T) {
	h := mustRouter(t)

	for _, path := range []string{"/api/reports", "/api/pocs", "/api/projects", "/api/ledger"} {
		code, ct := probe(t, h, path, browserAccept)
		if code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", path, code)
		}
		if !strings.Contains(ct, "application/json") {
			t.Errorf("%s content-type = %q, want application/json", path, ct)
		}
	}
}

// TestLegacyAPIRouteMatcher 直接覆盖判定函数本身。
func TestLegacyAPIRouteMatcher(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{browserAccept, false},
		{"text/html", false},
		{"*/*", true},
		{"application/json, text/plain, */*", true},
		{"text/event-stream", true},
		{"", true},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/reports", nil)
		if c.accept != "" {
			req.Header.Set("Accept", c.accept)
		}
		if got := legacyAPIRoute(req, nil); got != c.want {
			t.Errorf("legacyAPIRoute(Accept=%q) = %v, want %v", c.accept, got, c.want)
		}
	}
}
