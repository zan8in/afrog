package misconfig

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

func newTx(t *testing.T, rawURL string, headers http.Header) *passive.CapturedTransaction {
	t.Helper()
	return &passive.CapturedTransaction{
		ID:      "tx-1",
		Request: &passive.CapturedRequest{Method: "GET", URL: mustURL(t, rawURL), Headers: http.Header{}},
		Response: &passive.CapturedResponse{
			Status:  200,
			Headers: headers,
			Body:    []byte("ok"),
		},
	}
}

func detect(t *testing.T, tx *passive.CapturedTransaction) []passive.Finding {
	t.Helper()
	d := New(DefaultOptions())
	// 刻意传 nil Prober：本检测器零流量，任何重放调用都说明实现走偏了。
	findings, err := d.Detect(context.Background(), tx, nil)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	return findings
}

func findByLocation(findings []passive.Finding, location string) (passive.Finding, bool) {
	for _, f := range findings {
		if f.Location == location {
			return f, true
		}
	}
	return passive.Finding{}, false
}

func TestInterestGating(t *testing.T) {
	d := New(DefaultOptions())

	// 既无 Set-Cookie 也无会话参数的普通响应：不该进检测池。
	plain := newTx(t, "https://example.com/app", http.Header{})
	if d.Interest(plain) {
		t.Fatalf("无 Cookie、无会话参数的响应不应被判定为需检测")
	}

	// 下发 Cookie 的响应：需要检测。
	withCookie := newTx(t, "https://example.com/app", http.Header{"Set-Cookie": {"a=1"}})
	if !d.Interest(withCookie) {
		t.Fatalf("下发 Cookie 的响应应被判定为需检测")
	}

	// URL 带会话参数：需要检测。
	withSID := newTx(t, "https://example.com/app?jsessionid=ABC", http.Header{})
	if !d.Interest(withSID) {
		t.Fatalf("URL 带会话参数应被判定为需检测")
	}
}

// TestZeroTraffic 锁定「B 档检测器宁可不报也不发请求」这一约束。
func TestZeroTraffic(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{"Set-Cookie": {"sid=1"}})
	// 传入的 Prober 一旦被调用就 panic，从而证明检测路径完全没有触网。
	d := New(DefaultOptions())
	if _, err := d.Detect(context.Background(), tx, panicProber{}); err != nil {
		t.Fatalf("Detect error: %v", err)
	}
}

type panicProber struct{}

func (panicProber) Replay(context.Context, *passive.CapturedTransaction) (*passive.CapturedResponse, error) {
	panic("misconfig 检测器不应发起任何重放")
}

func (panicProber) Mutate(context.Context, *passive.CapturedTransaction, passive.Mutation) (*passive.CapturedResponse, error) {
	panic("misconfig 检测器不应发起任何重放")
}

func TestCookieSecureOnlyOnHTTPS(t *testing.T) {
	// HTTPS + 缺 Secure：应报。
	httpsTx := newTx(t, "https://example.com/app", http.Header{"Set-Cookie": {"sid=abc; Path=/"}})
	if _, ok := findByLocation(detect(t, httpsTx), "cookie-secure:sid"); !ok {
		t.Fatalf("HTTPS 下缺 Secure 的 Cookie 应被报出")
	}

	// HTTP 下缺 Secure 不构成问题：报文本来就是明文。
	httpTx := newTx(t, "http://example.com/app", http.Header{"Set-Cookie": {"sid=abc; Path=/"}})
	if _, ok := findByLocation(detect(t, httpTx), "cookie-secure:sid"); ok {
		t.Fatalf("HTTP 下不应报缺 Secure")
	}
}

func TestCookieFlagsReported(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{
		"Set-Cookie": {"sid=abc; Path=/"},
	})
	findings := detect(t, tx)

	if f, ok := findByLocation(findings, "cookie-httponly:sid"); !ok {
		t.Fatalf("缺 HttpOnly 应被报出")
	} else if f.Severity != "medium" {
		t.Fatalf("会话类 Cookie 缺 HttpOnly 级别应为 medium，实际 %s", f.Severity)
	}
	if _, ok := findByLocation(findings, "cookie-samesite:sid"); !ok {
		t.Fatalf("缺 SameSite 应被报出")
	}
}

func TestCookieWithAllFlagsIsClean(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{
		"Set-Cookie": {"sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"},
	})
	if findings := detect(t, tx); len(findings) != 0 {
		t.Fatalf("属性完整的 Cookie 不应产生任何发现，实际 %d 条", len(findings))
	}
}

func TestCookieDomainTooBroad(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{
		"Set-Cookie": {"x=1; Domain=.com; Secure; HttpOnly; SameSite=Lax"},
	})
	if _, ok := findByLocation(detect(t, tx), "cookie-domain:x"); !ok {
		t.Fatalf("Domain 落到裸顶级域应被报出")
	}

	// 正常父域共享不算漏洞：这是常见且常常有意的配置。
	normal := newTx(t, "https://app.example.com/app", http.Header{
		"Set-Cookie": {"x=1; Domain=example.com; Secure; HttpOnly; SameSite=Lax"},
	})
	if _, ok := findByLocation(detect(t, normal), "cookie-domain:x"); ok {
		t.Fatalf("正常父域共享不应被报为 Domain 过宽")
	}
}

func TestCacheableHTTPS(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{
		"Set-Cookie":    {"sid=abc; Secure; HttpOnly; SameSite=Lax"},
		"Cache-Control": {"public, max-age=3600"},
	})
	if _, ok := findByLocation(detect(t, tx), "cacheable-https:sid"); !ok {
		t.Fatalf("HTTPS + Cookie + public 缓存应被报出")
	}
}

func TestSessionIDInURL(t *testing.T) {
	pathForm := newTx(t, "https://example.com/app;jsessionid=ABC123", http.Header{})
	if _, ok := findByLocation(detect(t, pathForm), "session-id-in-url:jsessionid"); !ok {
		t.Fatalf("路径参数形态的会话标识应被报出")
	}

	queryForm := newTx(t, "https://example.com/app?PHPSESSID=abc", http.Header{})
	if _, ok := findByLocation(detect(t, queryForm), "session-id-in-url:PHPSESSID"); !ok {
		t.Fatalf("查询串形态的会话标识应被报出")
	}
}

// TestAggregatesByHost 锁定「按 Host 聚合」口径：Target 必须是 origin 而不是完整路径，
// 否则同一站点在不同路径上重复下发同一个 Cookie 会变成多条记录。
func TestAggregatesByHost(t *testing.T) {
	a := newTx(t, "https://example.com/one", http.Header{"Set-Cookie": {"sid=1"}})
	b := newTx(t, "https://example.com/two", http.Header{"Set-Cookie": {"sid=1"}})

	fa := detect(t, a)
	fb := detect(t, b)
	if len(fa) == 0 || len(fb) == 0 {
		t.Fatalf("两处均应产生发现")
	}
	if fa[0].Target != "https://example.com" {
		t.Fatalf("Target 应为 origin，实际 %q", fa[0].Target)
	}
	if fa[0].Target != fb[0].Target || fa[0].Location != fb[0].Location {
		t.Fatalf("不同路径下的同一 Cookie 问题应归并到同一 (Target, Location)")
	}
}

func TestFindingsAreCertain(t *testing.T) {
	tx := newTx(t, "https://example.com/app", http.Header{"Set-Cookie": {"sid=1"}})
	for _, f := range detect(t, tx) {
		if f.Confidence != passive.ConfidenceCertain {
			t.Fatalf("发现 %s 的置信度应为 Certain（否则会被调度层拦下）", f.Location)
		}
		if f.Detector != DetectorName || f.VulnType != VulnType {
			t.Fatalf("发现的 Detector/VulnType 归类不正确: %+v", f)
		}
	}
}
