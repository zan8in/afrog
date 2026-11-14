package exposure

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/guard"
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

func newTx(t *testing.T, rawURL string) *passive.CapturedTransaction {
	t.Helper()
	return &passive.CapturedTransaction{
		ID:      "tx-1",
		Request: &passive.CapturedRequest{Method: "GET", URL: mustURL(t, rawURL), Headers: http.Header{}},
	}
}

// fakeProber 记录所有探针路径，并按回调返回预设响应。
type fakeProber struct {
	mu       sync.Mutex
	requests []string
	respond  func(path string) *passive.CapturedResponse
}

func (f *fakeProber) record(tx *passive.CapturedTransaction) string {
	p := tx.Request.URL.EscapedPath()
	if tx.Request.URL.RawQuery != "" {
		p += "?" + tx.Request.URL.RawQuery
	}
	f.mu.Lock()
	f.requests = append(f.requests, p)
	f.mu.Unlock()
	return p
}

func (f *fakeProber) Replay(_ context.Context, tx *passive.CapturedTransaction) (*passive.CapturedResponse, error) {
	p := f.record(tx)
	if f.respond == nil {
		return nil, nil
	}
	return f.respond(p), nil
}

func (f *fakeProber) Mutate(ctx context.Context, tx *passive.CapturedTransaction, _ passive.Mutation) (*passive.CapturedResponse, error) {
	return f.Replay(ctx, tx)
}

func (f *fakeProber) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.requests {
		if p == path {
			return true
		}
	}
	return false
}

func (f *fakeProber) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func resp(status int, body string, header http.Header) *passive.CapturedResponse {
	if header == nil {
		header = http.Header{}
	}
	return &passive.CapturedResponse{Status: status, Headers: header, Body: []byte(body)}
}

func notFound() *passive.CapturedResponse { return resp(404, "not found", nil) }

// oneBase 把探测收敛到根目录，便于在测试里断言路径。
func oneBase() Options {
	o := DefaultOptions()
	o.MaxBasePaths = 1
	o.MaxDepth = 1
	return o
}

// TestSignatureValidatesGitHead 锁定「只认内容签名」：只有真正的 .git/HEAD 才算命中。
func TestSignatureValidatesGitHead(t *testing.T) {
	prober := &fakeProber{respond: func(p string) *passive.CapturedResponse {
		if p == "/.git/HEAD" {
			return resp(200, "ref: refs/heads/main\n", nil)
		}
		return notFound()
	}}
	d := New(oneBase())

	findings, err := d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("应恰好命中 1 条，实际 %d 条", len(findings))
	}
	f := findings[0]
	if f.Location != ".git/HEAD" {
		t.Fatalf("Location 应为 .git/HEAD，实际 %q", f.Location)
	}
	if f.Target != "https://example.com/.git/HEAD" {
		t.Fatalf("Target 应为精确 URL，实际 %q", f.Target)
	}
	if f.Confidence != passive.ConfidenceCertain {
		t.Fatalf("暴露类发现的置信度应为 Certain")
	}
	if f.Severity != "high" {
		t.Fatalf(".git/HEAD 的级别应为 high，实际 %s", f.Severity)
	}
}

// TestRejectsWAFSoftBlock 锁定零误报底线：200 + 拦截页绝不算命中。
func TestRejectsWAFSoftBlock(t *testing.T) {
	prober := &fakeProber{respond: func(p string) *passive.CapturedResponse {
		if p == "/.git/HEAD" {
			// 典型软拦截：200，但正文是拦截页。
			return resp(200, "<!DOCTYPE html><html><body>Access Denied</body></html>",
				http.Header{"Content-Type": {"text/html"}})
		}
		return notFound()
	}}
	d := New(oneBase())

	findings, _ := d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
	if len(findings) != 0 {
		t.Fatalf("200 + HTML 拦截页不应被判为命中，实际 %d 条", len(findings))
	}
}

// TestEnvSignatureRequiresKeyValue 锁定 .env 的签名要求。
func TestEnvSignatureRequiresKeyValue(t *testing.T) {
	prober := &fakeProber{respond: func(p string) *passive.CapturedResponse {
		switch p {
		case "/.env":
			return resp(200, "APP_ENV=production\nDB_PASSWORD=s3cr3t\n", nil)
		case "/.svn/entries":
			return resp(200, "12\n", nil)
		}
		return notFound()
	}}
	d := New(oneBase())

	findings, _ := d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
	if _, ok := findLocation(findings, ".env"); !ok {
		t.Fatalf(".env 的 KEY=VALUE 签名应被识别")
	}
	// "12\n" 只有一行，够不上旧格式 entries 的判定（需要版本号 + 目录名两行）。
	if _, ok := findLocation(findings, ".svn/entries"); ok {
		t.Fatalf("仅一行的响应不应判为 .svn/entries")
	}
}

func findLocation(findings []passive.Finding, loc string) (passive.Finding, bool) {
	for _, f := range findings {
		if f.Location == loc {
			return f, true
		}
	}
	return passive.Finding{}, false
}

// TestBypassOnlyOnIntercept 锁定「绕过仅在拦截信号下触发」。
func TestBypassOnlyOnIntercept(t *testing.T) {
	t.Run("被拦截时尝试绕过", func(t *testing.T) {
		prober := &fakeProber{respond: func(p string) *passive.CapturedResponse {
			switch p {
			case "/.git/HEAD":
				return resp(403, "forbidden", nil)
			case "/./.git/HEAD":
				return resp(200, "ref: refs/heads/main\n", nil)
			}
			return notFound()
		}}
		d := New(oneBase())

		findings, _ := d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
		if len(findings) != 1 {
			t.Fatalf("被拦截后应通过绕过命中 1 条，实际 %d 条", len(findings))
		}
		if byp, _ := findings[0].Extra["bypass"].(bool); !byp {
			t.Fatalf("该命中的 Extra.bypass 应为 true")
		}
		if findings[0].Target != "https://example.com/./.git/HEAD" {
			t.Fatalf("Target 应为绕过路径，实际 %q", findings[0].Target)
		}
	})

	t.Run("未拦截时不绕过", func(t *testing.T) {
		prober := &fakeProber{respond: func(p string) *passive.CapturedResponse {
			return notFound()
		}}
		d := New(oneBase())

		_, _ = d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
		if prober.called("/./.git/HEAD") {
			t.Fatalf("普通 404 不应触发绕过变体")
		}
	})
}

// TestProbeBudget 锁定核心探测的请求预算上界。
func TestProbeBudget(t *testing.T) {
	prober := &fakeProber{respond: func(string) *passive.CapturedResponse {
		return notFound()
	}}
	opts := oneBase()
	opts.MaxProbes = 3
	d := New(opts)

	_, _ = d.Detect(context.Background(), newTx(t, "https://example.com/"), prober)
	if got := prober.count(); got > 3 {
		t.Fatalf("核心探测请求数应被预算封顶为 3，实际 %d", got)
	}
}

// TestHostClaimedOnce 锁定「每 origin 一次性」的认领语义。
func TestHostClaimedOnce(t *testing.T) {
	d := New(DefaultOptions())
	first := newTx(t, "https://example.com/")
	second := newTx(t, "https://example.com/other")

	if !d.Interest(first) {
		t.Fatalf("首次遇到该 origin 应认领成功")
	}
	if d.Interest(second) {
		t.Fatalf("同一 origin 的后续流量不应再次认领")
	}
	// 不同 origin 可各自认领一次。
	other := newTx(t, "https://other.example.com/")
	if !d.Interest(other) {
		t.Fatalf("不同 origin 应可独立认领")
	}
}

func TestInterestSkipsStaticAssets(t *testing.T) {
	d := New(DefaultOptions())
	if d.Interest(newTx(t, "https://example.com/static/app.js")) {
		t.Fatalf("静态资源不应触发探针")
	}
}

// TestGuardDeniesProbe 锁定闸门语义：deny/ask 与白名单硬边界都必须挡住探针，
// 且跳过原因能直接展示（而不是笼统的「已完成探测」）。
func TestGuardDeniesProbe(t *testing.T) {
	t.Cleanup(func() { guard.Configure(nil, nil) })

	// deny：该动作整体关闭。
	guard.Configure(map[string]string{"exposure-probe": "deny"}, nil)
	d := New(DefaultOptions())
	tx := newTx(t, "https://example.com/")
	if d.Interest(tx) {
		t.Fatalf("deny 模式下不应认领探测权")
	}
	if reason := d.InterestReason(tx); !strings.Contains(reason, "安全策略") {
		t.Fatalf("拒绝原因应指向安全策略，实际 = %q", reason)
	}
	// 同一 origin 的后续流量走缓存：既不重复裁决，也不能放行。
	if d.Interest(newTx(t, "https://example.com/other")) {
		t.Fatalf("被拒的 origin 不应在后续流量上重新认领")
	}

	// 白名单是硬边界：名单外的 origin 不探，名单内的照常探。
	guard.Configure(nil, []string{"*.corp.example"})
	d2 := New(DefaultOptions())
	if d2.Interest(newTx(t, "https://evil.example/")) {
		t.Fatalf("白名单外的 origin 不应探测")
	}
	if !d2.Interest(newTx(t, "https://api.corp.example/")) {
		t.Fatalf("白名单内的 origin 应可探测")
	}

	// ask 在无人值守的服务端等价于拒绝，绝不静默放行。
	guard.Configure(map[string]string{"exposure-probe": "ask"}, nil)
	d3 := New(DefaultOptions())
	if d3.Interest(newTx(t, "https://example.com/")) {
		t.Fatalf("ask 模式下不应自动放行")
	}
}

func TestBuildBasePaths(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"https://example.com/", []string{"/"}},
		{"https://example.com/app/user/profile", []string{"/", "/app/", "/app/user/"}},
		{"https://example.com/app/index.php", []string{"/", "/app/"}},
		{"https://example.com/a/b/c/d", []string{"/", "/a/", "/a/b/"}},
	}
	for _, c := range cases {
		got := buildBasePaths(mustURL(t, c.raw), 2, 3)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("buildBasePaths(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestBypassVariantShapes(t *testing.T) {
	variants := bypassVariants("/", ".git/HEAD")
	want := map[string]bool{
		"/./.git/HEAD":                true,
		"//.git/HEAD":                 true,
		"/.git/HEAD/.":                true,
		"/.git/HEAD%20":               true,
		"/%2egit/HEAD":                true,
		"/.git/HEAD%23":               true,
		"/.git/HEAD?x=1":              true,
		"/.git%2fHEAD":                true,
		"/_afrog-bypass/../.git/HEAD": true,
	}
	for _, v := range variants {
		delete(want, v)
	}
	if len(want) != 0 {
		t.Fatalf("缺少预期的绕过变体: %v", want)
	}
	// 原路径不应出现在变体里（它已经单独请求过）。
	for _, v := range variants {
		if v == "/.git/HEAD" {
			t.Fatalf("原路径不应作为绕过变体重复出现")
		}
	}
}

func TestInterceptedSignals(t *testing.T) {
	if !intercepted(resp(403, "", nil)) {
		t.Fatalf("403 应被判定为拦截")
	}
	if !intercepted(resp(429, "", nil)) {
		t.Fatalf("429 应被判定为拦截")
	}
	if intercepted(resp(404, "", nil)) {
		t.Fatalf("404 不属于拦截信号")
	}
	if intercepted(resp(200, "ok", nil)) {
		t.Fatalf("200 不属于拦截信号")
	}
}
