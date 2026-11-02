package sqli

import (
	"context"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

func testProber() *passive.HTTPProber {
	opts := passive.DefaultProberOptions()
	opts.Timeout = 5 * time.Second
	opts.GlobalRPS = 0 // 测试不设速率上限，避免拉长用例耗时
	return passive.NewHTTPProber(opts)
}

// txFor 构造一条只带请求的事务。Response 仅用于通过 Interest 门控，
// 真正的基线来自 Prober 的重放。
func txFor(t *testing.T, rawURL string) *passive.CapturedTransaction {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return &passive.CapturedTransaction{
		ID: "test",
		Request: &passive.CapturedRequest{
			Method:  http.MethodGet,
			URL:     u,
			Headers: http.Header{},
		},
		Response: &passive.CapturedResponse{
			Status:  200,
			Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:    []byte("<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n"),
		},
	}
}

// vulnerableServer 用字符串匹配粗略模拟一个存在布尔盲注的后端。
// 恒假条件会让结果集为空，页面结构随之变化。
func vulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		falseCond := strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'")
		if falseCond {
			fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n</ul>\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n")
	}))
}

func TestDetectVulnerable(t *testing.T) {
	srv := vulnerableServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.VulnType != VulnType || f.Confidence != passive.ConfidenceCertain {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Location != "query:id" {
		t.Errorf("Location = %q, want query:id", f.Location)
	}
	if !strings.Contains(f.Payload, "1=1") {
		t.Errorf("Payload = %q, want a true-condition payload", f.Payload)
	}
	if f.Evidence == "" || len(f.Request) == 0 || len(f.Response) == 0 {
		t.Errorf("evidence or raw dump is missing")
	}
	assertBooleanTraces(t, f.Traces)
}

// assertBooleanTraces 校验布尔差分的证据链完整可复核：
// 基线 + 恒真/恒假各两轮，共 5 条，缺任一条结论都无法自证。
func assertBooleanTraces(t *testing.T, traces []passive.Trace) {
	t.Helper()
	wantLabels := []string{"基线", "恒真 #1", "恒假 #1", "恒真 #2", "恒假 #2"}
	if len(traces) != len(wantLabels) {
		t.Fatalf("traces = %d, want %d", len(traces), len(wantLabels))
	}
	for i, want := range wantLabels {
		tr := traces[i]
		if tr.Label != want {
			t.Errorf("traces[%d].Label = %q, want %q", i, tr.Label, want)
		}
		if tr.Request == "" || tr.Response == "" {
			t.Errorf("traces[%d]（%s）缺少请求或响应原文", i, tr.Label)
		}
		if tr.Status == 0 {
			t.Errorf("traces[%d]（%s）缺少状态码", i, tr.Label)
		}
	}
	// 正向与反向载荷必须都在证据链里，否则无法证明「差分」成立。
	var hasTrue, hasFalse bool
	for _, tr := range traces {
		if strings.Contains(tr.Payload, "1=1") {
			hasTrue = true
		}
		if strings.Contains(tr.Payload, "1=2") {
			hasFalse = true
		}
	}
	if !hasTrue || !hasFalse {
		t.Errorf("证据链缺少正向或反向载荷：hasTrue=%v hasFalse=%v", hasTrue, hasFalse)
	}
}

// safeReflectServer 把参数原样反射到页面，但后端没有任何注入。
// 这是被动 SQLi 最容易误报的形态，必须不报。
func safeReflectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html>\n<body>\n<h1>Search</h1>\n<p>You searched: %s</p>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n", html.EscapeString(q))
	}))
}

func TestDetectReflectedButSafe(t *testing.T) {
	srv := safeReflectServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/search?q=abc")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("reflected-but-safe page must not be reported, got %+v", findings[0])
	}
}

// dynamicServer 每次响应都不同（模拟带时间戳/随机数的页面）。
// 基线不稳定时应直接放弃，而不是把抖动误判成注入。
func dynamicServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html>\n<body>\n<h1>List</h1>\n<p>trace=%d</p>\n<ul>\n<li>ITEM-A</li>\n</ul>\n</body>\n</html>\n", rand.Int63())
	}))
}

func TestDetectSkipsUnstableBaseline(t *testing.T) {
	srv := dynamicServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("unstable page must not be reported, got %+v", findings[0])
	}
}

// timeServer 只在注入 SLEEP(n) 时延时，其余请求立即返回。
func timeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "SLEEP(1)") {
			time.Sleep(time.Second)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n")
	}))
}

func TestDetectTimeBased(t *testing.T) {
	if testing.Short() {
		t.Skip("time-based detection is slow")
	}

	srv := timeServer(t)
	defer srv.Close()

	opts := DefaultOptions()
	opts.TimeSleepSeconds = 1
	opts.TimeTriggerThreshold = 600 * time.Millisecond
	opts.TimeControlThreshold = 300 * time.Millisecond

	d := New(opts)
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "时间盲注") {
		t.Errorf("evidence = %q, want time-based evidence", findings[0].Evidence)
	}
	assertTimeTraces(t, findings[0].Traces)
}

// assertTimeTraces 校验时间盲注的证据链：基线 + 延时触发两次 + 不延时的对照。
// 没有对照组就无法排除「目标本来就慢」，所以对照组必须在链上。
func assertTimeTraces(t *testing.T, traces []passive.Trace) {
	t.Helper()
	wantLabels := []string{"基线", "延时触发 #1", "对照组", "延时触发 #2"}
	if len(traces) != len(wantLabels) {
		t.Fatalf("traces = %d, want %d", len(traces), len(wantLabels))
	}
	for i, want := range wantLabels {
		if traces[i].Label != want {
			t.Errorf("traces[%d].Label = %q, want %q", i, traces[i].Label, want)
		}
	}
	// 延时证据的价值在于耗时，必须留档：触发请求应显著高于对照组。
	triggerLatency := traces[1].LatencyMs
	controlLatency := traces[2].LatencyMs
	if triggerLatency < 900 {
		t.Errorf("延时触发耗时 = %dms, want >= 900ms（SLEEP(1)）", triggerLatency)
	}
	if controlLatency >= triggerLatency {
		t.Errorf("对照组耗时 %dms 不应达到触发请求 %dms", controlLatency, triggerLatency)
	}
}
