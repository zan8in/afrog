package sqli

import (
	"context"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
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
	// 恒真/恒假条件有数字型（1=1）与引号型（'1'='1）两种写法，两种都要认。
	truthy := func(p string) bool {
		return strings.Contains(p, "1=1") || strings.Contains(p, "'1'='1")
	}
	falsy := func(p string) bool {
		return strings.Contains(p, "1=2") || strings.Contains(p, "'1'='2")
	}
	var hasTrue, hasFalse bool
	for _, tr := range traces {
		if truthy(tr.Payload) {
			hasTrue = true
		}
		if falsy(tr.Payload) {
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

// delayFromPayload 从参数里解析 fn(n) 的秒数，模拟「后端按 payload 给出的秒数延时」。
// 成比例验证要求 SLEEP(2) 的延时确实是 SLEEP(1) 的两倍，服务器必须照着秒数睡。
func delayFromPayload(id, fn string) time.Duration {
	idx := strings.Index(id, fn+"(")
	if idx < 0 {
		return 0
	}
	rest := id[idx+len(fn)+1:]
	end := strings.IndexAny(rest, "),")
	if end < 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

const listPage = "<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n"

// timeServer 按注入 payload 里 SLEEP(n) 的秒数延时，其余请求立即返回。
func timeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := delayFromPayload(r.URL.Query().Get("id"), "SLEEP"); d > 0 {
			time.Sleep(d)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, listPage)
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

// assertTimeTraces 校验时间盲注的证据链：基线 + 对照组 + 同档触发两次 + 加档 + 三档。
// 没有对照组就无法排除「目标本来就慢」，没有加档就说不清延时是否真由我们给的秒数驱动，
// 缺了三档则无法证明延时是线性增长（而非被顶到某个固定上限），所以三组证据都必须在链上。
func assertTimeTraces(t *testing.T, traces []passive.Trace) {
	t.Helper()
	wantLabels := []string{"基线", "对照组", "延时触发 #1", "延时触发 #2", "延时触发（加档）", "延时触发（三档）"}
	if len(traces) != len(wantLabels) {
		t.Fatalf("traces = %d, want %d", len(traces), len(wantLabels))
	}
	for i, want := range wantLabels {
		if traces[i].Label != want {
			t.Errorf("traces[%d].Label = %q, want %q", i, traces[i].Label, want)
		}
	}
	// 延时证据的价值在于耗时，必须留档：触发请求应显著高于对照组，
	// 且加档（秒数翻倍）、三档（秒数三倍）应逐档更慢。
	controlLatency := traces[1].LatencyMs
	triggerLatency := traces[2].LatencyMs
	repeatLatency := traces[3].LatencyMs
	highLatency := traces[4].LatencyMs
	thirdLatency := traces[5].LatencyMs
	if triggerLatency < 900 {
		t.Errorf("延时触发耗时 = %dms, want >= 900ms（SLEEP(1)）", triggerLatency)
	}
	if repeatLatency < 900 {
		t.Errorf("延时复现耗时 = %dms, want >= 900ms（SLEEP(1)）", repeatLatency)
	}
	if controlLatency >= triggerLatency {
		t.Errorf("对照组耗时 %dms 不应达到触发请求 %dms", controlLatency, triggerLatency)
	}
	if highLatency < triggerLatency {
		t.Errorf("加档耗时 %dms 应高于基准档 %dms（SLEEP(2) vs SLEEP(1)）", highLatency, triggerLatency)
	}
	if thirdLatency < highLatency {
		t.Errorf("三档耗时 %dms 应高于加档 %dms（SLEEP(3) vs SLEEP(2)）", thirdLatency, highLatency)
	}
}

// degreeMismatchServer 只在基准档 SLEEP(1) 上延时，加档 SLEEP(2) 反而立即返回。
// 这种「单点延时」正是成比例验证要拦下的形态：延时没有随秒数增长，说明它并非
// 由我们给出的秒数驱动（偶发慢查询、外部限流等），不能据此报漏洞。
func TestDetectTimeBasedRejectsNonProportionalDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("time-based detection is slow")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "SLEEP(1)") {
			time.Sleep(time.Second)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, listPage)
	}))
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
	if len(findings) != 0 {
		t.Fatalf("延时未随秒数成比例增长，不得报漏洞，got %+v", findings[0])
	}
}

// pgTimeServer 按 PostgreSQL 的 pg_sleep(n) 秒数延时，用于验证「按方言展开」有效：
// MySQL 的 SLEEP 在这台机器上没有任何效果，必须靠 pg_sleep 候选才能命中。
func pgTimeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := delayFromPayload(r.URL.Query().Get("id"), "pg_sleep"); d > 0 {
			time.Sleep(d)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, listPage)
	}))
}

func TestDetectTimeBasedPostgresDialect(t *testing.T) {
	if testing.Short() {
		t.Skip("time-based detection is slow")
	}

	srv := pgTimeServer(t)
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
	if got := findings[0].Extra["dialect"]; got != "postgresql" {
		t.Errorf("dialect = %v, want postgresql", got)
	}
	if got := findings[0].Extra["technique"]; got != techniqueTime {
		t.Errorf("technique = %v, want %s", got, techniqueTime)
	}
	if !strings.Contains(findings[0].Payload, "pg_sleep") {
		t.Errorf("Payload = %q, want pg_sleep", findings[0].Payload)
	}
}

// TestTimePairsCoverDialects 锁定时间盲注的方言覆盖范围：
// 少一个方言就少一类数据库的检出能力，属于能力回退。
func TestTimePairsCoverDialects(t *testing.T) {
	got := map[string]bool{}
	for _, p := range timePairs("1", 3) {
		got[p.dialect] = true
	}
	for _, want := range []string{"mysql", "postgresql", "mssql", "oracle"} {
		if !got[want] {
			t.Errorf("时间盲注缺少方言 %s", want)
		}
	}
}

// TestPointSessionDetectsWAF 校验拦截识别口径：正常响应不升级，出现明确拦截
// 迹象（状态码由正常转为被拒、或响应头带 WAF 特征）才升级，避免无谓的绕过流量。
func TestPointSessionDetectsWAF(t *testing.T) {
	normal := &pointSession{baseStatus: http.StatusOK}
	normal.observe(&passive.CapturedResponse{Status: http.StatusOK, Body: []byte("ok")})
	if normal.wafSuspected {
		t.Fatalf("正常响应不应被判定为 WAF 拦截")
	}

	// 基线正常、注入后被 403：典型拦截特征。
	denied := &pointSession{baseStatus: http.StatusOK}
	denied.observe(&passive.CapturedResponse{Status: http.StatusForbidden, Body: []byte("Request blocked by WAF")})
	if !denied.wafSuspected {
		t.Fatalf("注入后被 403 应判定为疑似 WAF")
	}

	// 基线本身就是 403（如整站鉴权），状态码未变化，但响应头带 WAF 特征。
	hinted := &pointSession{baseStatus: http.StatusForbidden}
	hinted.observe(&passive.CapturedResponse{Status: http.StatusForbidden,
		Headers: http.Header{"Server": []string{"cloudflare"}}})
	if !hinted.wafSuspected {
		t.Fatalf("响应头带 cloudflare 特征应判定为疑似 WAF")
	}
}

// TestReplaceKeywordPreservesParamValues 校验绕过改写只动「独立关键字」，
// 绝不碰参数值里的同形子串（brand 里的 and、order 里的 or）。
func TestReplaceKeywordPreservesParamValues(t *testing.T) {
	cases := []struct {
		name, in, kw, repl, want string
	}{
		{"不改坏参数值 brand", "brand AND 1=1", "AND", "AnD", "brand AnD 1=1"},
		{"不改坏参数值 order", "order AND 1=1", "OR", "Or", "order AND 1=1"},
		{"内联注释包裹关键字", "1 AND 1=1-- -", "AND", "/**/AND/**/", "1 /**/AND/**/ 1=1-- -"},
		{"非 ASCII 参数不越界", "İ AND 1=1", "AND", "AnD", "İ AnD 1=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := replaceKeyword(c.in, c.kw, c.repl); got != c.want {
				t.Errorf("replaceKeyword(%q,%q,%q) = %q, want %q", c.in, c.kw, c.repl, got, c.want)
			}
		})
	}
}

// TestEvasionPairsAreVerifiable 校验绕过候选始终带风格标签、且真假载荷不同。
// 缺了标签就无法在证据链里说清是哪一步绕过了 WAF。
func TestEvasionPairsAreVerifiable(t *testing.T) {
	for _, p := range evasionBoolPairs("1") {
		if p.evasion == "" {
			t.Errorf("绕过候选缺少风格标签: %+v", p)
		}
		if p.trueValue == p.falseValue {
			t.Errorf("绕过候选真假载荷相同: %+v", p)
		}
	}
}

// wafServer 模拟一台「朴素规则」WAF：只要请求里出现标准写法 " AND " 就返回 403，
// 其余情况透传给一个存在布尔盲注的后端。用于验证绕过链路端到端可用。
func wafServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(id, " AND ") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body><h1>Request blocked by WAF</h1></body></html>")
			return
		}
		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'") {
			fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n</ul>\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n")
	}))
}

func TestDetectBypassesNaiveWAF(t *testing.T) {
	srv := wafServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1（应通过大小写混淆绕过朴素 WAF）", len(findings))
	}
	if got := findings[0].Extra["evasion"]; got == "" {
		t.Errorf("evasion 标签为空，无法说明绕过方式: %+v", findings[0].Extra)
	}
	// 绕过的前提是语义仍成立：即使被改写，命中载荷也必须保留恒真条件。
	if !strings.Contains(strings.ToLower(findings[0].Payload), "1=1") {
		t.Errorf("Payload = %q, want 保留恒真条件", findings[0].Payload)
	}
	assertBooleanTraces(t, findings[0].Traces)
}

// errorServer 模拟「把参数直接拼进 SQL」的后端：参数里出现未闭合的引号时，
// 数据库把语法报错吐回页面。
func errorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			fmt.Fprint(w, "<html>\n<body>\n<b>Warning</b>: mysql_query() [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1]\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, listPage)
	}))
}

func TestDetectErrorBased(t *testing.T) {
	srv := errorServer(t)
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
	if got := f.Extra["technique"]; got != techniqueError {
		t.Errorf("technique = %v, want %s（报错型应最先定论）", got, techniqueError)
	}
	if got := f.Extra["dialect"]; got != "mysql" {
		t.Errorf("dialect = %v, want mysql", got)
	}
	if f.Payload != "1'" {
		t.Errorf("Payload = %q, want 破坏闭合的探针 1'", f.Payload)
	}
	if !strings.Contains(f.Evidence, "报错型") {
		t.Errorf("evidence = %q, want 报错型证据", f.Evidence)
	}
	assertErrorTraces(t, f.Traces)
}

// assertErrorTraces 校验报错型证据链：基线（不含特征）+ 触发两次（含特征）。
// 缺了基线就无法证明特征是被我们打出来的，缺了复现就无法排除偶发。
func assertErrorTraces(t *testing.T, traces []passive.Trace) {
	t.Helper()
	wantLabels := []string{"基线", "报错触发 #1", "报错触发 #2"}
	if len(traces) != len(wantLabels) {
		t.Fatalf("traces = %d, want %d", len(traces), len(wantLabels))
	}
	for i, want := range wantLabels {
		if traces[i].Label != want {
			t.Errorf("traces[%d].Label = %q, want %q", i, traces[i].Label, want)
		}
	}
	for _, tr := range traces[1:] {
		if !strings.Contains(strings.ToLower(tr.Response), "you have an error in your sql syntax") {
			t.Errorf("%s 的响应留档缺少报错特征", tr.Label)
		}
	}
}

// TestDetectErrorBasedIgnoresPreExistingMarker 校验「基线里本来就有的报错文案」
// 不构成证据：站点可能自己就在页面上展示一段 SQL 报错示例，那不是被我们打出来的。
func TestDetectErrorBasedIgnoresPreExistingMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html>\n<body>\n<p>常见报错示例：You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>\n</body>\n</html>\n")
	}))
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("基线已含报错文案，不得报漏洞，got %+v", findings[0])
	}
}

// TestDetectErrorBasedOnHeader 校验请求头注入点端到端可用：
// X-Forwarded-For 常被服务端直接拼进查询，报错型能覆盖到这类位置。
func TestDetectErrorBasedOnHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(r.Header.Get("X-Forwarded-For"), "'") {
			fmt.Fprint(w, "<html>\n<body>\nYou have an error in your SQL syntax; check the manual that corresponds to your MySQL server version\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, listPage)
	}))
	defer srv.Close()

	tx := txFor(t, srv.URL+"/list")
	tx.Request.Headers.Set("X-Forwarded-For", "127.0.0.1")

	d := New(DefaultOptions())
	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1（应检出头注入点）", len(findings))
	}
	if got := findings[0].Location; got != "header:X-Forwarded-For" {
		t.Errorf("Location = %q, want header:X-Forwarded-For", got)
	}
}

// TestDetectHeaderOnlyUsesErrorTier 锁定「只有头部注入点」事务的成本上限。
//
// 请求头几乎每个请求都带，若布尔/时间盲注也在头部展开，动态流量会被成倍放大，
// 因此这类事务只发单引号报错探针：命中即报，不命中就到此为止。这里刻意构造一个
// 「只有布尔差异、不会报错」的 XFF 注入——它可能真实存在，但只靠报文相似度证明
// 需要成倍的重放量，代价不成比例，属于刻意接受的取舍。
func TestDetectHeaderOnlyUsesErrorTier(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(r.Header.Get("X-Forwarded-For"), "1=2") {
			fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n</ul>\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, listPage)
	}))
	defer srv.Close()

	tx := txFor(t, srv.URL+"/list")
	tx.Request.Headers.Set("X-Forwarded-For", "127.0.0.1")

	d := New(DefaultOptions())
	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("无报错特征的头部注入点不应在轻量档被报出，got %+v", findings[0])
	}
	// 轻量档 = 一次单引号探针，最多再复现一次；多出来的就说明深测层被意外打开了。
	if got := atomic.LoadInt32(&requests); got > 2 {
		t.Errorf("头部专属轻量档发出 %d 次重放，want <= 2（不应展开布尔/时间盲注）", got)
	}
}

// TestOrderByDialectHint 校验指纹只调序、不裁剪：
// 「猜错只是多花请求」的前提就是候选一条都不能丢。
func TestOrderByDialectHint(t *testing.T) {
	pairs := timePairs("1", 1)
	got := orderByDialectHint(pairs, "oracle")
	if len(got) != len(pairs) {
		t.Fatalf("调序后候选数 = %d, want %d（禁止裁剪）", len(got), len(pairs))
	}
	if got[0].dialect != "oracle" {
		t.Errorf("首个候选方言 = %s, want oracle", got[0].dialect)
	}
	if got[1].dialect != "mysql" || got[3].dialect != "postgresql" {
		t.Errorf("其余候选的相对顺序被破坏: %s, %s", got[1].dialect, got[3].dialect)
	}
}

// labClauseServer 复刻 PortSwigger 靶场「WHERE category = '<输入>' AND released = 1」
// 的形态：参数后面还挂着一个额外条件，库里除已发布商品外还有一个未发布商品。
//
// 这一形态是本轮漏报的关键：带注释终止的 payload（...' AND '1'='1'-- -）会把
// 后面的 AND released = 1 一并注释掉，恒真响应因此多出「未发布商品」，与基线的
// 相似度跌破阈值而被判不成立；靠模板末尾引号收尾、不加注释的 payload 则完整保留
// 原查询语义，恒真响应与基线一致。
func labClauseServer(t *testing.T) *httptest.Server {
	t.Helper()
	releasedPets := []string{"PET-A", "PET-B"}
	const hiddenPet = "PET-HIDDEN"

	render := func(items []string) string {
		var b strings.Builder
		b.WriteString("<!DOCTYPE html>\n<html>\n<head><title>Pets</title></head>\n<body>\n")
		b.WriteString("<h1>Products</h1>\n<ul>\n")
		for _, it := range items {
			fmt.Fprintf(&b, "<li>%s</li>\n", it)
		}
		b.WriteString("</ul>\n<footer>copyright</footer>\n</body>\n</html>\n")
		return b.String()
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		cat := r.URL.Query().Get("category")
		if cat == "" || cat == "Pets" {
			fmt.Fprint(w, render(releasedPets))
			return
		}

		isFalse := strings.Contains(cat, "'1'='2") || strings.Contains(cat, "1=2")
		isTrue := strings.Contains(cat, "'1'='1") || strings.Contains(cat, "1=1")
		switch {
		case isFalse && !isTrue:
			// 恒假：结果集为空。
			fmt.Fprint(w, render(nil))
		case isTrue && !isFalse:
			if strings.Contains(cat, "--") {
				// 注释终止顺带注释掉了 AND released = 1，未发布商品随之出现。
				fmt.Fprint(w, render(append(append([]string{}, releasedPets...), hiddenPet)))
				return
			}
			if strings.HasPrefix(cat, "Pets'") {
				// 靠模板末尾引号收尾：原查询语义完整，结果与基线一致。
				fmt.Fprint(w, render(releasedPets))
				return
			}
			fmt.Fprint(w, render(nil))
		default:
			// 语法错误：返回通用 500，且不带任何数据库报错特征。
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "<html>\n<body>\n<h1>Internal Server Error</h1>\n</body>\n</html>\n")
		}
	}))
}

// TestDetectBooleanClauseTruncation 回归本轮漏报：参数后还挂着额外 WHERE 条件时，
// 必须有一个「不加注释终止、靠模板末尾引号收尾」的候选能通过门控。
func TestDetectBooleanClauseTruncation(t *testing.T) {
	srv := labClauseServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/filter?category=Pets")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1（应识别出布尔盲注）", len(findings))
	}
	f := findings[0]
	if f.Location != "query:category" {
		t.Errorf("Location = %q, want query:category", f.Location)
	}
	if construct, _ := f.Extra["construct"].(string); !strings.Contains(construct, "closed") {
		t.Errorf("命中候选 = %q, want 靠模板引号收尾的闭合候选", construct)
	}
	assertBooleanTraces(t, f.Traces)
}

// labOracleServer 复刻 PortSwigger Oracle 布尔盲注靶场的真实形态：
//  1. 参数原样反射进 <h1>，单引号被转义成 XML 命名实体 &apos;（而非 Go 的 &#39;）；
//  2. 恒真条件返回与基线相同的商品列表，恒假条件返回空列表。
//
// 这一形态此前会漏报：反射文本用的是 &apos;，而 Normalize 只覆盖 Go 的 &#39;，
// 反射未被剔除，恒真页与基线的相似度被反射噪声拉到阈值之下。
func labOracleServer(t *testing.T) *httptest.Server {
	t.Helper()
	products := []string{"PET-A", "PET-B", "PET-C", "PET-D"}

	xmlEscape := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;",
	)

	render := func(cat string, items []string) string {
		var b strings.Builder
		b.WriteString("<!DOCTYPE html>\n<html>\n<head><title>Pets</title></head>\n<body>\n")
		fmt.Fprintf(&b, "<h1>%s</h1>\n", xmlEscape.Replace(cat))
		b.WriteString("<ul>\n")
		for _, it := range items {
			fmt.Fprintf(&b, "<li>%s</li>\n", it)
		}
		b.WriteString("</ul>\n</body>\n</html>\n")
		return b.String()
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		cat := r.URL.Query().Get("category")
		if cat == "" || cat == "Pets" {
			fmt.Fprint(w, render(cat, products))
			return
		}
		isFalse := strings.Contains(cat, "'1'='2") || strings.Contains(cat, "1=2")
		isTrue := strings.Contains(cat, "'1'='1") || strings.Contains(cat, "1=1")
		switch {
		case isFalse && !isTrue:
			fmt.Fprint(w, render(cat, nil))
		case isTrue && !isFalse:
			fmt.Fprint(w, render(cat, products))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "<html>\n<body>\n<h1>Internal Server Error</h1>\n</body>\n</html>\n")
		}
	}))
}

// TestDetectBooleanOracleLab 回归 PortSwigger Oracle 靶场的漏报：
// 反射使用 XML 命名实体 &apos; 时，布尔盲注仍必须被检出。
func TestDetectBooleanOracleLab(t *testing.T) {
	srv := labOracleServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/filter?category=Pets")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1（应识别出布尔盲注）", len(findings))
	}
	f := findings[0]
	if f.Location != "query:category" {
		t.Errorf("Location = %q, want query:category", f.Location)
	}
	assertBooleanTraces(t, f.Traces)
}

// TestInferDBMSHint 校验方言指纹只采信强信号：数据库报错特征、IIS/ASP.NET 标识。
// 弱信号（如只带 PHP 的正常页面）不得被当成指纹，否则会把猜测写进证据链。
func TestInferDBMSHint(t *testing.T) {
	cases := []struct {
		name string
		res  *passive.CapturedResponse
		want string
	}{
		{
			name: "MySQL 报错特征",
			res: &passive.CapturedResponse{
				Body: []byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"),
			},
			want: "mysql",
		},
		{
			name: "ASP.NET 头指向 SQL Server",
			res: &passive.CapturedResponse{
				Headers: http.Header{"X-Powered-By": []string{"ASP.NET"}},
			},
			want: "mssql",
		},
		{
			name: "普通 PHP 页面不构成指纹",
			res: &passive.CapturedResponse{
				Headers: http.Header{"X-Powered-By": []string{"PHP/8.2"}},
				Body:    []byte(listPage),
			},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := inferDBMSHint(c.res); got != c.want {
				t.Errorf("inferDBMSHint = %q, want %q", got, c.want)
			}
		})
	}
}

// TestReportErrorMarkers 覆盖新增的报错特征：原生方言补充项与 ORM / 驱动层特征。
//
// 这类特征让「框架把数据库异常包了一层再抛出来」的站点也能被报错型定论；
// 同时必须证明框架的泛型异常（空指针、类型错误等）不会被采信——一旦把泛词
// 收进来，报错型就会退化成「任意错误页都算注入」的误报机器。
func TestReportErrorMarkers(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"oracle 补充分码", "ORA-00904: invalid identifier", "oracle"},
		{"mssql 类型转换失败", "Conversion failed when converting the varchar value 'a' to data type int.", "mssql"},
		{"postgresql 美元引号未闭合", "unterminated dollar-quoted string at or near \"$$", "postgresql"},
		{"jdbc 语法异常", "java.sql.SQLSyntaxErrorException", "jdbc"},
		{"hibernate 语法异常", "org.hibernate.exception.SQLGrammarException: could not prepare statement", "hibernate"},
		{"mybatis 持久化异常", "org.apache.ibatis.exceptions.PersistenceException", "mybatis"},
		{"spring 语法错误", "BadSqlGrammarException: bad sql grammar", "spring"},
		{"aspnet oledb 异常", "System.Data.OleDb.OleDbException", "aspnet"},
		{"php mysqli 异常", "mysqli_sql_exception", "php"},
		{"django 数据库异常", "django.db.utils.ProgrammingError", "django"},
		{"sqlalchemy 异常", "sqlalchemy.exc.OperationalError", "sqlalchemy"},
		{"python psycopg2 异常", "psycopg2.errors.SyntaxError", "python"},
		{"rails 语句无效", "ActiveRecord::StatementInvalid", "rails"},
		{"node sequelize 异常", "SequelizeDatabaseError: ER_PARSE_ERROR", "node"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, marker := reportError([]byte("<html>\n<body>\n" + c.body + "\n</body>\n</html>"))
			if got != c.want {
				t.Errorf("reportError = (%q, %q), want dialect %q", got, marker, c.want)
			}
		})
	}

	// 反向闸门：不指向 SQL 的框架泛型异常与普通错误页一律不得命中。
	negatives := []string{
		"java.lang.NullPointerException",
		"java.lang.ClassCastException",
		"Request processing failed; nested exception is java.lang.IllegalStateException",
		"TypeError: Cannot read properties of undefined (reading 'id')",
		"SyntaxError: Unexpected end of JSON input",
		"500 Internal Server Error",
	}
	for _, body := range negatives {
		if dialect, marker := reportError([]byte("<html>\n<body>\n" + body + "\n</body>\n</html>")); marker != "" {
			t.Errorf("泛型异常被误采信：body=%q → dialect=%q marker=%q", body, dialect, marker)
		}
	}
}

// shortPageFixture 是短页噪声豁免用例共用的页面骨架。
const (
	shortPageHead = "<!DOCTYPE html>\n<html>\n<head><title>T</title></head>\n<body>\n<h1>List</h1>\n"
	shortPageTail = "<footer>copyright</footer>\n</body>\n</html>\n"
)

// renderShortPage 渲染一个 13 个非空行的短页面：5 行页头 + 1 行导航 + 结果行 + 3 行页脚。
// 页面刻意做小，好让「改 1 行」的相似度 (N-1)/(N+1) 跌破严格阈值，从而落到豁免分支。
func renderShortPage(nav string, items []string) string {
	var b strings.Builder
	b.WriteString(shortPageHead)
	fmt.Fprintf(&b, "<div id=\"nav\">%s</div>\n", nav)
	for _, it := range items {
		fmt.Fprintf(&b, "<li>%s</li>\n", it)
	}
	b.WriteString(shortPageTail)
	return b.String()
}

// shortPageNoiseServer 模拟「恒真条件只改动一行动态 UI（行数不变）、恒假条件清空结果集」。
// 这正是短页噪声行豁免要放行的形态。
func shortPageNoiseServer(t *testing.T) *httptest.Server {
	t.Helper()
	items := []string{"ITEM-A", "ITEM-B", "ITEM-C", "ITEM-D"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		v := r.URL.Query().Get("id")
		isFalse := strings.Contains(v, "'1'='2") || strings.Contains(v, "1=2")
		isTrue := strings.Contains(v, "'1'='1") || strings.Contains(v, "1=1")
		switch {
		case isFalse && !isTrue:
			fmt.Fprint(w, renderShortPage("Home", nil))
		case isTrue && !isFalse:
			// 恒真：只把导航文案换一下（行数不变），模拟 A/B 分桶 / 导航高亮的动态噪声。
			fmt.Fprint(w, renderShortPage("Home (active)", items))
		default:
			fmt.Fprint(w, renderShortPage("Home", items))
		}
	}))
}

// TestDetectShortPageNoiseExemption 校验短页噪声行豁免：恒真响应只改一行内容时，
// 严格相似度 (13-1)/(13+1)=0.857 会跌破 0.97，但结构其实一致，仍应定论为布尔注入，
// 且证据里必须如实标注「按结构一致处理」，方便复核者看出它没走最严格的门控。
func TestDetectShortPageNoiseExemption(t *testing.T) {
	srv := shortPageNoiseServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1（短页噪声行应被豁免，恒真仍成立）", len(findings))
	}
	f := findings[0]
	if got := f.Extra["technique"]; got != techniqueBoolean {
		t.Errorf("technique = %v, want %s", got, techniqueBoolean)
	}
	if !strings.Contains(f.Evidence, "按结构一致处理") {
		t.Errorf("evidence = %q, want 显式标注短页噪声行豁免", f.Evidence)
	}
	assertBooleanTraces(t, f.Traces)
}

// shortPageRowDropServer 模拟「恒真条件反而让结果集少一行（行数变化）」。
// 对称差同样很小，但这不是动态 UI 噪声而是结果集变化，豁免必须拒绝放行。
func shortPageRowDropServer(t *testing.T) *httptest.Server {
	t.Helper()
	items := []string{"ITEM-A", "ITEM-B", "ITEM-C", "ITEM-D"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		v := r.URL.Query().Get("id")
		isFalse := strings.Contains(v, "'1'='2") || strings.Contains(v, "1=2")
		isTrue := strings.Contains(v, "'1'='1") || strings.Contains(v, "1=1")
		switch {
		case isFalse && !isTrue:
			fmt.Fprint(w, renderShortPage("Home", nil))
		case isTrue && !isFalse:
			// 恒真却少了一行：行数变了，不能当噪声行豁免。
			fmt.Fprint(w, renderShortPage("Home", items[:len(items)-1]))
		default:
			fmt.Fprint(w, renderShortPage("Home", items))
		}
	}))
}

// TestDetectShortPageRowDropNotExempted 校验豁免的边界：行数发生变化（结果集少一行）
// 时不得豁免。对称差为 1 仍在阈值内，只有「非空行数必须相同」这道守卫能挡住它，
// 否则恒假条件下「结果集变空（删两行）」的形态也会被误判成恒真。
func TestDetectShortPageRowDropNotExempted(t *testing.T) {
	srv := shortPageRowDropServer(t)
	defer srv.Close()

	d := New(DefaultOptions())
	tx := txFor(t, srv.URL+"/list?id=1")

	findings, err := d.Detect(context.Background(), tx, testProber())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0（行数变化不得走短页豁免）", len(findings))
	}
}

// TestEvadeDoubleURL 校验「双重 URL 编码」绕过就是把整串再做一次 URL 编码：
// 只解码一层的 WAF 看不到裸引号，而后端多解一层即可还原出等价 SQL。
func TestEvadeDoubleURL(t *testing.T) {
	payload := "1' AND '1'='1"
	got := evadeDoubleURL(payload, "mysql")
	if want := url.QueryEscape(payload); got != want {
		t.Errorf("evadeDoubleURL(%q) = %q, want %q", payload, got, want)
	}
	if strings.Contains(got, "'") {
		t.Errorf("编码后不应残留裸引号: %q", got)
	}
}

// TestEvadeCharEncodings 校验两种字符级编码绕过只改写「承担 SQL 结构作用」的字符
// （引号、括号、空格），关键字与参数值这些无关字节必须逐字节原样保留。
func TestEvadeCharEncodings(t *testing.T) {
	in := "SLEEP(1) AND 'a b'='a b'"
	cases := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "Unicode %uXXXX",
			got:  evadeUnicode(in, "mysql"),
			want: "SLEEP%u00281%u0029%u0020AND%u0020%u0027a%u0020b%u0027=%u0027a%u0020b%u0027",
		},
		{
			name: "十六进制实体",
			got:  evadeHexEntity(in, "mysql"),
			want: "SLEEP(1)&#x20;AND&#x20;&#x27;a&#x20;b&#x27;=&#x27;a&#x20;b&#x27;",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
			// 关键字必须原样保留，否则语义会被改坏，绕过也就失去意义。
			if !strings.Contains(c.got, "SLEEP") || !strings.Contains(c.got, "AND") {
				t.Errorf("%s 不应改写关键字: %q", c.name, c.got)
			}
		})
	}
}

// TestEvasionCandidatesCoverEncodings 校验编码类绕过确实接入了候选队列：
// 布尔候选里必须能看到三种新风格，否则它们只是没人调用的死代码。
func TestEvasionCandidatesCoverEncodings(t *testing.T) {
	seen := map[string]int{}
	for _, p := range evasionBoolPairs("1") {
		seen[p.evasion]++
	}
	for _, name := range []string{"双重 URL 编码", "Unicode 编码", "十六进制实体"} {
		if seen[name] == 0 {
			t.Errorf("候选队列缺少绕过风格 %q，实际覆盖: %v", name, seen)
		}
	}
	if len(seen) != len(evasions) {
		t.Errorf("候选队列覆盖 %d 种绕过风格, want %d", len(seen), len(evasions))
	}
}
