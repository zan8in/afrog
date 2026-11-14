package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/passive"
)

// TestPassivePageFallsBackToSPA 锁定 /passive 页面路由：
// 后端没有这个接口，浏览器导航必须回退到 SPA 外壳，而不是 404 或 JSON。
func TestPassivePageFallsBackToSPA(t *testing.T) {
	h := mustRouter(t)

	code, ct := probe(t, h, "/passive", browserAccept)
	if code != http.StatusOK {
		t.Fatalf("/passive status = %d, want 200", code)
	}
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("/passive content-type = %q, want text/html", ct)
	}
}

// TestPassiveRoutesRequireAuth 锁定被动扫描接口必须登录后才能访问。
// 代理与 CA 都属于高敏感能力，未认证可达等同于开放中间人解密。
func TestPassiveRoutesRequireAuth(t *testing.T) {
	h := mustRouter(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/passive/status"},
		{http.MethodPost, "/api/passive/start"},
		{http.MethodPost, "/api/passive/stop"},
		{http.MethodGet, "/api/passive/config"},
		{http.MethodPut, "/api/passive/config"},
		{http.MethodGet, "/api/passive/ca"},
		{http.MethodGet, "/api/passive/findings"},
		{http.MethodGet, "/api/passive/findings/1"},
		{http.MethodPost, "/api/passive/findings/1/promote"},
		// 观测接口同样属于高敏感能力：流量里可能带明文凭据。
		{http.MethodGet, "/api/passive/traffic"},
		{http.MethodGet, "/api/passive/diagnostics"},
		// 敏感信息提取物（HAE 等价能力）同样可能含明文密钥，必须登录后可见。
		{http.MethodGet, "/api/passive/extractions"},
		{http.MethodGet, "/api/passive/extractions/1"},
		// 覆盖度台账会暴露被测资产全貌，同样属于高敏感信息。
		{http.MethodGet, "/api/passive/coverage"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Accept", "application/json")
		// apiMiddleware 要求写操作声明 JSON，否则先返回 400，测不到认证这一层。
		if tc.method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

// TestPassiveRuntimeStartStop 验证生命周期幂等，且测试不占用真实端口与用户目录。
func TestPassiveRuntimeStartStop(t *testing.T) {
	oldCfg := passiveRT.cfg
	oldOverride := passiveRT.listenOverride
	oldDir := passiveRT.caDir

	passiveRT.cfg = config.Passive{
		Host:            "127.0.0.1",
		Port:            16869,
		Detectors:       []string{"sqli"},
		MaxRPS:          100,
		HostConcurrency: 4,
	}
	passiveRT.listenOverride = "127.0.0.1:0"
	passiveRT.caDir = t.TempDir()
	t.Cleanup(func() {
		StopPassive()
		passiveRT.cfg = oldCfg
		passiveRT.listenOverride = oldOverride
		passiveRT.caDir = oldDir
	})

	if err := StartPassive(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := StartPassive(); err != nil {
		t.Fatalf("start must be idempotent: %v", err)
	}
	if passiveRT.server == nil {
		t.Fatalf("server not recorded after start")
	}

	StopPassive()
	StopPassive()

	if passiveRT.server != nil || passiveRT.engine != nil {
		t.Fatalf("runtime must be cleared after stop")
	}
}

// TestNormalizePassivePayload 锁定设置面板的入参校验与兜底。
func TestNormalizePassivePayload(t *testing.T) {
	bad := []passiveConfigPayload{
		{Host: "127.0.0.1", Port: 0},
		{Host: "127.0.0.1", Port: 70000},
		{Host: "127.0.0.1", Port: 16869, Upstream: "not-a-url"},
		{Host: "127.0.0.1", Port: 16869, Upstream: "socks5://127.0.0.1:1080"},
	}
	for _, in := range bad {
		if _, err := normalizePassivePayload(in); err == nil {
			t.Errorf("payload %+v must be rejected", in)
		}
	}

	got, err := normalizePassivePayload(passiveConfigPayload{
		Host:      " ",
		Port:      18080,
		Upstream:  "http://127.0.0.1:8080/",
		Detectors: []string{"UNKNOWN", "sqli"},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.Host != config.DefaultPassiveHost {
		t.Errorf("host = %q, want default", got.Host)
	}
	if got.Upstream != "http://127.0.0.1:8080" {
		t.Errorf("upstream = %q, want trailing slash trimmed", got.Upstream)
	}
	if len(got.Detectors) != 1 || got.Detectors[0] != "sqli" {
		t.Errorf("detectors = %v, want [sqli]", got.Detectors)
	}
	if got.MaxRPS != config.DefaultPassiveMaxRPS || got.HostConcurrency != config.DefaultPassiveHostConcurrency {
		t.Errorf("rate limits not defaulted: %+v", got)
	}
}

// TestPassiveProxyHintForLan 绑定所有网卡时，提示必须给出可连接的目标地址。
func TestPassiveProxyHintForLan(t *testing.T) {
	hint := passiveProxyHint(config.Passive{Host: "0.0.0.0", Port: 18080})
	if !strings.Contains(hint, "127.0.0.1:18080") || !strings.Contains(hint, "局域网") {
		t.Fatalf("lan hint = %q", hint)
	}

	hint = passiveProxyHint(config.Passive{Host: "127.0.0.1", Port: 16869})
	if !strings.Contains(hint, "127.0.0.1:16869") {
		t.Fatalf("local hint = %q", hint)
	}
}

// TestBuildPassiveResult 锁定「被动发现 → result 记录」的字段映射。
// 这里只验证构造逻辑，不碰数据库。
func TestBuildPassiveResult(t *testing.T) {
	detail := &sqlite.PassiveFindingDetail{
		PassiveFinding: sqlite.PassiveFinding{
			VulnType: "sqli",
			Severity: "high",
			Title:    "SQL 注入",
			Target:   "http://example.com/list",
			Location: "query:id",
			Evidence: "布尔差分成立",
		},
		Request:  "GET /list?id=1 AND 1=1-- - HTTP/1.1",
		Response: "HTTP/1.1 200 OK",
	}

	r := buildPassiveResult(detail)

	if r.PocInfo == nil || r.PocInfo.Id != "passive-sqli" {
		t.Fatalf("poc id = %+v, want passive-sqli", r.PocInfo)
	}
	if r.Target != detail.Target {
		t.Errorf("target = %q, want %q", r.Target, detail.Target)
	}
	if r.PocInfo.Info.Severity != "high" {
		t.Errorf("severity = %q, want high", r.PocInfo.Info.Severity)
	}
	if len(r.AllPocResult) != 1 {
		t.Fatalf("poc results = %d, want 1", len(r.AllPocResult))
	}
	pr := r.AllPocResult[0]
	if string(pr.ResultRequest.Raw) != detail.Request {
		t.Errorf("request raw mismatch")
	}
	if string(pr.ResultResponse.Raw) != detail.Response {
		t.Errorf("response raw mismatch")
	}
}

// TestNewPassiveFindingDetailView 锁定详情视图对证据链的解析，以及老记录的退化行为。
//
// 单条请求无法自证 SQL 注入，详情必须能把整条证据链交给前端；而升级前入库的
// 老记录没有证据链，界面上也不能出现「什么都没有」的空窗。
func TestNewPassiveFindingDetailView(t *testing.T) {
	traces := []passive.Trace{
		{Label: "基线", Payload: "1", Status: 200, LatencyMs: 30, Request: "GET /list?id=1", Response: "HTTP/1.1 200 OK"},
		{Label: "恒真 #1", Payload: "1 AND 1=1", Status: 200, LatencyMs: 31, Request: "GET /list?id=1 AND 1=1", Response: "HTTP/1.1 200 OK"},
		{Label: "恒假 #1", Payload: "1 AND 1=2", Status: 200, LatencyMs: 32, Request: "GET /list?id=1 AND 1=2", Response: "HTTP/1.1 200 OK"},
	}
	raw, err := json.Marshal(traces)
	if err != nil {
		t.Fatalf("marshal traces: %v", err)
	}

	d := &sqlite.PassiveFindingDetail{
		PassiveFinding: sqlite.PassiveFinding{
			Payload:   "1 AND 1=1",
			TracesRaw: string(raw),
		},
		Request:  "GET /list?id=1 AND 1=1 HTTP/1.1",
		Response: "HTTP/1.1 200 OK",
	}
	view := newPassiveFindingDetailView(d)
	if len(view.Traces) != len(traces) {
		t.Fatalf("traces = %d, want %d", len(view.Traces), len(traces))
	}
	if view.Traces[1].Label != "恒真 #1" || view.Traces[1].LatencyMs != 31 {
		t.Errorf("traces[1] = %+v, want 恒真 #1 / 31ms", view.Traces[1])
	}

	// 老记录：没有 traces，退化为单条「命中请求」，保证详情非空。
	legacy := &sqlite.PassiveFindingDetail{
		PassiveFinding: sqlite.PassiveFinding{Payload: "1 AND 1=1", LatencyMs: 42},
		Request:        "GET /list?id=1 AND 1=1 HTTP/1.1",
		Response:       "HTTP/1.1 200 OK",
	}
	lv := newPassiveFindingDetailView(legacy)
	if len(lv.Traces) != 1 || lv.Traces[0].Label != "命中请求" {
		t.Fatalf("legacy traces = %+v, want one 命中请求", lv.Traces)
	}
	if lv.Traces[0].LatencyMs != 42 {
		t.Errorf("legacy latency = %d, want 42", lv.Traces[0].LatencyMs)
	}
}

// TestBuildPassiveResultWithTraces 锁定证据链提升为台账时的展开：
// 每条 Trace 各占一条 PocResult，编号（FullTarget 后缀）与耗时都要带过去，
// 否则报告里只剩一条请求，又回到「单条请求无法自证」的老问题。
func TestBuildPassiveResultWithTraces(t *testing.T) {
	traces := []passive.Trace{
		{Label: "基线", Payload: "1", Status: 200, LatencyMs: 30, Request: "GET /list?id=1", Response: "HTTP/1.1 200 OK"},
		{Label: "恒真 #1", Payload: "1 AND 1=1", Status: 200, LatencyMs: 31, Request: "GET /list?id=1 AND 1=1", Response: "HTTP/1.1 200 OK"},
		{Label: "恒假 #1", Payload: "1 AND 1=2", Status: 200, LatencyMs: 32, Request: "GET /list?id=1 AND 1=2", Response: "HTTP/1.1 200 OK"},
	}
	raw, err := json.Marshal(traces)
	if err != nil {
		t.Fatalf("marshal traces: %v", err)
	}

	detail := &sqlite.PassiveFindingDetail{
		PassiveFinding: sqlite.PassiveFinding{
			VulnType: "sqli",
			Severity: "high",
			Title:    "SQL 注入",
			Target:   "http://example.com/list",
			Location: "query:id",
			Evidence: "布尔差分成立",
			// TracesRaw 走 JSON 列；Request/Response 仅为兼容老界面保留。
			TracesRaw: string(raw),
		},
		Request:  "GET /list?id=1 AND 1=1 HTTP/1.1",
		Response: "HTTP/1.1 200 OK",
	}

	r := buildPassiveResult(detail)

	if len(r.AllPocResult) != len(traces) {
		t.Fatalf("poc results = %d, want %d（证据链每条各占一条）", len(r.AllPocResult), len(traces))
	}
	second := r.AllPocResult[1]
	if !strings.Contains(second.FullTarget, "恒真 #1") {
		t.Errorf("FullTarget = %q, want 带证据链标签", second.FullTarget)
	}
	if second.ResultResponse.Latency != 31 {
		t.Errorf("latency = %d, want 31", second.ResultResponse.Latency)
	}
	if string(second.ResultRequest.Raw) != traces[1].Request {
		t.Errorf("request raw mismatch: %q", string(second.ResultRequest.Raw))
	}
}
