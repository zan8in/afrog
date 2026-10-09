package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// 只掩码敏感头，不能把判定所需的证据（payload、回显内容）也抹掉。
func TestMaskEvidence(t *testing.T) {
	in := strings.Join([]string{
		"GET /x HTTP/1.1",
		"Host: a.example",
		"Cookie: session=secret",
		"Authorization: Bearer sk-live-123",
		"X-Api-Key: abc123",
		"X-Trace: keep-me",
	}, "\n")

	out := maskEvidence(in)
	for _, leaked := range []string{"session=secret", "sk-live-123", "abc123"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("敏感值未隐藏：%q\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "Cookie: <已隐藏>") || !strings.Contains(out, "Authorization: <已隐藏>") {
		t.Fatalf("应按头名掩码：\n%s", out)
	}
	if !strings.Contains(out, "Host: a.example") || !strings.Contains(out, "X-Trace: keep-me") {
		t.Fatalf("非敏感头应原样保留：\n%s", out)
	}
}

func TestAIChatEndpointAndBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://api.deepseek.com/v1":                  "https://api.deepseek.com/v1/chat/completions",
		"https://api.deepseek.com/v1/":                 "https://api.deepseek.com/v1/chat/completions",
		"https://api.deepseek.com/v1/chat/completions": "https://api.deepseek.com/v1/chat/completions",
		"  https://afrog.example/openai/v1  ":          "https://afrog.example/openai/v1/chat/completions",
		"":                                             "",
	}
	for in, want := range cases {
		if got := aiChatEndpoint(in); got != want {
			t.Errorf("aiChatEndpoint(%q) = %q, want %q", in, got, want)
		}
	}

	if got, err := normalizeAIBaseURL("https://api.deepseek.com/v1/chat/completions/"); err != nil || got != "https://api.deepseek.com/v1" {
		t.Fatalf("带完整路径的地址应归一化：got=%q err=%v", got, err)
	}
	if got, err := normalizeAIBaseURL("api.deepseek.com/v1"); err == nil || got != "" {
		t.Fatalf("缺少协议应被拒绝：got=%q err=%v", got, err)
	}
	if got, err := normalizeAIBaseURL("  "); err != nil || got != "" {
		t.Fatalf("空地址应放行（表示先不配）：got=%q err=%v", got, err)
	}
}

func TestAIDeltaFromChunk(t *testing.T) {
	if got := aiDeltaFromChunk(`{"choices":[{"delta":{"content":"你好"}}]}`); got != "你好" {
		t.Fatalf("delta = %q", got)
	}
	// 少数服务商在 stream 模式下用 message 整段返回
	if got := aiDeltaFromChunk(`{"choices":[{"message":{"content":"整段"}}]}`); got != "整段" {
		t.Fatalf("message fallback = %q", got)
	}
	for _, junk := range []string{"", "[DONE]", `{"choices":[]}`, `{"usage":{}}`, "not-json"} {
		if got := aiDeltaFromChunk(junk); got != "" {
			t.Fatalf("非增量帧 %q 应返回空串，实际 %q", junk, got)
		}
	}
}

// 提示词要带够判定依据，同时不把敏感头与超长响应体原样送出去。
func TestAIVerdictPrompt_MasksSecretsAndTruncates(t *testing.T) {
	evidence := &db2.HitEvidence{
		VulID:      "poc-ai",
		VulName:    "AI 测试 PoC",
		Severity:   "HIGH",
		Target:     "http://ai.example",
		FullTarget: "http://ai.example/x",
		Created:    "2026-10-01 10:00:00",
		Poc:        `{"Id":"poc-ai","Info":{"Name":"AI 测试 PoC","Severity":"high","Description":"测试用的描述","Reference":["https://example.com/cve"]}}`,
		Request:    "GET /x HTTP/1.1\r\nHost: ai.example\r\nCookie: session=secret\r\n",
		Response:   "HTTP/1.1 200 OK\r\nSet-Cookie: sid=1\r\n\r\n" + strings.Repeat("A", aiEvidenceResponseLimit+500),
	}

	system, user := aiVerdictPrompt(evidence)

	if !strings.Contains(system, "不得引入证据里没有的事实") || !strings.Contains(system, "严禁编造") {
		t.Fatalf("system prompt 缺少「不编造」约束：\n%s", system)
	}
	for _, want := range []string{"## 结论", "## 判定依据", "## 误报可能", "## 人工验证", "## 危害与影响", "## 修复建议"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt 缺少小节 %q", want)
		}
	}

	if !strings.Contains(user, "AI 测试 PoC") || !strings.Contains(user, "http://ai.example/x") {
		t.Fatalf("user prompt 缺少命中信息：\n%s", user)
	}
	if !strings.Contains(user, "测试用的描述") || !strings.Contains(user, "https://example.com/cve") {
		t.Fatalf("user prompt 缺少 PoC 元信息：\n%s", user)
	}
	if strings.Contains(user, "session=secret") || strings.Contains(user, "sid=1") {
		t.Fatalf("user prompt 泄漏了敏感头：\n%s", user)
	}
	if !strings.Contains(user, "已截断") || strings.Contains(user, strings.Repeat("A", aiEvidenceResponseLimit+1)) {
		t.Fatalf("超长响应体应被截断：\n%s", user)
	}
}

// 端到端：流式转发模型增量 -> 落缓存 -> 第二次直接回放缓存（不再调模型）。
func TestAIVerdictHandler_StreamsThenServesFromCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("初始化临时数据库失败: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := sqlite.InsertResultAndReturnID(&result.Result{
		Target:     "http://ai.example",
		FullTarget: "http://ai.example/x",
		PocInfo: &poc.Poc{
			Id:   "poc-ai",
			Info: poc.Info{Name: "AI 测试 PoC", Severity: "high", Description: "测试用 PoC"},
		},
		AllPocResult: []*result.PocResult{{
			FullTarget:     "http://ai.example/x",
			ResultRequest:  &proto.Request{Raw: []byte("GET /x HTTP/1.1\r\nHost: ai.example\r\nCookie: session=secret\r\n")},
			ResultResponse: &proto.Response{Raw: []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=1\r\n\r\nroot:x:0:0")},
		}},
	}); err != nil {
		t.Fatalf("写入命中失败: %v", err)
	}

	var calls int32
	var gotAuth, gotBody string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, part := range []string{"## 结论\n", "真实漏洞（置信度：高）"} {
			chunk, _ := json.Marshal(map[string]any{
				"choices": []any{map[string]any{"delta": map[string]string{"content": part}}},
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
			if fl != nil {
				fl.Flush()
			}
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if fl != nil {
			fl.Flush()
		}
	}))
	defer fake.Close()

	SetAIConfig(config.AI{BaseURL: fake.URL + "/v1", Model: "test-model", APIKey: "test-key", TimeoutSec: 10, MaxTokens: 256}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	call := func() string {
		t.Helper()
		qs := url.Values{}
		qs.Set("vulid", "poc-ai")
		qs.Set("target", "http://ai.example")
		qs.Set("fulltarget", "http://ai.example/x")
		rec := httptest.NewRecorder()
		aiVerdictHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/verdict?"+qs.Encode(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	first := call()
	if !strings.Contains(first, "event: delta") || !strings.Contains(first, "真实漏洞") {
		t.Fatalf("未流式返回模型内容：\n%s", first)
	}
	if !strings.Contains(first, "event: done") || strings.Contains(first, "event: failed") {
		t.Fatalf("流式结束事件不对：\n%s", first)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("模型调用次数 = %d，期望 1", got)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	// 提示词本身是 JSON 编码的，所以断言中文标记而不是尖括号原文。
	if !strings.Contains(gotBody, "已隐藏") || strings.Contains(gotBody, "session=secret") {
		t.Fatalf("敏感请求头未被隐藏：\n%s", gotBody)
	}
	if !strings.Contains(gotBody, "root:x:0:0") {
		t.Fatalf("响应证据应原样带给模型：\n%s", gotBody)
	}

	second := call()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("第二次查看应命中缓存，实际调用模型 %d 次", got)
	}
	if !strings.Contains(second, `"cached":true`) || !strings.Contains(second, "真实漏洞") {
		t.Fatalf("缓存回放不正确：\n%s", second)
	}
}

// 没配模型时给出可照做的引导，而不是让 EventSource 只看到「连接失败」。
func TestAIVerdictHandler_NotConfigured(t *testing.T) {
	SetAIConfig(config.AI{}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	rec := httptest.NewRecorder()
	aiVerdictHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/verdict?vulid=poc-ai&target=http://ai.example", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "event: failed") || !strings.Contains(body, "还没有配置模型接口") {
		t.Fatalf("应返回可照做的错误事件：\n%s", body)
	}
}

// 摘要提示词要带统计与条目清单，并如实说明「这不是单次扫描」。
func TestAISummaryPrompt_WarnsAboutFilterScope(t *testing.T) {
	data := &db2.SummaryData{
		Scope:        "filter",
		Severity:     "high",
		Keyword:      "spring",
		HitRows:      9,
		SeverityDist: map[string]int64{"HIGH": 2, "LOW": 1},
		Findings: []db2.SummaryFinding{{
			VulID: "poc-1", VulName: "示例漏洞", Target: "http://a.example",
			FullTarget: "http://a.example/x", Severity: "HIGH", HitCount: 3, Status: "false_positive",
		}},
	}

	system, user := aiSummaryPrompt(data)

	for _, want := range []string{"## 执行摘要", "## 整体风险评级", "## 关键风险", "## 处置建议"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt 缺少小节 %q", want)
		}
	}
	if !strings.Contains(system, "不得编造 CVE") {
		t.Fatalf("system prompt 缺少「不编造」约束：\n%s", system)
	}
	if !strings.Contains(user, "不是单次扫描") {
		t.Fatalf("跨任务范围必须写明：\n%s", user)
	}
	if !strings.Contains(user, "命中条目（按 PoC + 目标聚合）：3 条") || !strings.Contains(user, "原始命中记录：9 条") {
		t.Fatalf("统计数字不正确：\n%s", user)
	}
	if !strings.Contains(user, "HIGH：2 条") || !strings.Contains(user, "LOW：1 条") {
		t.Fatalf("按级别的分布缺失：\n%s", user)
	}
	if !strings.Contains(user, "已标记误报") {
		t.Fatalf("条目应带上人工状态：\n%s", user)
	}
	if !strings.Contains(user, "spring") {
		t.Fatalf("应说明筛选条件：\n%s", user)
	}
}

// 单任务摘要要带上任务元信息，并把来源翻译成中文。
func TestAISummaryPrompt_TaskScope(t *testing.T) {
	data := &db2.SummaryData{
		Scope: "task", TaskID: "t-1", TaskName: "客户A每日巡检", TaskSource: "schedule",
		StartedAt: "2026-10-01 10:00:00", EndedAt: "2026-10-01 10:05:00",
		TotalTargets: 12, TotalPocs: 300, TotalScans: 3600, HitRows: 4,
		SeverityDist: map[string]int64{"CRITICAL": 1},
		Findings:     []db2.SummaryFinding{{VulID: "poc-1", VulName: "严重漏洞", Target: "http://a.example", Severity: "CRITICAL", HitCount: 1}},
	}

	_, user := aiSummaryPrompt(data)

	for _, want := range []string{"客户A每日巡检", "计划扫描（自动触发）", "目标数：12", "加载 PoC 数：300", "CRITICAL：1 条"} {
		if !strings.Contains(user, want) {
			t.Fatalf("单任务摘要缺少 %q：\n%s", want, user)
		}
	}
	if strings.Contains(user, "不是单次扫描") {
		t.Fatalf("单任务摘要不该提示跨任务范围：\n%s", user)
	}
}

// 端到端：摘要与研判共用同一套流式 + 缓存流程。
func TestAISummaryHandler_StreamsAndCaches(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("初始化临时数据库失败: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := sqlite.InsertResultAndReturnID(&result.Result{
		Target:     "http://sum.example",
		FullTarget: "http://sum.example/x",
		PocInfo: &poc.Poc{
			Id:   "poc-sum",
			Info: poc.Info{Name: "汇总用 PoC", Severity: "high"},
		},
	}); err != nil {
		t.Fatalf("写入命中失败: %v", err)
	}

	var calls int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		chunk, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"delta": map[string]string{"content": "## 执行摘要\n整体风险中等"}}},
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if fl != nil {
			fl.Flush()
		}
	}))
	defer fake.Close()

	SetAIConfig(config.AI{BaseURL: fake.URL + "/v1", Model: "test-model", APIKey: "test-key", TimeoutSec: 10, MaxTokens: 256}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	call := func(qs string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		aiSummaryHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/summary?"+qs, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	first := call("severity=high")
	if !strings.Contains(first, "event: delta") || !strings.Contains(first, "整体风险中等") || !strings.Contains(first, "event: done") {
		t.Fatalf("摘要未正确流式返回：\n%s", first)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("模型调用次数 = %d，期望 1", got)
	}

	second := call("severity=high")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("第二次摘要应命中缓存，实际调用模型 %d 次", got)
	}
	if !strings.Contains(second, `"cached":true`) {
		t.Fatalf("缓存回放不正确：\n%s", second)
	}

	// 换筛选条件就是另一份摘要（缓存键不同），必须重新调用模型。
	// 这里用关键字而不是 severity=low：后者在本数据集下没有命中，会走「无需生成」分支。
	_ = call("keyword=poc-sum")
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("换筛选条件后模型调用次数 = %d，期望 2", got)
	}
}

// 「测试连接」：成功时回传模型片段；上游拒绝时把原因翻译成用户能照做的提示。
func TestAITestHandler_SuccessThenUpstreamError(t *testing.T) {
	// 保证「未配置」用例不受其它用例残留的内存配置影响。
	SetAIConfig(config.AI{}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("请求路径 = %q，期望 /v1/chat/completions", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("鉴权头 = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": "正常"}}},
		})
	}))
	defer okSrv.Close()

	rec := runAITest(t, aiTestPayload{BaseURL: okSrv.URL + "/v1", Model: "m", APIKey: "sk-test"})
	if body := rec.Body.String(); !strings.Contains(body, `"success":true`) || !strings.Contains(body, "正常") {
		t.Fatalf("测试连接应成功：%s", body)
	}

	// 401 应翻译成「检查 api_key」，而不是把裸 JSON 甩给用户。
	denySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid api key"}}`)
	}))
	defer denySrv.Close()

	rec = runAITest(t, aiTestPayload{BaseURL: denySrv.URL + "/v1", Model: "m", APIKey: "bad"})
	if body := rec.Body.String(); !strings.Contains(body, `"success":false`) || !strings.Contains(body, "api_key") {
		t.Fatalf("401 应给出可照做的提示：%s", body)
	}

	// 三项不全：直接给出配置提示（此用例下内存配置为空）。
	rec = runAITest(t, aiTestPayload{})
	if body := rec.Body.String(); !strings.Contains(body, `"success":false`) {
		t.Fatalf("缺配置应失败：%s", body)
	}
}

func runAITest(t *testing.T, payload aiTestPayload) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	aiTestHandler(rec, httptest.NewRequest(http.MethodPost, "/api/ai/test", strings.NewReader(string(b))))
	return rec
}
