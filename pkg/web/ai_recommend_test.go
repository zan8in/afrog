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
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// 模型输出里的 JSON 要能被稳定取出，并把越界值与非法级别修正掉。
func TestParseRecommendParams(t *testing.T) {
	text := strings.Join([]string{
		"- 目标以 URL 为主，开启 Web 指纹。",
		"",
		"```json",
		`{"concurrency":9999,"rate_limit":0,"timeout":45,"smart":true,`,
		`"portscan":false,"ports":"","skip_host_discovery":false,`,
		`"web_fingerprint":true,"severity":["HIGH","bogus","high"]}`,
		"```",
	}, "\n")

	params, ok := parseRecommendParams(text)
	if !ok {
		t.Fatalf("应能解析出参数：\n%s", text)
	}
	if got := params["concurrency"]; got != 500 {
		t.Fatalf("越界并发应夹到上限 500，实际 %v", got)
	}
	if got := params["rate_limit"]; got != 1 {
		t.Fatalf("低于下限的速率应夹到 1，实际 %v", got)
	}
	if got := params["timeout"]; got != 45 {
		t.Fatalf("timeout = %v, want 45", got)
	}
	if got := params["smart"]; got != true {
		t.Fatalf("smart = %v, want true", got)
	}
	if got := params["web_fingerprint"]; got != true {
		t.Fatalf("web_fingerprint = %v, want true", got)
	}
	// 非法级别被丢弃、大小写被归一、重复项去重。
	if got := fmt.Sprint(params["severity"]); got != "[high]" {
		t.Fatalf("severity = %v, want [high]", got)
	}

	// 只覆盖模型确实给出的字段：没出现的键不应存在。
	if _, exists := params["portscan"]; !exists {
		t.Fatalf("portscan 明确给出，应当保留")
	}

	// 没有围栏时退回「第一个 { 到最后一个 }」。
	bare := `理由略。{"concurrency":10,"severity":[]} 结束。`
	params, ok = parseRecommendParams(bare)
	if !ok || params["concurrency"] != 10 {
		t.Fatalf("无围栏输出应仍能解析，got=%v ok=%v", params, ok)
	}

	// 完全没有 JSON 时判为解析失败，而不是返回空参数。
	if _, ok := parseRecommendParams("只有一段没有任何 JSON 的说明"); ok {
		t.Fatalf("没有 JSON 时不应判定为解析成功")
	}
}

func TestAIRecommendPrompt_IncludesProfile(t *testing.T) {
	system, user := aiRecommendPrompt(aiRecommendInput{
		Sample:      "https://a.example\n10.0.0.0/24",
		Count:       2,
		Hosts:       255,
		Kinds:       "url:1,cidr:1",
		Intent:      "standard",
		Project:     "客户A",
		ProjectSize: 120,
		Pocs:        2000,
	})

	for _, want := range []string{"concurrency", "rate_limit", "timeout", "severity", "JSON"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt 缺少字段说明 %q", want)
		}
	}
	for _, want := range []string{"客户A", "120 个目标", "url:1,cidr:1", "https://a.example", "标准漏扫"} {
		if !strings.Contains(user, want) {
			t.Fatalf("user prompt 缺少目标画像 %q：\n%s", want, user)
		}
	}
}

// 完整链路：流式返回理由，并在 done 之前补发可应用的 params 事件；再次查看命中缓存。
func TestAIRecommendHandler_StreamsParamsAndCaches(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("初始化临时数据库失败: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	var calls int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, part := range []string{
			"- 目标数量大，建议开启智能并发。\n",
			"```json\n{\"concurrency\":80,\"smart\":true,\"severity\":[\"high\"]}\n```",
		} {
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
		qs.Set("count", "120")
		qs.Set("kinds", "url:120")
		qs.Set("intent", "standard")
		qs.Set("sample", "https://a.example")
		rec := httptest.NewRecorder()
		aiRecommendHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/recommend?"+qs.Encode(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	first := call()
	if !strings.Contains(first, "event: delta") || !strings.Contains(first, "智能并发") {
		t.Fatalf("未流式返回理由：\n%s", first)
	}
	if !strings.Contains(first, "event: params") || !strings.Contains(first, `"concurrency":80`) {
		t.Fatalf("未补发 params 事件：\n%s", first)
	}
	if !strings.Contains(first, "event: done") || strings.Contains(first, "event: failed") {
		t.Fatalf("流式结束事件不对：\n%s", first)
	}

	second := call()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("第二次查看应命中缓存，实际调用模型 %d 次", got)
	}
	if !strings.Contains(second, `"cached":true`) || !strings.Contains(second, "event: params") {
		t.Fatalf("缓存回放也应补发 params 事件：\n%s", second)
	}
}

// 没填目标时给出可照做的引导，而不是让模型凭空推荐。
func TestAIRecommendHandler_RequiresTargets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("初始化临时数据库失败: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	SetAIConfig(config.AI{BaseURL: "https://ai.example/v1", Model: "m", APIKey: "k"}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	rec := httptest.NewRecorder()
	aiRecommendHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/recommend", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "event: failed") || !strings.Contains(body, "先填写扫描目标") {
		t.Fatalf("缺少目标时应返回引导：\n%s", body)
	}
}

// 未配置模型时，同样通过 failed 事件把原因说清楚。
func TestAIRecommendHandler_NotConfigured(t *testing.T) {
	SetAIConfig(config.AI{}, "")
	t.Cleanup(func() { SetAIConfig(config.AI{}, "") })

	rec := httptest.NewRecorder()
	aiRecommendHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ai/recommend?count=1", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "event: failed") || !strings.Contains(body, "还没有配置模型接口") {
		t.Fatalf("未配置模型时应返回引导：\n%s", body)
	}
}

// 传入的样例与类型分布要经过清洗，避免把任意长文本塞进提示词。
func TestSanitizeRecommendInputs(t *testing.T) {
	if got := sanitizeRecommendKinds("url:12, bad,ip:-3,cidr:1,domain:x"); got != "url:12,cidr:1" {
		t.Fatalf("kinds = %q", got)
	}
	sample := sanitizeRecommendSample(strings.Repeat("a.example\n", 40))
	if got := strings.Count(sample, "\n"); got != aiRecommendSampleLimit-1 {
		t.Fatalf("样例条数应被限制为 %d，实际换行 %d", aiRecommendSampleLimit, got)
	}
}
