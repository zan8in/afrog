package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

func newTestServer() *Server {
	s := New(Options{Policy: policy.Default()})
	s.tools = map[string]*Tool{
		"echo": {
			Name:        "echo",
			Description: "echo arguments",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, args json.RawMessage) (any, error) {
				return string(args), nil
			},
		},
		"boom": {
			Name:        "boom",
			Description: "always fails",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(context.Context, json.RawMessage) (any, error) {
				return nil, errors.New("boom")
			},
		},
	}
	return s
}

func TestServeProtocol(t *testing.T) {
	srv := newTestServer()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"boom"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"no.such"}`,
	}, "\n")

	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	lines := nonEmptyLines(out.String())
	if len(lines) != 5 {
		t.Fatalf("expected 5 responses (notification skipped), got %d: %q", len(lines), out.String())
	}

	// 请求是并发处理的，响应顺序不保证；JSON-RPC 靠 id 配对，测试也按 id 取。
	byID := make(map[int]string, len(lines))
	for _, ln := range lines {
		var env struct {
			ID *int `json:"id"`
		}
		if err := json.Unmarshal([]byte(ln), &env); err != nil || env.ID == nil {
			t.Fatalf("response must carry an id: %s", ln)
		}
		byID[*env.ID] = ln
	}
	for _, id := range []int{1, 2, 3, 4, 5} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing response for id %d: %v", id, lines)
		}
	}

	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(byID[1]), &initResp); err != nil {
		t.Fatalf("decode initialize: %v", err)
	}
	if initResp.Result.ProtocolVersion != "2025-06-18" || initResp.Result.ServerInfo.Name != "afrog" {
		t.Fatalf("unexpected initialize result: %s", byID[1])
	}

	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(byID[2]), &listResp); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(listResp.Result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %+v", listResp.Result.Tools)
	}

	var callResp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(byID[3]), &callResp); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if callResp.Result.IsError || len(callResp.Result.Content) != 1 {
		t.Fatalf("unexpected call result: %s", byID[3])
	}
	if !strings.Contains(callResp.Result.Content[0].Text, `"x":1`) {
		t.Fatalf("arguments not forwarded: %q", callResp.Result.Content[0].Text)
	}

	var errResp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(byID[4]), &errResp); err != nil {
		t.Fatalf("decode tool error: %v", err)
	}
	if !errResp.Result.IsError || !strings.Contains(errResp.Result.Content[0].Text, "boom") {
		t.Fatalf("tool error not surfaced: %s", byID[4])
	}

	var methodErr struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(byID[5]), &methodErr); err != nil {
		t.Fatalf("decode method error: %v", err)
	}
	if methodErr.Error.Code != codeMethodNotFound {
		t.Fatalf("expected -32601, got %s", byID[5])
	}
}

// initialize 必须带 instructions：客户端会把它并入模型上下文，模型才知道
// 「指纹 → poc.search 预检 → scan.start」这条主路径。
func TestInitializeIncludesInstructions(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	got := s.initializeResult(json.RawMessage(`{"protocolVersion":"2025-06-18"}`))
	text, _ := got["instructions"].(string)
	if strings.TrimSpace(text) == "" {
		t.Fatal("initialize result must carry instructions")
	}
	for _, want := range []string{"poc.search", "scan.start"} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions must mention %s: %q", want, text)
		}
	}

	// scan.start 与 poc.search 的描述也要把这条约束说清楚。
	if d := s.tools["scan.start"].Description; !strings.Contains(d, "poc.search") {
		t.Fatalf("scan.start description must point at poc.search: %q", d)
	}
	if d := s.tools["poc.search"].Description; !strings.Contains(d, "-pl -s") {
		t.Fatalf("poc.search description must spell out its `afrog -pl -s` precheck role: %q", d)
	}
}

// initialize 的版本协商按规范：客户端报的支持就沿用，不支持就回我们自己的最新版，
// 而不是原样复述一个并不会说的版本。
func TestInitializeNegotiatesProtocolVersion(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	cases := map[string]string{
		"2025-06-18": "2025-06-18",
		"2024-11-05": "2024-11-05",
		"1999-01-01": ProtocolVersion,
		"":           ProtocolVersion,
	}
	for requested, want := range cases {
		params, _ := json.Marshal(map[string]string{"protocolVersion": requested})
		got, _ := s.initializeResult(params)["protocolVersion"].(string)
		if got != want {
			t.Fatalf("requested %q: got %q, want %q", requested, got, want)
		}
	}
}

// tools/list 必须给每个工具带上 title 与 annotations，并把只读/破坏性区分清楚。
func TestToolListCarriesTitleAndAnnotations(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	byName := map[string]map[string]any{}
	for _, e := range s.toolList() {
		name, _ := e["name"].(string)
		byName[name] = e
	}
	if len(byName) != len(s.tools) {
		t.Fatalf("toolList size = %d, want %d", len(byName), len(s.tools))
	}

	for name, e := range byName {
		if title, _ := e["title"].(string); strings.TrimSpace(title) == "" {
			t.Fatalf("%s must carry a non-empty title", name)
		}
		if _, ok := e["annotations"].(ToolAnnotations); !ok {
			t.Fatalf("%s must carry annotations", name)
		}
	}

	ro, _ := byName["observe.findings"]["annotations"].(ToolAnnotations)
	if !ro.ReadOnlyHint || ro.OpenWorldHint {
		t.Fatalf("observe.findings annotations = %+v, want readOnly & not openWorld", ro)
	}
	st, _ := byName["server.status"]["annotations"].(ToolAnnotations)
	if !st.ReadOnlyHint || st.OpenWorldHint || st.DestructiveHint {
		t.Fatalf("server.status annotations = %+v, want readOnly & not openWorld", st)
	}
	brute, _ := byName["act.brute"]["annotations"].(ToolAnnotations)
	if brute.ReadOnlyHint || !brute.DestructiveHint || !brute.OpenWorldHint {
		t.Fatalf("act.brute annotations = %+v, want destructive & openWorld", brute)
	}
	// 只读与破坏性不应同时成立。
	for name, e := range byName {
		a := e["annotations"].(ToolAnnotations)
		if a.ReadOnlyHint && a.DestructiveHint {
			t.Fatalf("%s is annotated both readOnly and destructive", name)
		}
	}

	// 稳定契约的工具要声明 outputSchema，客户端据此取 structuredContent。
	if byName["poc.search"]["outputSchema"] == nil {
		t.Fatal("poc.search must declare outputSchema")
	}
}

// toolContent 只在声明了 outputSchema 时才附 structuredContent，避免把大 payload 翻倍。
func TestToolContentStructuredOnlyWithSchema(t *testing.T) {
	with := &Tool{Name: "s", OutputSchema: map[string]any{"type": "object"}}
	if _, ok := toolContent(with, map[string]any{"a": 1})["structuredContent"]; !ok {
		t.Fatal("structuredContent expected when outputSchema is set")
	}
	without := &Tool{Name: "n"}
	if _, ok := toolContent(without, map[string]any{"a": 1})["structuredContent"]; ok {
		t.Fatal("structuredContent must be omitted when outputSchema is absent")
	}
}

// 客户端带了 progressToken 才推 notifications/progress；没带就不该推。
func TestToolCallEmitsProgressOnlyWithToken(t *testing.T) {
	s := newTestServer()
	s.tools["tick"] = &Tool{
		Name:        "tick",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if fn := progressFrom(ctx); fn != nil {
				fn(1, 2, "half")
			}
			return "ok", nil
		},
	}

	var got []string
	notify := func(method string, _ any) { got = append(got, method) }

	withToken := &request{ID: json.RawMessage(`1`), Params: json.RawMessage(`{"name":"tick","_meta":{"progressToken":"tok"}}`)}
	if _, _ = s.callTool(context.Background(), withToken, notify); len(got) != 1 || got[0] != "notifications/progress" {
		t.Fatalf("with token: want one progress notification, got %v", got)
	}

	got = nil
	noToken := &request{ID: json.RawMessage(`2`), Params: json.RawMessage(`{"name":"tick"}`)}
	if _, _ = s.callTool(context.Background(), noToken, notify); len(got) != 0 {
		t.Fatalf("without token: want no notification, got %v", got)
	}
}

// reportScanProgress 把子进程的 progress/phase 事件转成一条进度通知；缺 token、
// 事件为 nil、载荷为 nil 时都必须安全返回、不产生通知。
func TestReportScanProgressMapsEvents(t *testing.T) {
	type call struct {
		progress, total float64
		message         string
	}
	var calls []call
	report := func(progress, total float64, message string) {
		calls = append(calls, call{progress, total, message})
	}

	// nil 上报函数、nil 事件：不 panic、无副作用。
	reportScanProgress(nil, &scanstream.Event{Type: scanstream.TypeProgress})
	reportScanProgress(report, nil)

	// 载荷为 nil：按类型跳过，不产生通知。
	reportScanProgress(report, &scanstream.Event{Type: scanstream.TypeProgress})
	reportScanProgress(report, &scanstream.Event{Type: scanstream.TypePhase})
	if len(calls) != 0 {
		t.Fatalf("nil payload must not emit progress, got %v", calls)
	}

	// progress 事件：percent 直接映射，total 归一化到 100，消息含百分比与计数。
	reportScanProgress(report, &scanstream.Event{
		Type:     scanstream.TypeProgress,
		Progress: &scanstream.ProgressEvent{Percent: 42, Finished: 21, Total: 50},
	})
	// phase 事件：消息含阶段名与状态，便于调用方区分「正在哪个阶段」。
	reportScanProgress(report, &scanstream.Event{
		Type:  scanstream.TypePhase,
		Phase: &scanstream.PhaseEvent{Phase: "vuln", Status: "running", Percent: 7, Finished: 3, Total: 40},
	})

	if len(calls) != 2 {
		t.Fatalf("want 2 progress notifications, got %d: %v", len(calls), calls)
	}
	if calls[0].progress != 42 || calls[0].total != 100 ||
		!strings.Contains(calls[0].message, "42%") || !strings.Contains(calls[0].message, "21/50") {
		t.Fatalf("unexpected progress mapping: %+v", calls[0])
	}
	if calls[1].progress != 7 || calls[1].total != 100 ||
		!strings.Contains(calls[1].message, "vuln") || !strings.Contains(calls[1].message, "running") {
		t.Fatalf("unexpected phase mapping: %+v", calls[1])
	}
}

// notifications/cancelled 必须精确取消被点名的调用，且只取消它。
func TestCancelledCancelsInFlightCall(t *testing.T) {
	s := newTestServer()
	started := make(chan struct{})
	s.tools["block"] = &Tool{
		Name:        "block",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		req := &request{ID: json.RawMessage(`7`), Params: json.RawMessage(`{"name":"block"}`)}
		_, _ = s.callTool(context.Background(), req, nil)
	}()

	<-started
	s.cancelCall(json.RawMessage(`{"requestId":7}`))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled call did not return")
	}
}

func TestObserveStateRegistered(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	for _, name := range s.ToolNames() {
		if name == "observe.state" {
			return
		}
	}
	t.Fatal("observe.state must be registered")
}

func TestActBruteRegistered(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	for _, name := range s.ToolNames() {
		if name == "act.brute" {
			return
		}
	}
	t.Fatal("act.brute must be registered")
}

// server.status 是只读自省工具：默认只读档下必须放行，并如实返回档位与预算。
func TestServerStatusTool(t *testing.T) {
	s := New(Options{Policy: policy.Default(), Info: ServerInfo{Name: "afrog", Version: "test"}})

	if _, ok := s.tools["server.status"]; !ok {
		t.Fatal("server.status must be registered")
	}
	if err := s.gate.Take(policy.Action{Name: "server.status"}, 0); err != nil {
		t.Fatalf("server.status must be allowed under readonly policy: %v", err)
	}

	out, err := s.tools["server.status"].Handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T, want map", out)
	}
	if v, _ := m["protocol_version"].(string); v == "" {
		t.Fatal("protocol_version must be present")
	}
	pol, _ := m["policy"].(map[string]any)
	if pol["mode"] != string(policy.DefaultMode) {
		t.Fatalf("policy.mode = %v, want %s", pol["mode"], policy.DefaultMode)
	}
	bud, _ := m["budget"].(map[string]any)
	if bud["requests_remaining"] != policy.DefaultRequests || bud["requests_limit"] != policy.DefaultRequests {
		t.Fatalf("budget = %+v, want remaining=limit=%d on a fresh session", bud, policy.DefaultRequests)
	}
	scope, _ := pol["scope"].(map[string]any)
	if _, ok := scope["allow_hosts"].([]string); !ok {
		t.Fatalf("policy.scope.allow_hosts = %T, want []string (never null)", scope["allow_hosts"])
	}
}

// Judge / Learner 的四个工具是「本地 advisory」：读写本机库、不发包，
// 因此默认只读策略下也必须放行。
func TestJudgeLearnToolsRegisteredAndReadOnlyAllowed(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	registered := map[string]bool{}
	for _, name := range s.ToolNames() {
		registered[name] = true
	}
	for _, name := range []string{"judge.brief", "judge.record", "learn.brief", "learn.record"} {
		if !registered[name] {
			t.Fatalf("%s must be registered", name)
		}
		if err := s.gate.Take(policy.Action{Name: name}, 0); err != nil {
			t.Fatalf("%s must be allowed under readonly policy: %v", name, err)
		}
	}
}

// 破坏性工具必须默认被策略挡住，且在真正发包前就拒绝。
func TestActBruteDeniedByDefault(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	tool := s.tools["act.brute"]
	if tool == nil {
		t.Fatal("act.brute not registered")
	}

	_, err := tool.Handler(context.Background(), json.RawMessage(
		`{"poc_id":"redis-weak-login","target":"127.0.0.1:6379"}`))
	if err == nil || !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestActBruteAllowedOnlyWithFullAndDestructive(t *testing.T) {
	s := New(Options{Policy: &policy.Policy{Mode: policy.ModeFull, Destructive: true}})
	err := s.gate.Take(policy.Action{
		Name:        "act.brute",
		Target:      "127.0.0.1",
		Capability:  capability.Exec,
		Destructive: true,
	}, 1)
	if err != nil {
		t.Fatalf("full+destructive must allow act.brute: %v", err)
	}
}

func TestGateDeniesByPolicy(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	if err := s.gate.Take(policy.Action{Name: "probe.http", Target: "http://example.com"}, 1); err == nil {
		t.Fatal("readonly policy must deny probe.http")
	}
	if err := s.gate.Take(policy.Action{Name: "observe.findings"}, 0); err != nil {
		t.Fatalf("observe must be allowed: %v", err)
	}
}

func TestGateEnforcesBudget(t *testing.T) {
	p := policy.Default()
	s := New(Options{Policy: p, Budget: policy.NewBudget(policy.Limits{Requests: 1}, nowFunc())})
	if err := s.gate.Take(policy.Action{Name: "observe.findings"}, 1); err != nil {
		t.Fatalf("first take: %v", err)
	}
	if err := s.gate.Take(policy.Action{Name: "observe.findings"}, 1); err == nil {
		t.Fatal("budget must reject the second request")
	}
}

func nonEmptyLines(s string) []string {
	out := make([]string, 0, 8)
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
