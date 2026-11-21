package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
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

// initialize 声明的能力必须与「真正实现的 MCP 原语」严格对应：多声明会让客户端去等一个
// 永远不会来的推送，少声明则会让它错过可用能力。本服务实现 tools / logging / resources /
// prompts / completions 五个原语。
//
// 之所以只有这五个：进度通知（notifications/progress）与取消（notifications/cancelled）
// 属于基础协议、无对应能力位。
func TestInitializeCapabilitiesMatchImplementedPrimitives(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	caps, _ := s.initializeResult(json.RawMessage(`{}`))["capabilities"].(map[string]any)
	if len(caps) != 5 {
		t.Fatalf("capabilities = %v, want exactly tools + logging + resources + prompts + completions", caps)
	}
	tools, _ := caps["tools"].(map[string]any)
	if tools == nil || tools["listChanged"] != false {
		t.Fatalf("tools capability = %v, want {listChanged:false}", caps["tools"])
	}
	if _, ok := caps["logging"]; !ok {
		t.Fatal("logging capability must be declared")
	}
	res, _ := caps["resources"].(map[string]any)
	if res == nil || res["subscribe"] != true || res["listChanged"] != false {
		t.Fatalf("resources capability = %v, want {subscribe:true, listChanged:false}", caps["resources"])
	}
	if _, ok := caps["prompts"]; !ok {
		t.Fatal("prompts capability must be declared")
	}
	if _, ok := caps["completions"]; !ok {
		t.Fatal("completions capability must be declared")
	}

	// 已声明的原语必须真的能应答。
	for _, tc := range []struct {
		method string
		params string
	}{
		{"tools/list", ""},
		{"logging/setLevel", `{"level":"info"}`},
		{"resources/list", ""},
		{"resources/templates/list", ""},
		{"resources/subscribe", `{"uri":"afrog://status"}`},
		{"resources/unsubscribe", `{"uri":"afrog://status"}`},
		{"prompts/list", ""},
		{"completion/complete", `{"ref":{"type":"ref/prompt","name":"triage-findings"},"argument":{"name":"severity","value":"h"}}`},
	} {
		var params json.RawMessage
		if tc.params != "" {
			params = json.RawMessage(tc.params)
		}
		resp, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`1`), Method: tc.method, Params: params}, nil)
		if resp == nil || resp.Error != nil {
			t.Fatalf("%s = %+v, want an ok response", tc.method, resp)
		}
	}

	// 不认识的方法必须真的报 method not found，而不是一个空壳成功。
	// completions/complete（复数）是照着能力位想当然写出来的名字，协议里没有这个方法。
	for _, method := range []string{"unknown/method", "completions/complete"} {
		resp, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`2`), Method: method}, nil)
		if resp == nil || resp.Error == nil || resp.Error.Code != codeMethodNotFound {
			t.Fatalf("%s = %+v, want method not found", method, resp)
		}
	}
}

// 资源读取必须复用对应工具的 Handler：门控、参数校验、返回结构都只有一份实现。
func TestResourceReadReusesToolHandlers(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	list, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`1`), Method: "resources/list"}, nil)
	resources, _ := list.Result.(map[string]any)["resources"].([]map[string]any)
	if len(resources) == 0 {
		t.Fatalf("resources/list = %+v, want entries", list.Result)
	}
	uris := map[string]bool{}
	for _, r := range resources {
		u, _ := r["uri"].(string)
		uris[u] = true
		if name, _ := r["name"].(string); strings.TrimSpace(name) == "" {
			t.Fatalf("resource %v must carry a name", r)
		}
	}
	for _, want := range []string{resourceStatusURI, resourceFindingsURI, resourceTasksURI} {
		if !uris[want] {
			t.Fatalf("resources/list is missing %s: %v", want, uris)
		}
	}

	// afrog://status 与 server.status 必须给出同一份内容。
	tool, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"server.status"}`)}, nil)
	toolText := tool.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)

	read, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`3`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"` + resourceStatusURI + `"}`)}, nil)
	if read.Error != nil {
		t.Fatalf("resources/read = %+v", read)
	}
	contents, _ := read.Result.(map[string]any)["contents"].([]map[string]any)
	if len(contents) != 1 {
		t.Fatalf("contents = %+v, want one entry", read.Result)
	}
	got, _ := contents[0]["text"].(string)
	var a, b map[string]any
	if err := json.Unmarshal([]byte(got), &a); err != nil {
		t.Fatalf("resource body is not JSON: %v (%s)", err, got)
	}
	if err := json.Unmarshal([]byte(toolText), &b); err != nil {
		t.Fatalf("tool body is not JSON: %v", err)
	}
	modeOf := func(v map[string]any) any {
		m, _ := v["policy"].(map[string]any)
		return m["mode"]
	}
	if len(a) == 0 || modeOf(a) != modeOf(b) {
		t.Fatalf("resource body %v does not match server.status %v", a, b)
	}

	// 未知 URI 报「找不到」，与「门控拒绝」区分开。
	bad, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`4`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"afrog://nope"}`)}, nil)
	if bad.Error == nil || bad.Error.Code != codeResourceNotFound {
		t.Fatalf("unknown uri = %+v, want codeResourceNotFound", bad)
	}
}

// 资源订阅是会话级状态：订阅后由服务端主动推变更通知，退订即停推；通知只发给订阅了
// 该 URI 的那个会话，没订阅的资源不推。
func TestResourceSubscriptionDeliversUpdates(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	var pushed []string
	unregister := s.RegisterResourcePush("s1", func(method string, params any) {
		if method != "notifications/resources/updated" {
			t.Errorf("notification method = %s, want notifications/resources/updated", method)
			return
		}
		p, _ := params.(map[string]any)
		uri, _ := p["uri"].(string)
		pushed = append(pushed, uri)
	})
	defer unregister()
	ctx := withSession(context.Background(), "s1")

	call := func(method, params string) *response {
		t.Helper()
		resp, _ := s.handle(ctx, &request{ID: json.RawMessage(`1`), Method: method, Params: json.RawMessage(params)}, nil)
		return resp
	}
	subscribe := func(uri string) {
		t.Helper()
		if resp := call("resources/subscribe", `{"uri":"`+uri+`"}`); resp.Error != nil {
			t.Fatalf("subscribe %s = %+v", uri, resp)
		}
	}

	// 参数坏报 -32602；没有 uri、或 URI 不是本服务的资源报 -32002（与 resources/read 一致）。
	if resp := call("resources/subscribe", `123`); resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Fatalf("malformed params = %+v, want codeInvalidParams", resp)
	}
	if resp := call("resources/subscribe", `{}`); resp.Error == nil || resp.Error.Code != codeResourceNotFound {
		t.Fatalf("subscribe without uri = %+v, want codeResourceNotFound", resp)
	}
	if resp := call("resources/subscribe", `{"uri":"afrog://nope"}`); resp.Error == nil || resp.Error.Code != codeResourceNotFound {
		t.Fatalf("subscribe unknown uri = %+v, want codeResourceNotFound", resp)
	}

	subscribe(resourceStatusURI)

	s.notifyResourceUpdated(resourceStatusURI)
	if len(pushed) != 1 || pushed[0] != resourceStatusURI {
		t.Fatalf("pushed = %v, want exactly [%s]", pushed, resourceStatusURI)
	}

	// 重复订阅不产生重复通知：订阅是一份集合，不是计数器。
	subscribe(resourceStatusURI)
	s.notifyResourceUpdated(resourceStatusURI)
	if len(pushed) != 2 {
		t.Fatalf("pushed = %v, want one more notification only", pushed)
	}

	// 没订阅的资源不推。
	s.notifyResourceUpdated(resourceFindingsURI)
	if len(pushed) != 2 {
		t.Fatalf("pushed = %v, want no notification for an unsubscribed resource", pushed)
	}

	// 退订后不再推。
	if resp := call("resources/unsubscribe", `{"uri":"afrog://status"}`); resp.Error != nil {
		t.Fatalf("unsubscribe = %+v", resp)
	}
	s.notifyResourceUpdated(resourceStatusURI)
	if len(pushed) != 2 {
		t.Fatalf("pushed = %v, want no notification after unsubscribe", pushed)
	}

	// 退订从未订阅的 URI 也算成功：退订是「此后别推」，不是「必须曾经订阅过」。
	if resp := call("resources/unsubscribe", `{"uri":"afrog://status"}`); resp.Error != nil {
		t.Fatalf("repeated unsubscribe = %+v", resp)
	}
}

// 任务资源按模板拼 URI：读到的必须是 task.status / task.events 的内容，而不是一句空壳。
func TestTaskResourceTemplates(t *testing.T) {
	s, ex := newTaskTestServer(t, "mode: safe\n")
	taskID, _ := submitFakeTask(t, s, ex)
	waitTaskStatus(t, taskMgrOf(t, s), taskID, scantask.StatusRunning)

	tmpl, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`1`), Method: "resources/templates/list"}, nil)
	templates, _ := tmpl.Result.(map[string]any)["resourceTemplates"].([]map[string]any)
	if len(templates) != 2 {
		t.Fatalf("resourceTemplates = %+v, want two entries", tmpl.Result)
	}

	read, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`2`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"` + resourceTaskPrefix + taskID + `"}`)}, nil)
	if read.Error != nil {
		t.Fatalf("read task resource: %+v", read)
	}
	contents, _ := read.Result.(map[string]any)["contents"].([]map[string]any)
	var view map[string]any
	if err := json.Unmarshal([]byte(contents[0]["text"].(string)), &view); err != nil {
		t.Fatalf("decode task resource: %v", err)
	}
	if view["task_id"] != taskID || view["status"] != "running" {
		t.Fatalf("task resource = %v, want id=%s status=running", view, taskID)
	}

	// task_id 里带 "/" 说明 URI 拼错了，不能拿它去查库。
	bad, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`3`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"` + resourceTaskPrefix + `a/b"}`)}, nil)
	if bad.Error == nil || bad.Error.Code != codeResourceNotFound {
		t.Fatalf("malformed task uri = %+v, want codeResourceNotFound", bad)
	}
}

// prompts/get 必须校验必填参数，并把模板渲染成一条 user 消息。
func TestPromptsListAndGet(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	list, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`1`), Method: "prompts/list"}, nil)
	prompts, _ := list.Result.(map[string]any)["prompts"].([]map[string]any)
	if len(prompts) == 0 {
		t.Fatalf("prompts/list = %+v, want entries", list.Result)
	}
	names := map[string]bool{}
	for _, p := range prompts {
		name, _ := p["name"].(string)
		names[name] = true
		if name == "" {
			t.Fatalf("prompt without name: %v", p)
		}
	}
	if !names["scan-target"] {
		t.Fatalf("prompts/list is missing scan-target: %v", names)
	}

	got, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`2`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"scan-target","arguments":{"target":"http://10.0.0.5:8080","project_id":"p1"}}`)}, nil)
	if got.Error != nil {
		t.Fatalf("prompts/get = %+v", got)
	}
	result := got.Result.(map[string]any)
	messages, _ := result["messages"].([]map[string]any)
	if len(messages) != 1 {
		t.Fatalf("messages = %+v, want one", result["messages"])
	}
	text, _ := messages[0]["content"].(map[string]any)["text"].(string)
	for _, want := range []string{"http://10.0.0.5:8080", "server.status", "task.status", "p1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered prompt is missing %q: %s", want, text)
		}
	}

	// 必填参数缺失：报 -32602，而不是渲染出一句缺了目标的提示词。
	missing, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`3`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"scan-target","arguments":{}}`)}, nil)
	if missing.Error == nil || missing.Error.Code != codeInvalidParams {
		t.Fatalf("missing required argument = %+v, want codeInvalidParams", missing)
	}

	// 未知 prompt 同样报 -32602。
	unknown, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`4`), Method: "prompts/get",
		Params: json.RawMessage(`{"name":"nope"}`)}, nil)
	if unknown.Error == nil || unknown.Error.Code != codeInvalidParams {
		t.Fatalf("unknown prompt = %+v, want codeInvalidParams", unknown)
	}
}

// 结构化输出要成规模：声明 outputSchema 等于承诺「返回结构是稳定契约」，客户端才能按
// structuredContent 取数、而不是去解析 content 里的文本。这里锁住覆盖面，以及唯一的例外。
func TestToolOutputSchemaCoverage(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	// 唯一豁免：observe.state 的返回体随目标规模变化（整张攻击面子图），属于 server.go
	// 里说的「大对象」——声明它只会把同一份 payload 在 content 与 structuredContent 里
	// 各发一遍。
	exempt := map[string]bool{"observe.state": true}

	listed := map[string]bool{}
	for _, e := range s.toolList() {
		name, _ := e["name"].(string)
		listed[name] = true
		if _, ok := e["outputSchema"]; ok != !exempt[name] {
			t.Fatalf("tools/list entry for %s: outputSchema present = %v, want %v", name, ok, !exempt[name])
		}
	}

	for name, tool := range s.tools {
		if !listed[name] {
			t.Fatalf("%s is missing from tools/list", name)
		}
		if exempt[name] {
			if tool.OutputSchema != nil {
				t.Fatalf("%s is exempt from outputSchema but declares one", name)
			}
			continue
		}
		schema, ok := tool.OutputSchema.(map[string]any)
		if !ok {
			t.Fatalf("%s must declare an outputSchema", name)
		}
		if schema["type"] != "object" {
			t.Fatalf("%s outputSchema type = %v, want object", name, schema["type"])
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok || len(props) == 0 {
			t.Fatalf("%s outputSchema must declare properties", name)
		}
		// required 是可选的；一旦写了，里面的字段就必须真的在 properties 里声明过，
		// 否则契约自相矛盾。
		if raw, ok := schema["required"]; ok {
			required, ok := raw.([]string)
			if !ok {
				t.Fatalf("%s outputSchema required = %T, want []string", name, raw)
			}
			for _, r := range required {
				if _, ok := props[r]; !ok {
					t.Fatalf("%s outputSchema requires %q but does not declare it", name, r)
				}
			}
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

// logging 原语：initialize 声明能力，logging/setLevel 设级别，工具执行期间发的日志
// 经 notifications/message 推给客户端，并按已设级别过滤。
func TestLoggingPrimitive(t *testing.T) {
	s := newTestServer()

	caps, _ := s.initializeResult(json.RawMessage(`{}`))["capabilities"].(map[string]any)
	if _, ok := caps["logging"]; !ok {
		t.Fatal("initialize must declare logging capability")
	}

	// setLevel 校验：未知级别报 -32602，合法级别生效。
	bad, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`9`),
		Method: "logging/setLevel", Params: json.RawMessage(`{"level":"bogus"}`)}, nil)
	if bad == nil || bad.Error == nil {
		t.Fatal("unknown log level must be rejected")
	}

	s.tools["talk"] = &Tool{
		Name:        "talk",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if fn := loggerFrom(ctx); fn != nil {
				fn("info", "started")
				fn("error", "boom")
			}
			return "ok", nil
		},
	}

	var got []map[string]any
	notify := func(method string, params any) {
		if method != "notifications/message" {
			return
		}
		m, _ := params.(map[string]any)
		got = append(got, m)
	}
	call := func() {
		_, _ = s.callTool(context.Background(),
			&request{ID: json.RawMessage(`1`), Params: json.RawMessage(`{"name":"talk"}`)}, notify)
	}

	// 默认级别 info：info 与 error 都推。
	call()
	if len(got) != 2 {
		t.Fatalf("default level: want info+error, got %v", got)
	}

	// 设到 error 后，info 被过滤，只剩 error。
	got = nil
	ok, _ := s.handle(context.Background(), &request{ID: json.RawMessage(`10`),
		Method: "logging/setLevel", Params: json.RawMessage(`{"level":"error"}`)}, nil)
	if ok == nil || ok.Error != nil {
		t.Fatalf("valid log level must be accepted: %+v", ok)
	}
	call()
	if len(got) != 1 || got[0]["level"] != "error" {
		t.Fatalf("after setLevel(error): want only error, got %v", got)
	}
}

// reportScanLog 把子进程诊断日志映射成 MCP 级别；空载荷、缺通道时安全返回。
func TestReportScanLogMapsLevels(t *testing.T) {
	type call struct{ level, message string }
	var calls []call
	logf := func(level, message string) { calls = append(calls, call{level, message}) }

	reportScanLog(nil, &scanstream.Event{Type: scanstream.TypeLog, Log: &scanstream.LogEvent{Level: "INF", Text: "x"}})
	reportScanLog(logf, nil)
	reportScanLog(logf, &scanstream.Event{Type: scanstream.TypeLog})
	if len(calls) != 0 {
		t.Fatalf("nil payload/channel must not emit, got %v", calls)
	}

	for _, tc := range []struct{ in, want string }{
		{"INF", "info"}, {"WRN", "warning"}, {"ERR", "error"}, {"DBG", "debug"}, {"", "info"},
	} {
		reportScanLog(logf, &scanstream.Event{Type: scanstream.TypeLog, Log: &scanstream.LogEvent{Level: tc.in, Text: "m"}})
		if last := calls[len(calls)-1]; last.level != tc.want {
			t.Fatalf("level %q: want %q, got %q", tc.in, tc.want, last.level)
		}
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

// 工具错误的机器可读分类必须与 REST/gRPC 同口径：Agent 靠 kind 分流，而不是去猜中文文本。
func TestClassifyToolError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		kind      string
		retryable bool
	}{
		{"策略拒绝", fmt.Errorf("%w action %q: %s", policy.ErrDenied, "act.brute", "readonly"), errKindPolicyDenied, false},
		{"额度耗尽", fmt.Errorf("%w: window busy", policy.ErrBudgetExceeded), errKindBudgetExhausted, true},
		{"OOB 未配置", errOOBUnavailable, errKindNotConfigured, false},
		{"普通错误", errors.New("target is required"), errKindInvalidParams, true},
	}
	for _, tc := range cases {
		got := classifyToolError(tc.err)
		if got.Kind != tc.kind || got.Retryable != tc.retryable {
			t.Errorf("%s: got kind=%s retryable=%t, want kind=%s retryable=%t",
				tc.name, got.Kind, got.Retryable, tc.kind, tc.retryable)
		}
		if got.Message != tc.err.Error() {
			t.Errorf("%s: message = %q, want the original error text", tc.name, got.Message)
		}
		if strings.TrimSpace(got.Hint) == "" {
			t.Errorf("%s: hint must never be empty", tc.name)
		}
	}
}

// toolError 同时给人类可读文本与机器可读 _meta：不少客户端不把 _meta 交给模型，
// 所以 kind/retryable 要在文本里再出现一次。
func TestToolErrorCarriesStructuredMeta(t *testing.T) {
	out := toolError(fmt.Errorf("%w action %q: %s", policy.ErrDenied, "probe.http", "readonly"))

	if out["isError"] != true {
		t.Fatalf("isError = %v, want true", out["isError"])
	}
	content, _ := out["content"].([]map[string]any)
	if len(content) != 1 {
		t.Fatalf("content = %+v, want one entry", out["content"])
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "[kind=policy_denied retryable=false]") {
		t.Fatalf("error text must repeat kind/retryable for clients that drop _meta: %q", text)
	}
	if !strings.Contains(text, "policy denied") {
		t.Fatalf("error text must keep the original message: %q", text)
	}

	meta, _ := out["_meta"].(map[string]any)
	info, _ := meta["afrog/error"].(toolErrorInfo)
	if info.Kind != errKindPolicyDenied || info.Retryable {
		t.Fatalf("_meta[afrog/error] = %+v, want policy_denied & not retryable", meta["afrog/error"])
	}
	if _, ok := out["structuredContent"]; ok {
		t.Fatal("errors must not be smuggled into structuredContent (it clashes with outputSchema)")
	}
}

// 走 stdio 传输时 _meta 要真的落到线上，而不只是内存里的结构体。
func TestServeProtocolToolErrorMeta(t *testing.T) {
	srv := newTestServer()
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom"}}`), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	var env struct {
		Result struct {
			IsError bool `json:"isError"`
			Meta    map[string]struct {
				Kind      string `json:"kind"`
				Retryable bool   `json:"retryable"`
				Hint      string `json:"hint"`
			} `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(nonEmptyLines(out.String())[0]), &env); err != nil {
		t.Fatalf("decode: %v (%s)", err, out.String())
	}
	if !env.Result.IsError {
		t.Fatal("boom must surface as a tool error")
	}
	info := env.Result.Meta["afrog/error"]
	if info.Kind != errKindInvalidParams || !info.Retryable || strings.TrimSpace(info.Hint) == "" {
		t.Fatalf("afrog/error = %+v, want invalid_params & retryable & a hint", info)
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
