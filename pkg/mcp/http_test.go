package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

func postStreamable(t *testing.T, url, session, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, data
}

func TestStreamableHTTPInitializeAndTools(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("unexpected content type: %q", ct)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize must return Mcp-Session-Id")
	}

	var init struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &init); err != nil {
		t.Fatalf("decode initialize: %v (%s)", err, body)
	}
	if init.Result.ProtocolVersion != "2025-06-18" {
		t.Fatalf("unexpected protocol version: %q", init.Result.ProtocolVersion)
	}

	// 通知：202 且没有响应体。
	notifyResp, notifyBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if notifyResp.StatusCode != http.StatusAccepted || len(notifyBody) != 0 {
		t.Fatalf("notification = %d %q, want 202 empty", notifyResp.StatusCode, notifyBody)
	}

	// 带会话调 tools/list。
	listResp, listBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", listResp.StatusCode, listBody)
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode tools/list: %v (%s)", err, listBody)
	}
	if len(list.Result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %+v", list.Result.Tools)
	}
}

func TestStreamableHTTPBatch(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch status = %d: %s", resp.StatusCode, body)
	}

	var out []struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode batch: %v (%s)", err, body)
	}
	if len(out) != 1 || string(out[0].ID) != "1" {
		t.Fatalf("batch must return only the request with id: %s", body)
	}
}

func TestStreamableHTTPUnknownSession(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, _ := postStreamable(t, ts.URL+"/mcp", "not-a-session",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// GET 是服务端推送流：没带会话（或会话未知）时必须 404，而不是挂住不响应，
// 也不是像本服务早先那样一律 405——那样客户端会以为这个传输根本没有推送能力。
func TestStreamableHTTPStreamRequiresSession(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	for _, tc := range []struct{ name, session string }{
		{"no session", ""},
		{"unknown session", "not-a-session"},
	} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Accept", "text/event-stream")
		if tc.session != "" {
			req.Header.Set("Mcp-Session-Id", tc.session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: get: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", tc.name, resp.StatusCode)
		}
	}
}

// 推送流把工具执行期间的进度与日志实时下发——这正是「Streamable HTTP 也能看进度」
// 的兑现方式：POST 是一问一答，通知只能走这条 GET 流。
func TestStreamableHTTPPushStream(t *testing.T) {
	s := newTestServer()
	s.tools["tick"] = &Tool{
		Name:        "tick",
		Description: "reports progress and a log line",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if p := progressFrom(ctx); p != nil {
				p(1, 2, "half")
			}
			if l := loggerFrom(ctx); l != nil {
				l("info", "hello")
			}
			return "done", nil
		},
	}
	ts := httptest.NewServer(newHTTPMux(s, ""))
	// 用 t.Cleanup 而不是 defer：推送流要先关（dialStream 里的 cleanup 后注册、先执行），
	// 否则 ts.Close 会一直等这条永不结束的 GET 请求，把测试挂死。
	t.Cleanup(ts.Close)

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("initialize must return a session: %s", body)
	}

	stream := dialStream(t, ts.URL+"/mcp", session)

	// 带 progressToken 调一次会发通知的工具；响应仍从 POST 回，通知走 GET 流。
	callResp, callBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tick","_meta":{"progressToken":"tok-1"}}}`)
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call status = %d: %s", callResp.StatusCode, callBody)
	}

	prog := stream.waitForNotification(t, "notifications/progress")
	if prog["progress"] != float64(1) || prog["total"] != float64(2) || prog["message"] != "half" {
		t.Fatalf("progress params = %#v", prog)
	}
	if prog["progressToken"] != "tok-1" {
		t.Fatalf("progressToken = %v, want tok-1", prog["progressToken"])
	}

	msg := stream.waitForNotification(t, "notifications/message")
	if msg["level"] != "info" || msg["logger"] != "afrog" || msg["data"] != "hello" {
		t.Fatalf("log params = %#v", msg)
	}

	// 会话终止要顺带关掉推送流，否则客户端会挂在一个再也不会有消息的流上。
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/mcp", nil)
	req.Header.Set("Mcp-Session-Id", session)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	stream.waitClosed(t)
}

// 一个会话只允许一条 GET 流：重复开必须 409，否则第二条流会永远收不到东西却看起来正常。
func TestStreamableHTTPRejectsSecondStream(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	t.Cleanup(ts.Close)

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	dialStream(t, ts.URL+"/mcp", session)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", session)
	second, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second stream status = %d, want 409", second.StatusCode)
	}
}

// 客户端没开推送流时，带 progressToken 的调用必须照常成功——进度是可选增强，
// 不能因为没人听就失败。
func TestStreamableHTTPCallWithoutStream(t *testing.T) {
	s := newTestServer()
	s.tools["tick"] = &Tool{
		Name:        "tick",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if p := progressFrom(ctx); p != nil {
				p(1, 2, "half")
			}
			return "ok", nil
		},
	}
	ts := httptest.NewServer(newHTTPMux(s, ""))
	defer ts.Close()

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	callResp, callBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tick","_meta":{"progressToken":"tok"}}}`)
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", callResp.StatusCode, callBody)
	}
	if !strings.Contains(string(callBody), `"ok"`) {
		t.Fatalf("call result = %s, want the tool result", callBody)
	}
}

// callHTTPTool 经 /mcp 调一个工具，并把结果按结构化输出取回。
//
// 走 structuredContent 而不是解析 content 里的文本：这正是声明了 outputSchema 的工具
// 对客户端承诺的取数方式，用它断言等于顺带验证了那条契约在 HTTP 传输下成立。
func callHTTPTool(t *testing.T, url, session, name string, args map[string]any) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	_, body := postStreamable(t, url, session,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":`+string(params)+`}`)

	var out struct {
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
			IsError           bool           `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v (%s)", name, err, body)
	}
	if out.Result.IsError {
		t.Fatalf("%s returned a tool error: %s", name, body)
	}
	if out.Result.StructuredContent == nil {
		t.Fatalf("%s has no structuredContent: %s", name, body)
	}
	return out.Result.StructuredContent
}

// callHTTPToolText 经 /mcp 调一个工具，再把文本内容按 JSON 解回。
// 尚未声明 outputSchema 的工具没有 structuredContent，只能这样取数。
func callHTTPToolText(t *testing.T, url, session, name string, args map[string]any) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	_, body := postStreamable(t, url, session,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":`+string(params)+`}`)

	var out struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v (%s)", name, err, body)
	}
	if out.Result.IsError {
		t.Fatalf("%s returned a tool error: %s", name, body)
	}
	if len(out.Result.Content) == 0 {
		t.Fatalf("%s returned no content: %s", name, body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out.Result.Content[0].Text), &m); err != nil {
		t.Fatalf("decode %s content: %v (%s)", name, err, out.Result.Content[0].Text)
	}
	return m
}

// /mcp 传输下的长任务闭环：短等窗口内跑不完 → 拿 task_id 句柄 → 用 task.status 跟踪
// → 跑完后取得汇总与事件。这条链路此前只在 stdio / 子进程路径有覆盖。
func TestStreamableHTTPLongTaskLoop(t *testing.T) {
	p, err := policy.Parse([]byte("mode: safe\n"))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	ex := newFakeScanExecutor()
	srv := New(Options{Policy: p, Executor: ex})
	ts := httptest.NewServer(newHTTPMux(srv, ""))
	t.Cleanup(ts.Close)

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}
	mgr := taskMgrOf(t, srv)

	// 短等窗口压到 1ms：任务必然还没跑完，于是走「转句柄」这条路径。
	outcome, err := srv.submitScan(context.Background(),
		&executor.Spec{Targets: []string{"http://127.0.0.1:1/"}}, 0, time.Millisecond)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if outcome.Done() {
		t.Fatal("outcome.Done() = true, want a pending handle")
	}
	taskID := outcome.TaskID
	if taskID == "" {
		t.Fatal("pending handle without task_id")
	}
	handle := ex.waitHandle(t, taskID)
	waitTaskStatus(t, mgr, taskID, scantask.StatusRunning)

	// 句柄查得到：经 /mcp 读任务状态。
	running := callHTTPTool(t, ts.URL+"/mcp", session, "task.status", map[string]any{"task_id": taskID})
	if running["status"] != "running" || running["task_id"] != taskID {
		t.Fatalf("running view = %#v, want status=running id=%s", running, taskID)
	}
	if running["hit_total"] != float64(0) {
		t.Fatalf("hit_total = %v, want 0 before any hit", running["hit_total"])
	}

	// 让它产出一条命中并收尾。
	handle.emit(&scanstream.Event{Type: scanstream.TypeResult, Result: &scanstream.ResultEvent{
		PocID: "poc-x", PocName: "X", Severity: "high", Target: "http://127.0.0.1:1/",
	}})
	finishFakeTask(t, mgr, taskID, handle)

	done := callHTTPTool(t, ts.URL+"/mcp", session, "task.status", map[string]any{"task_id": taskID})
	if done["status"] != "completed" {
		t.Fatalf("status = %v, want completed", done["status"])
	}
	if done["hit_total"] != float64(1) {
		t.Fatalf("hit_total = %v, want 1", done["hit_total"])
	}
	summary, _ := done["summary"].(map[string]any)
	if summary == nil || summary["found"] != float64(1) {
		t.Fatalf("summary = %#v, want found=1", done["summary"])
	}

	// 事件拉取同样经 /mcp 可用，且收尾后 done 为真。
	events := callHTTPToolText(t, ts.URL+"/mcp", session, "task.events", map[string]any{"task_id": taskID})
	if events["done"] != true {
		t.Fatalf("events done = %v, want true after completion", events["done"])
	}
	items, _ := events["events"].([]any)
	if len(items) == 0 {
		t.Fatalf("events = %#v, want at least the status/result events", events["events"])
	}
	foundResult := false
	for _, it := range items {
		if ev, ok := it.(map[string]any); ok && ev["type"] == "result" {
			foundResult = true
		}
	}
	if !foundResult {
		t.Fatalf("no result event in %#v", items)
	}
	if events["last_seq"] != events["count"] {
		t.Fatalf("last_seq = %v, count = %v, want equal on a fresh pull", events["last_seq"], events["count"])
	}
}

// sseStream 是测试侧的推送流读取器：把 SSE 行喂进 channel，便于带超时地等待。
type sseStream struct {
	lines chan string
}

func dialStream(t *testing.T, url, session string) *sseStream {
	t.Helper()
	return dialStreamWithLastEvent(t, url, session, "")
}

// dialStreamWithLastEvent 打开 GET 推送流，并按需带上 Last-Event-ID 声明断点：服务端
// 据此从会话缓冲补发 id 更大的通知（见 handleStream）。
func dialStreamWithLastEvent(t *testing.T, url, session, lastID string) *sseStream {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", session)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		resp.Body.Close()
		t.Fatalf("stream content type = %q, want text/event-stream", ct)
	}
	t.Cleanup(func() { resp.Body.Close() })

	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return &sseStream{lines: lines}
}

// waitForNotification 等一条指定 method 的通知，返回它的 params。
func (s *sseStream) waitForNotification(t *testing.T, method string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ln, ok := <-s.lines:
			if !ok {
				t.Fatalf("stream closed while waiting for %s", method)
			}
			payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "data:"))
			if !strings.HasPrefix(payload, "{") {
				continue
			}
			var env struct {
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			if err := json.Unmarshal([]byte(payload), &env); err != nil {
				continue
			}
			if env.Method == method {
				return env.Params
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %s", method)
		}
	}
}

func (s *sseStream) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-s.lines:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("stream did not close")
		}
	}
}

// nextEvent 读一条完整的 SSE 事件帧，返回它的 id 与 data 里的 JSON-RPC 报文。
// 断线续传要断言的正是「补发的事件带了哪个 id」，所以这里必须把 id 一并取回。
func (s *sseStream) nextEvent(t *testing.T) (int, map[string]any) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	id := -1
	payload := ""
	for {
		select {
		case ln, ok := <-s.lines:
			if !ok {
				t.Fatal("stream closed while waiting for an event")
			}
			ln = strings.TrimSpace(ln)
			switch {
			case ln == "":
				if payload == "" {
					continue
				}
				var env map[string]any
				if err := json.Unmarshal([]byte(payload), &env); err != nil {
					t.Fatalf("event payload is not JSON: %q", payload)
				}
				return id, env
			case strings.HasPrefix(ln, "id:"):
				v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ln, "id:")))
				if err != nil {
					t.Fatalf("event id is not a number: %q", ln)
				}
				id = v
			case strings.HasPrefix(ln, "data:"):
				payload = strings.TrimSpace(strings.TrimPrefix(ln, "data:"))
			}
		case <-deadline:
			t.Fatal("timeout waiting for an SSE event")
		}
	}
}

// eventBuffer 是 GET 流的断线续传缓冲：id 只增不减，按 Last-Event-ID 补发 id 更大的，
// 超量裁剪与超大跳过都在这里锁住。
func TestEventBufferResume(t *testing.T) {
	b := eventBuffer{max: 3, maxLen: 8}

	// id 递增、不重复。
	for i := 0; i < 3; i++ {
		if ev := b.push([]byte("x")); ev.id != i {
			t.Fatalf("push #%d id = %d, want %d", i, ev.id, i)
		}
	}
	if got := b.since("0"); len(got) != 2 || got[0].id != 1 || got[1].id != 2 {
		t.Fatalf("since(0) = %+v, want ids 1,2", got)
	}

	// 空 / 非数字断点不补发：客户端没声明断点就不该凭空重发。
	if got := b.since(""); got != nil {
		t.Fatalf("since(\"\") = %+v, want nil", got)
	}
	if got := b.since("nope"); got != nil {
		t.Fatalf("since(nope) = %+v, want nil", got)
	}
	// 断点已是最新则不补发任何东西。
	if got := b.since("2"); len(got) != 0 {
		t.Fatalf("since(2) = %+v, want nothing", got)
	}

	// 超出条数上限后裁剪最旧的，id 仍一路递增。
	b.push([]byte("y"))
	if len(b.events) != 3 || b.events[0].id != 1 {
		t.Fatalf("buffer = %+v, want the 3 newest events (ids 1..3)", b.events)
	}
	if got := b.since("0"); len(got) != 3 || got[len(got)-1].id != 3 {
		t.Fatalf("since(0) = %+v, want ids 1,2,3", got)
	}

	// 超过单条字节上限的事件照常下发（带 id），但不进缓冲——否则几条 MB 级响应就能把
	// 内存占满。
	big := b.push([]byte("0123456789"))
	if big.id != 4 || len(big.data) != 10 {
		t.Fatalf("oversized event = %+v, want a full event with id 4", big)
	}
	if got := b.since("3"); len(got) != 0 {
		t.Fatalf("since(3) = %+v, want the oversized event left out of the buffer", got)
	}
}

// 客户端第一次没开 GET 流就调用长任务：通知进缓冲；带 Last-Event-ID 补开流时能把漏掉
// 的那条按原 id 取回，不至于「断了一段就永远看不到进度」。
func TestStreamableHTTPResumesMissedEvents(t *testing.T) {
	s := newTestServer()
	s.tools["tick"] = &Tool{
		Name:        "tick",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if p := progressFrom(ctx); p != nil {
				p(1, 2, "first")
				p(2, 2, "second")
			}
			return "ok", nil
		},
	}
	ts := httptest.NewServer(newHTTPMux(s, ""))
	t.Cleanup(ts.Close)

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	// 还没开 GET 流就先调一次：两条通知只进续传缓冲（id 0、1）。
	callResp, callBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tick","_meta":{"progressToken":"t"}}}`)
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("call status = %d: %s", callResp.StatusCode, callBody)
	}

	// 补开流，声明「只收到了 id=0 那条」：服务端应从缓冲补发 id 更大的那条。
	stream := dialStreamWithLastEvent(t, ts.URL+"/mcp", session, "0")
	id, env := stream.nextEvent(t)
	if id != 1 {
		t.Fatalf("replayed event id = %d, want 1", id)
	}
	if env["method"] != "notifications/progress" {
		t.Fatalf("replayed event = %#v, want a progress notification", env)
	}
	params, _ := env["params"].(map[string]any)
	if params["message"] != "second" {
		t.Fatalf("replayed params = %#v, want the missed notification (second)", params)
	}
}

// 不带 Last-Event-ID 补开流时不补发：客户端没声明断点，凭空重发一批它可能已处理过
// 的事件只会造成重复。
func TestStreamableHTTPStreamWithoutLastEventIDDoesNotReplay(t *testing.T) {
	s := newTestServer()
	s.tools["tick"] = &Tool{
		Name:        "tick",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if p := progressFrom(ctx); p != nil {
				p(1, 2, "before")
			}
			return "ok", nil
		},
	}
	ts := httptest.NewServer(newHTTPMux(s, ""))
	t.Cleanup(ts.Close)

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	// 先在无流状态下产生一条通知（id 0），再不带断点补开流。
	if _, callBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tick","_meta":{"progressToken":"t"}}}`); len(callBody) == 0 {
		t.Fatal("expected a call response")
	}
	stream := dialStream(t, ts.URL+"/mcp", session)

	// 再调一次：实时下发的那条必须是它自己的 id（1），而不是把 id 0 也重发过来。
	postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tick","_meta":{"progressToken":"t"}}}`)
	id, _ := stream.nextEvent(t)
	if id != 1 {
		t.Fatalf("first event id = %d, want 1 (no replay of the buffered id 0)", id)
	}
}

func TestStreamableHTTPDeleteSession(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	_, _ = postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	// 重新拿一个会话 id（initialize 响应头已消费在上面的 helper 里）。
	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/mcp", nil)
	req.Header.Set("Mcp-Session-Id", session)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", delResp.StatusCode)
	}

	after, _ := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("after delete status = %d, want 404", after.StatusCode)
	}
}

func TestStreamableHTTPRequiresToken(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), "secret"))
	defer ts.Close()

	resp, _ := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// Origin 校验是防 DNS rebinding 的：浏览器带来的跨站 Origin 必须被挡在门外，
// 而 curl / 原生客户端（不带 Origin）不受影响。
func TestStreamableHTTPOriginGuard(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	status := func(origin, host string) int {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	cases := []struct {
		name         string
		origin, host string
		want         int
	}{
		{"no origin", "", "", http.StatusOK},
		{"loopback origin", "http://127.0.0.1:3000", "", http.StatusOK},
		{"localhost origin", "http://localhost:3000", "", http.StatusOK},
		{"same host as request", "http://scan.corp.example", "scan.corp.example", http.StatusOK},
		{"foreign origin", "https://evil.example", "scan.corp.example", http.StatusForbidden},
		{"opaque null origin", "null", "scan.corp.example", http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := status(tc.origin, tc.host); got != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, got, tc.want)
		}
	}
}
