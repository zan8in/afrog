package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

// Supports 必须与映射表一致：已实现的四类工具面动作都认，执行面动作一律不认。
func TestDispatcherSupportsToolFaceKinds(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\n")
	d := s.Dispatcher()

	for _, k := range []scantask.ActionKind{
		scantask.ActionProbeHTTP, scantask.ActionReplayEvidence, scantask.ActionBrute, scantask.ActionOOBWait,
	} {
		if !d.Supports(k) {
			t.Fatalf("Supports(%s) = false, want true", k)
		}
	}
	for _, k := range []scantask.ActionKind{
		scantask.ActionRunPoc, scantask.ActionPortScan, scantask.ActionWebFingerprint, "no_such_kind",
	} {
		if d.Supports(k) {
			t.Fatalf("Supports(%s) = true, want false", k)
		}
	}
}

// 映射表只覆盖已实现的工具：多一个死值就意味着有动作永远落不到实现。
func TestToolFaceToolsCoverOnlyImplementedTools(t *testing.T) {
	want := map[scantask.ActionKind]string{
		scantask.ActionProbeHTTP:      "probe.http",
		scantask.ActionReplayEvidence: "verify.replay",
		scantask.ActionBrute:          "act.brute",
		scantask.ActionOOBWait:        "act.oob_wait",
	}
	if len(toolFaceTools) != len(want) {
		t.Fatalf("toolFaceTools = %v, want exactly %d entries", toolFaceTools, len(want))
	}
	for k, tool := range want {
		if got := toolFaceTools[k]; got != tool {
			t.Fatalf("toolFaceTools[%s] = %q, want %q", k, got, tool)
		}
	}
}

func TestDispatchRejectsEmptyBatch(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\n")
	if _, err := s.Dispatcher().Dispatch(context.Background(), "task-1", scantask.Batch{}); err == nil {
		t.Fatal("empty batch must be rejected")
	}
}

// 执行面动作没有对应工具，不能被工具面误接。
func TestDispatchRejectsUnmappedKind(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\n")
	if _, err := s.Dispatcher().Dispatch(context.Background(), "task-1", scantask.Batch{
		Actions: []scantask.Action{{Kind: scantask.ActionRunPoc, Target: "http://127.0.0.1:1/x"}},
	}); err == nil {
		t.Fatal("run_poc has no tool-face implementation and must be rejected")
	}
}

// Target / PocID 要按各工具自己的入参名补默认值。
func TestActionArgsDefaultsFromAction(t *testing.T) {
	cases := []struct {
		name string
		a    scantask.Action
		want map[string]any
	}{
		{
			name: "probe_http fills url",
			a:    scantask.Action{Kind: scantask.ActionProbeHTTP, Target: "http://a/x"},
			want: map[string]any{"url": "http://a/x"},
		},
		{
			name: "replay_evidence fills target",
			a:    scantask.Action{Kind: scantask.ActionReplayEvidence, Target: "http://a/x"},
			want: map[string]any{"target": "http://a/x"},
		},
		{
			name: "brute fills target and poc_id",
			a:    scantask.Action{Kind: scantask.ActionBrute, Target: "http://a/x", PocID: "poc-1"},
			want: map[string]any{"target": "http://a/x", "poc_id": "poc-1"},
		},
		{
			name: "oob_wait fills target",
			a:    scantask.Action{Kind: scantask.ActionOOBWait, Target: "http://a/x"},
			want: map[string]any{"target": "http://a/x"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := actionArgs(tc.a)
			if err != nil {
				t.Fatalf("actionArgs: %v", err)
			}
			assertArgsEqual(t, got, tc.want)
		})
	}
}

// Params 里显式给出的字段不能被动作自带的定位信息覆盖。
func TestActionArgsParamsWinOverDefaults(t *testing.T) {
	got, err := actionArgs(scantask.Action{
		Kind:   scantask.ActionProbeHTTP,
		Target: "http://ignored/x",
		Params: json.RawMessage(`{"url":"http://explicit/x","method":"POST"}`),
	})
	if err != nil {
		t.Fatalf("actionArgs: %v", err)
	}
	assertArgsEqual(t, got, map[string]any{"url": "http://explicit/x", "method": "POST"})
}

// 非对象参数要报错；字面量 null 是合法 JSON，要归一成空对象而不是 panic。
func TestActionArgsRejectsNonObjectParams(t *testing.T) {
	if _, err := actionArgs(scantask.Action{
		Kind:   scantask.ActionProbeHTTP,
		Target: "http://a/x",
		Params: json.RawMessage(`["nope"]`),
	}); err == nil {
		t.Fatal("array params must be rejected")
	}

	got, err := actionArgs(scantask.Action{
		Kind:   scantask.ActionProbeHTTP,
		Target: "http://a/x",
		Params: json.RawMessage(`null`),
	})
	if err != nil {
		t.Fatalf("null params: %v", err)
	}
	assertArgsEqual(t, got, map[string]any{"url": "http://a/x"})
}

// 经派发的真实 probe.http 要跑完并给出 completed，事件流以 done 收尾。
func TestDispatchProbeHTTPEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello dispatch"))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	h, err := s.Dispatcher().Dispatch(context.Background(), "task-1", scantask.Batch{
		Actions: []scantask.Action{
			{Kind: scantask.ActionProbeHTTP, Target: srv.URL + "/a"},
			{Kind: scantask.ActionProbeHTTP, Target: srv.URL + "/b"},
		},
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	events := drainHandle(t, h, 10*time.Second)
	if h.Err() != nil {
		t.Fatalf("Err = %v, want nil", h.Err())
	}
	if len(events) != 3 { // 两次动作日志 + 一次 done
		t.Fatalf("events = %d (%v), want 2 logs + 1 done", len(events), dispatchTypes(events))
	}
	for i := 0; i < 2; i++ {
		if events[i].Type != scanstream.TypeLog || events[i].Log == nil {
			t.Fatalf("event %d = %+v, want an info log", i, events[i])
		}
	}
	last := events[2]
	if last.Type != scanstream.TypeDone || last.Done == nil || last.Done.Status != "completed" {
		t.Fatalf("last event = %+v, want a completed done", last)
	}
	if last.Done.Summary == nil || last.Done.Summary.Executed != 2 {
		t.Fatalf("summary = %+v, want executed=2", last.Done.Summary)
	}
}

// 全部动作失败时判为失败：发一条 error 事件，不发 done。
func TestDispatchAllFailuresReportError(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")

	h, err := s.Dispatcher().Dispatch(context.Background(), "task-1", scantask.Batch{
		Actions: []scantask.Action{
			{Kind: scantask.ActionProbeHTTP, Target: "http://127.0.0.1:1/x"},
		},
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	events := drainHandle(t, h, 10*time.Second)
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	last := events[len(events)-1]
	if last.Type != scanstream.TypeError || last.Error == nil || last.Error.Code != "dispatch_failed" {
		t.Fatalf("last event = %+v, want a dispatch_failed error", last)
	}
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

func drainHandle(t *testing.T, h executor.Handle, timeout time.Duration) []*scanstream.Event {
	t.Helper()
	deadline := time.After(timeout)
	var out []*scanstream.Event
	for {
		select {
		case ev, ok := <-h.Events():
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline:
			t.Fatalf("timeout waiting for dispatch events, got %d: %v", len(out), dispatchTypes(out))
		}
	}
}

func dispatchTypes(events []*scanstream.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Type)
	}
	return out
}

func assertArgsEqual(t *testing.T, raw json.RawMessage, want map[string]any) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode args %s: %v", raw, err)
	}
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("args[%s] = %v, want %v (all %v)", k, got[k], v, got)
		}
	}
}
