package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/policy"
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

	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("decode initialize: %v", err)
	}
	if initResp.Result.ProtocolVersion != "2025-06-18" || initResp.Result.ServerInfo.Name != "afrog" {
		t.Fatalf("unexpected initialize result: %s", lines[0])
	}

	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
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
	if err := json.Unmarshal([]byte(lines[2]), &callResp); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if callResp.Result.IsError || len(callResp.Result.Content) != 1 {
		t.Fatalf("unexpected call result: %s", lines[2])
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
	if err := json.Unmarshal([]byte(lines[3]), &errResp); err != nil {
		t.Fatalf("decode tool error: %v", err)
	}
	if !errResp.Result.IsError || !strings.Contains(errResp.Result.Content[0].Text, "boom") {
		t.Fatalf("tool error not surfaced: %s", lines[3])
	}

	var methodErr struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[4]), &methodErr); err != nil {
		t.Fatalf("decode method error: %v", err)
	}
	if methodErr.Error.Code != codeMethodNotFound {
		t.Fatalf("expected -32601, got %s", lines[4])
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
