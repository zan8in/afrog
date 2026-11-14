package runner

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

func TestBuildEvidenceFromResult(t *testing.T) {
	r := &result.Result{
		Target:     "https://example.com/a",
		FullTarget: "https://example.com/a?id=1'",
		PocInfo:    &poc.Poc{Id: "test-poc"},
		Extractor:  yaml.MapSlice{{Key: "proof", Value: "SQL syntax error"}},
		AllPocResult: []*result.PocResult{
			{
				IsVul:      false,
				FullTarget: "https://example.com/a?id=1",
				ResultRequest: &proto.Request{
					Method:    "GET",
					RawHeader: []byte("GET /a?id=1 HTTP/1.1\r\nHost: example.com\r\n"),
				},
				ResultResponse: &proto.Response{Status: 200, RawHeader: []byte("HTTP/1.1 200 OK\r\n"), Body: []byte("ok")},
			},
			{
				IsVul:      true,
				FullTarget: "https://example.com/a?id=1'",
				ResultRequest: &proto.Request{
					Method:    "GET",
					RawHeader: []byte("GET /a?id=1%27 HTTP/1.1\r\nHost: example.com\r\n"),
				},
				ResultResponse: &proto.Response{
					Status:    500,
					RawHeader: []byte("HTTP/1.1 500 Internal Server Error\r\n"),
					Body:      []byte("You have an error in your SQL syntax"),
					Latency:   183,
				},
			},
		},
	}

	ev := buildEvidence(r)
	if ev == nil {
		t.Fatal("expected evidence")
	}
	if !strings.HasPrefix(ev.ID, "evd_") {
		t.Fatalf("unexpected evidence id: %q", ev.ID)
	}
	if len(ev.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(ev.Steps))
	}
	if ev.Steps[0].Role != evidence.RoleProbe || ev.Steps[1].Role != evidence.RoleConfirm {
		t.Fatalf("unexpected roles: %+v", []evidence.Role{ev.Steps[0].Role, ev.Steps[1].Role})
	}
	if !ev.Steps[1].Matched {
		t.Fatal("confirm step must be marked matched")
	}
	if got := ev.Steps[1].Extracted["proof"]; got != "SQL syntax error" {
		t.Fatalf("extracted proof = %q", got)
	}
	if ev.Steps[1].Request.Method != "GET" || ev.Steps[1].Request.URL == "" {
		t.Fatalf("unexpected request: %+v", ev.Steps[1].Request)
	}
	if ev.Steps[1].Response.Status != 500 || ev.Steps[1].Response.LatencyMs != 183 {
		t.Fatalf("unexpected response: %+v", ev.Steps[1].Response)
	}
	if !strings.Contains(ev.Replay.Command, "test-poc") || !strings.Contains(ev.Replay.Command, "afrog verify") {
		t.Fatalf("unexpected replay command: %q", ev.Replay.Command)
	}
	if ev.Confidence != string(evidence.Certain) {
		t.Fatalf("unexpected confidence: %q", ev.Confidence)
	}
}

func TestBuildEvidenceWithoutSteps(t *testing.T) {
	if ev := buildEvidence(&result.Result{PocInfo: &poc.Poc{Id: "x"}}); ev != nil {
		t.Fatalf("expected nil evidence, got %+v", ev)
	}
	if ev := buildEvidence(nil); ev != nil {
		t.Fatalf("expected nil evidence for nil result, got %+v", ev)
	}
}

// 同一次判定重复组装必须得到同一个证据 ID：这是 Agent 重试与幂等落库的前提。
func TestBuildEvidenceIsIdempotent(t *testing.T) {
	r := &result.Result{
		FullTarget: "https://example.com/a",
		PocInfo:    &poc.Poc{Id: "test-poc"},
		AllPocResult: []*result.PocResult{{
			IsVul:          true,
			ResultRequest:  &proto.Request{Method: "GET", RawHeader: []byte("GET / HTTP/1.1\r\n")},
			ResultResponse: &proto.Response{Status: 200, Body: []byte("a")},
		}},
	}
	first := buildEvidence(r)
	r.AllPocResult[0].ResultResponse.Body = []byte("response body changes every run")
	r.AllPocResult[0].ResultResponse.Latency = 999
	second := buildEvidence(r)
	if first == nil || second == nil {
		t.Fatal("expected evidence")
	}
	if first.ID != second.ID {
		t.Fatalf("evidence id must be stable: %q != %q", first.ID, second.ID)
	}
}

func TestClampTextKeepsUTF8Boundary(t *testing.T) {
	s := strings.Repeat("中", 10) // 30 字节
	got := clampText(s, 5)       // 5 落在第二个字符中间，必须回退到 3
	if !utf8.ValidString(got) {
		t.Fatalf("clamped text is not valid utf-8: %q", got)
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("missing truncation marker: %q", got)
	}
	if clampText("short", 5) != "short" {
		t.Fatal("text within limit must be unchanged")
	}
}
