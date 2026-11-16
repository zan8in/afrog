package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/drafter"
)

// 候选 PoC 的主链路：草稿 → 受限实跑取证据 → 进入待人工终审队列（pending），
// 但绝不自动入库——是否写进 pocs-my 仍由 `afrog poc approve` 决定。
func TestPocSubmitToolStagesVerifiedCandidate(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + verifyHitMarker + "</html>"))
	}))
	t.Cleanup(target.Close)

	s := newSubprocessServer(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	out, err := s.tools["poc.submit"].Handler(context.Background(), mustJSON(t, map[string]any{
		"poc_path": writeHitPoc(t),
		"target":   target.URL,
	}))
	if err != nil {
		t.Fatalf("poc.submit: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if res["submitted"] != true {
		t.Fatalf("submitted = %v (res=%+v)", res["submitted"], res)
	}

	pending, err := drafter.List(sqlite.PocDraftPending)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %+v, want 1", pending)
	}
	if pending[0].ID != "mcp-verify-hit" || pending[0].EvidenceID == "" {
		t.Fatalf("draft = %+v, want id + evidence", pending[0])
	}
	if pending[0].Target != target.URL {
		t.Fatalf("target = %q, want %q", pending[0].Target, target.URL)
	}
}

// 拿不到证据的候选不配进终审：实跑没复现时 submitted=false，且队列保持为空。
func TestPocSubmitToolRejectsCandidateWithoutEvidence(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>nothing to see</html>"))
	}))
	t.Cleanup(target.Close)

	s := newSubprocessServer(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	out, err := s.tools["poc.submit"].Handler(context.Background(), mustJSON(t, map[string]any{
		"poc_path": writeHitPoc(t),
		"target":   target.URL,
	}))
	if err != nil {
		t.Fatalf("poc.submit: %v", err)
	}
	res := out.(map[string]any)
	if res["submitted"] != false {
		t.Fatalf("submitted = %v, want false", res["submitted"])
	}

	pending, err := drafter.List("")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("queue must stay empty, got %+v", pending)
	}
}

// 只读模式下 poc.submit 会发包，必须被策略拒绝，且拒绝不扣预算。
func TestPocSubmitToolDeniedByReadOnlyPolicy(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")

	args, err := json.Marshal(map[string]any{"poc_path": writeHitPoc(t), "target": "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	if _, err := s.tools["poc.submit"].Handler(context.Background(), args); err == nil {
		t.Fatal("poc.submit must be denied in readonly mode")
	}
}
