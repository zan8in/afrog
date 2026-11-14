package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
)

func TestReplayMatchesUsesContentAddress(t *testing.T) {
	base := &evidence.Evidence{ID: "evd_a", Digest: "sha256:a"}

	same := &evidence.Evidence{ID: "evd_a", Digest: "sha256:a"}
	if !replayMatches(base, same) {
		t.Fatal("identical evidence must match")
	}
	if replayMatches(base, nil) {
		t.Fatal("missing replay result must not match")
	}
	if replayMatches(base, &evidence.Evidence{ID: "evd_b", Digest: "sha256:a"}) {
		t.Fatal("different id must not match")
	}
	if replayMatches(base, &evidence.Evidence{ID: "evd_a", Digest: "sha256:b"}) {
		t.Fatal("different digest must not match")
	}

	if got := replayReason(false, false); !strings.Contains(got, "did not reproduce") {
		t.Fatalf("reason for missed replay = %q", got)
	}
	if got := replayReason(true, false); !strings.Contains(got, "changed") {
		t.Fatalf("reason for changed evidence = %q", got)
	}
	if got := replayReason(true, true); got != "" {
		t.Fatalf("consistent replay should not carry a reason, got %q", got)
	}
}

// 完整链路：草稿落盘 → verify.poc 产出证据 → 落库 → verify.replay 只凭证据 id 复核。
// 这里同时验证了「按 poc_id 从 drafts 目录回查 PoC」，否则草稿来源的证据无法重放。
func TestVerifyReplayToolMatchesStoredEvidence(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + verifyHitMarker + "</html>"))
	}))
	t.Cleanup(target.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n")
	if err := db2.NewSnowFlake(); err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	// 1. 模型草稿落盘，后面 verify.replay 只能靠 poc_id 找回它。
	draftYAML, err := os.ReadFile(writeHitPoc(t))
	if err != nil {
		t.Fatalf("read poc: %v", err)
	}
	saved, err := s.tools["poc.draft"].Handler(context.Background(), mustJSON(t, map[string]any{
		"yaml": string(draftYAML),
		"save": true,
	}))
	if err != nil {
		t.Fatalf("poc.draft: %v", err)
	}
	draftPath, _ := saved.(map[string]any)["poc_path"].(string)
	if draftPath == "" {
		t.Fatalf("poc.draft returned no path: %+v", saved)
	}

	// 2. 验证一次，拿到真实证据。
	verified, err := s.tools["verify.poc"].Handler(context.Background(), mustJSON(t, map[string]any{
		"poc_path": draftPath,
		"target":   target.URL,
	}))
	if err != nil {
		t.Fatalf("verify.poc: %v", err)
	}
	ev := firstEvidence(verified.(map[string]any)["results"].([]map[string]any))
	if ev == nil {
		t.Fatal("verify.poc produced no evidence")
	}
	if err := sqlite.InsertEvidence(ev, 9001, "task-replay"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	// 3. 重放：只给证据 id，target 与 PoC 都由证据带出。
	res, err := s.tools["verify.replay"].Handler(context.Background(), mustJSON(t, map[string]any{"id": ev.ID}))
	if err != nil {
		t.Fatalf("verify.replay: %v", err)
	}
	replayed := res.(map[string]any)
	if replayed["replayed"] != true || replayed["consistent"] != true {
		t.Fatalf("replay = %+v, want reproduced and consistent", replayed)
	}
	actual, ok := replayed["evidence"].(*evidence.Evidence)
	if !ok || actual.ID != ev.ID || actual.Digest != ev.Digest {
		t.Fatalf("replayed evidence = %+v, want %s/%s", actual, ev.ID, ev.Digest)
	}
	if _, hasReason := replayed["reason"]; hasReason {
		t.Fatalf("consistent replay should not carry a reason: %+v", replayed)
	}

	// 4. 旧证据（目标行为已变）必须被标记为不一致，而不是继续当成事实。
	stale := &evidence.Evidence{
		ID:         "evd_stale",
		Digest:     "sha256:stale",
		PocID:      ev.PocID,
		Target:     ev.Target,
		Confidence: ev.Confidence,
		Steps:      ev.Steps,
	}
	if err := sqlite.InsertEvidence(stale, 9002, "task-replay"); err != nil {
		t.Fatalf("insert stale: %v", err)
	}
	out, err := s.tools["verify.replay"].Handler(context.Background(), mustJSON(t, map[string]any{"id": stale.ID}))
	if err != nil {
		t.Fatalf("verify.replay(stale): %v", err)
	}
	mismatch := out.(map[string]any)
	if mismatch["replayed"] != true || mismatch["consistent"] != false {
		t.Fatalf("stale replay = %+v, want reproduced but inconsistent", mismatch)
	}
	if reason, _ := mismatch["reason"].(string); reason == "" {
		t.Fatalf("inconsistent replay must explain why: %+v", mismatch)
	}
}

func TestVerifyReplayToolRejectsUnknownEvidence(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	_, err := s.tools["verify.replay"].Handler(context.Background(), mustJSON(t, map[string]any{"id": "evd_missing"}))
	if err == nil || !strings.Contains(err.Error(), "evidence not found") {
		t.Fatalf("err = %v, want evidence not found", err)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
