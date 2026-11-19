package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	if got := replayReason(false, false, false); !strings.Contains(got, "did not reproduce") {
		t.Fatalf("reason for missed replay = %q", got)
	}
	if got := replayReason(true, false, false); !strings.Contains(got, "changed") {
		t.Fatalf("reason for changed evidence = %q", got)
	}
	if got := replayReason(true, false, true); !strings.Contains(got, "same behavior") {
		t.Fatalf("reason for behavior-consistent replay = %q", got)
	}
	if got := replayReason(true, true, true); got != "" {
		t.Fatalf("consistent replay should not carry a reason, got %q", got)
	}
}

// digest 包含抽取到的取值，重放时若响应里的易变值（会话号、token）不同，digest 会变，
// 但行为指纹（只保留抽取到的键）应当相等——这正是「同一行为、只是易变值不同」的判据。
func TestBehaviorDigestIgnoresExtractedValues(t *testing.T) {
	step := func(v string) evidence.Step {
		return evidence.Step{
			Role:      evidence.RoleConfirm,
			Matched:   true,
			Request:   evidence.Request{Method: "GET", URL: "http://h/a"},
			Response:  evidence.Response{Status: 200},
			Extracted: map[string]string{"session": v},
		}
	}
	a := &evidence.Evidence{PocID: "p", Target: "http://h", Steps: []evidence.Step{step("aaa")}}
	b := &evidence.Evidence{PocID: "p", Target: "http://h", Steps: []evidence.Step{step("bbb")}}

	if evidence.BehaviorDigest(a) != evidence.BehaviorDigest(b) {
		t.Fatalf("behavior digest must ignore extracted values: %s vs %s",
			evidence.BehaviorDigest(a), evidence.BehaviorDigest(b))
	}
	if evidence.BehaviorDigest(nil) != "" {
		t.Fatal("nil evidence must have an empty behavior digest")
	}
}

// 完整链路：PoC 落 pocs-my → scan.start 产出证据 → 落库 → verify.replay 只凭证据 id 复核。
// 重放时 verify.replay 会按证据里的 poc_id 从仓库回查 PoC，否则重放无法复现。
func TestVerifyReplayToolMatchesStoredEvidence(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + verifyHitMarker + "</html>"))
	}))
	t.Cleanup(target.Close)

	s := newSubprocessServer(t, "mode: safe\nbudget:\n  requests: 200\n  duration: 2m\n")
	if err := db2.NewSnowFlake(); err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	// 1. PoC 落 pocs-my：scan.start 的 -s 按 id 选中它，verify.replay 也按 id 回查它。
	installPoc(t, verifyHitID, hitPocYAML())

	scanned := runTool(t, s, "scan.start", map[string]any{"target": target.URL, "search": verifyHitID})
	items, _ := scanned.(map[string]any)["results"].([]map[string]any)
	ev := firstEvidence(items)
	if ev == nil {
		t.Fatalf("scan.start produced no evidence: %+v", scanned)
	}
	if err := sqlite.InsertEvidence(ev, 9001, "task-replay"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	// 2. 重放：只给证据 id，target 与 PoC 都由证据带出。
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

	// 3. 旧证据（目标行为已变）必须被标记为不一致，而不是继续当成事实。
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
