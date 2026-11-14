package sqlite

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/evidence"
)

func sampleEvidence() *evidence.Evidence {
	ev := &evidence.Evidence{
		ID:         "evd_test",
		PocID:      "poc-test",
		Target:     "https://example.com/a",
		Digest:     "sha256:abc",
		Confidence: "certain",
		Created:    "2026-11-14T10:00:00Z",
		Steps: []evidence.Step{{
			Role:    evidence.RoleConfirm,
			Matched: true,
		}},
	}
	return ev
}

func TestInsertEvidenceIsIdempotent(t *testing.T) {
	useFixtureDB(t)
	ev := sampleEvidence()

	if err := InsertEvidence(ev, 42, "task-1"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := InsertEvidence(ev, 42, "task-1"); err != nil {
		t.Fatalf("second insert: %v", err)
	}

	got, err := SelectEvidenceByResultID(42)
	if err != nil {
		t.Fatalf("select by result: %v", err)
	}
	if got == nil || got.ID != ev.ID || got.PocID != ev.PocID {
		t.Fatalf("unexpected evidence: %+v", got)
	}
	if len(got.Steps) != 1 || got.Steps[0].Role != evidence.RoleConfirm {
		t.Fatalf("evidence steps not round-tripped: %+v", got.Steps)
	}

	if got, err := SelectEvidenceByID(ev.ID); err != nil || got == nil {
		t.Fatalf("select by id: ev=%+v err=%v", got, err)
	}
}

// 跨任务不去重：同一条证据在不同任务里各存一份，查询按任务各自可见。
func TestInsertEvidenceKeepsPerTaskCopies(t *testing.T) {
	useFixtureDB(t)
	ev := sampleEvidence()

	if err := InsertEvidence(ev, 42, "task-1"); err != nil {
		t.Fatalf("insert task-1: %v", err)
	}
	if err := InsertEvidence(ev, 43, "task-2"); err != nil {
		t.Fatalf("insert task-2: %v", err)
	}

	for _, tc := range []struct {
		resultID int64
		taskID   string
	}{{42, "task-1"}, {43, "task-2"}} {
		var n int
		if err := dbx.Get(&n, `SELECT COUNT(*) FROM "evidence" WHERE "result_id" = ? AND "taskid" = ?`, tc.resultID, tc.taskID); err != nil {
			t.Fatalf("count evidence: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected 1 evidence for %v, got %d", tc, n)
		}
	}
}

func TestSelectEvidenceMissingReturnsNil(t *testing.T) {
	useFixtureDB(t)
	got, err := SelectEvidenceByResultID(9999)
	if err != nil {
		t.Fatalf("select missing: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil evidence, got %+v", got)
	}
}

// 集群回填：快照要带出证据，落库后新主键与证据一一对应，删任务时一起清掉。
func TestRawResultsCarryEvidenceAcrossBackfill(t *testing.T) {
	useFixtureDB(t)

	insertResult(t, dbx, 1001, "node-task", "poc-x", "http://x.example", "http://x.example/a", "high", "2026-11-14 10:00:00")
	ev := sampleEvidence()
	if err := InsertEvidence(ev, 1001, "node-task"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	rows, err := SelectRawResultsByTask("node-task", 10)
	if err != nil {
		t.Fatalf("select raw results: %v", err)
	}
	if len(rows) != 1 || rows[0].Evidence == nil || rows[0].Evidence.ID != ev.ID {
		t.Fatalf("evidence not attached to snapshot: %+v", rows)
	}

	n, err := InsertRawResults("shadow-task", "node-a", rows)
	if err != nil || n != 1 {
		t.Fatalf("insert raw results = %d, %v", n, err)
	}

	var newID int64
	if err := dbx.Get(&newID, `SELECT "id" FROM "result" WHERE "taskid" = 'shadow-task'`); err != nil {
		t.Fatalf("read new result id: %v", err)
	}
	if newID == 1001 {
		t.Fatal("backfill must assign a new local primary key")
	}

	got, err := SelectEvidenceByResultID(newID)
	if err != nil || got == nil || got.PocID != ev.PocID {
		t.Fatalf("evidence not backfilled: ev=%+v err=%v", got, err)
	}

	var cnt int
	if err := dbx.Get(&cnt, `SELECT COUNT(*) FROM "evidence" WHERE "taskid" = 'shadow-task'`); err != nil {
		t.Fatalf("count evidence: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("evidence rows = %d, want 1", cnt)
	}

	if _, err := DeleteResultsByTask("shadow-task"); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	if err := dbx.Get(&cnt, `SELECT COUNT(*) FROM "evidence" WHERE "taskid" = 'shadow-task'`); err != nil {
		t.Fatalf("count evidence after delete: %v", err)
	}
	if cnt != 0 {
		t.Fatalf("evidence not cleaned with task: %d", cnt)
	}
}

// 台账列表要直接带出最新命中的 result_id 与 evidence_id，
// 这样 Agent 的「先看命中、再取证据」不需要额外猜 id。
func TestLedgerPageCarriesEvidenceID(t *testing.T) {
	useFixtureDB(t)

	insertResult(t, dbx, 3001, "task-led", "poc-z", "http://z.example", "http://z.example/a", "high", "2026-11-14 10:00:00")
	ev := sampleEvidence()
	if err := InsertEvidence(ev, 3001, "task-led"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	page, err := SelectLedgerPage(LedgerFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("select ledger page: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 ledger row, got %d", len(page.Items))
	}
	got := page.Items[0]
	if got.ResultID != 3001 {
		t.Fatalf("result_id = %d, want 3001", got.ResultID)
	}
	if got.EvidenceID != ev.ID {
		t.Fatalf("evidence_id = %q, want %q", got.EvidenceID, ev.ID)
	}
}

func TestLedgerPageWithoutEvidence(t *testing.T) {
	useFixtureDB(t)

	insertResult(t, dbx, 3002, "task-led2", "poc-w", "http://w.example", "http://w.example/a", "low", "2026-11-14 10:00:00")
	page, err := SelectLedgerPage(LedgerFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("select ledger page: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 ledger row, got %d", len(page.Items))
	}
	if page.Items[0].EvidenceID != "" {
		t.Fatalf("evidence_id = %q, want empty", page.Items[0].EvidenceID)
	}
}

func TestDeleteResultsByIDsCleansEvidence(t *testing.T) {
	useFixtureDB(t)

	insertResult(t, dbx, 2001, "task-del", "poc-y", "http://y.example", "http://y.example/a", "low", "2026-11-14 10:00:00")
	if err := InsertEvidence(sampleEvidence(), 2001, "task-del"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	if _, err := DeleteResultsByIDs([]int64{2001}); err != nil {
		t.Fatalf("delete by ids: %v", err)
	}
	got, err := SelectEvidenceByResultID(2001)
	if err != nil {
		t.Fatalf("select evidence: %v", err)
	}
	if got != nil {
		t.Fatalf("evidence must be removed with result: %+v", got)
	}
}
