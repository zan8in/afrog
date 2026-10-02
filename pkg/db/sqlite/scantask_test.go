package sqlite

import (
	"fmt"
	"testing"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
)

// withScanTaskFixture 在临时库上建表并接管 dbx，避免依赖开发者本机的 afrog.db。
func withScanTaskFixture(t *testing.T) {
	t.Helper()
	db := newExportFixture(t)
	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
}

func sampleScanTask(taskID, createdAt string) db2.ScanTaskRow {
	return db2.ScanTaskRow{
		TaskID:       taskID,
		Name:         "客户A每日巡检",
		Status:       "completed",
		Source:       "schedule",
		ScheduleID:   "s_1",
		ProjectID:    "p_1",
		Targets:      []string{"http://a.example", "http://b.example"},
		Hits:         map[string]int{"high": 2, "info": 1},
		HitTotal:     3,
		Percent:      100,
		Finished:     50,
		Total:        50,
		ElapsedMs:    12345,
		TotalTargets: 2,
		TotalPocs:    300,
		TotalScans:   600,
		OOBEnabled:   true,
		OOBStatus:    "running",
		Error:        "",
		CreatedAt:    createdAt,
		StartedAt:    createdAt,
		EndedAt:      createdAt,
	}
}

func TestScanTaskRoundTrip(t *testing.T) {
	withScanTaskFixture(t)

	want := sampleScanTask("t-1", "2026-09-30 10:00:00")
	if err := UpsertScanTask(want); err != nil {
		t.Fatalf("UpsertScanTask: %v", err)
	}

	got, err := SelectScanTask("t-1")
	if err != nil {
		t.Fatalf("SelectScanTask: %v", err)
	}
	if got == nil {
		t.Fatal("SelectScanTask returned nil for an existing task")
	}
	if got.Name != want.Name || got.Status != want.Status || got.Source != want.Source {
		t.Fatalf("identity fields mismatch: %+v", got)
	}
	if got.ScheduleID != "s_1" || got.ProjectID != "p_1" {
		t.Fatalf("ownership fields mismatch: %+v", got)
	}
	if len(got.Targets) != 2 || got.Targets[0] != "http://a.example" {
		t.Fatalf("targets mismatch: %+v", got.Targets)
	}
	if got.Hits["high"] != 2 || got.Hits["info"] != 1 || got.HitTotal != 3 {
		t.Fatalf("hits mismatch: %+v", got)
	}
	if got.TotalPocs != 300 || got.TotalTargets != 2 || got.TotalScans != 600 {
		t.Fatalf("scan info mismatch: %+v", got)
	}
	if !got.OOBEnabled || got.OOBStatus != "running" {
		t.Fatalf("oob fields mismatch: %+v", got)
	}
}

func TestScanTaskUpsertOverwrites(t *testing.T) {
	withScanTaskFixture(t)

	rec := sampleScanTask("t-1", "2026-09-30 10:00:00")
	rec.Status = "running"
	rec.HitTotal = 0
	if err := UpsertScanTask(rec); err != nil {
		t.Fatalf("UpsertScanTask(running): %v", err)
	}

	// 收尾时用同一 taskid 再写一次终态，读到的应是最后一次。
	rec.Status = "completed"
	rec.HitTotal = 5
	if err := UpsertScanTask(rec); err != nil {
		t.Fatalf("UpsertScanTask(completed): %v", err)
	}

	got, err := SelectScanTask("t-1")
	if err != nil {
		t.Fatalf("SelectScanTask: %v", err)
	}
	if got == nil || got.Status != "completed" || got.HitTotal != 5 {
		t.Fatalf("expected the last write to win, got %+v", got)
	}
}

func TestSelectScanTasksOrdersNewestFirst(t *testing.T) {
	withScanTaskFixture(t)

	for _, item := range []struct{ id, at string }{
		{"t-old", "2026-09-28 09:00:00"},
		{"t-new", "2026-09-30 09:00:00"},
		{"t-mid", "2026-09-29 09:00:00"},
	} {
		if err := UpsertScanTask(sampleScanTask(item.id, item.at)); err != nil {
			t.Fatalf("UpsertScanTask(%s): %v", item.id, err)
		}
	}

	rows, err := SelectScanTasks(0)
	if err != nil {
		t.Fatalf("SelectScanTasks: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	want := []string{"t-new", "t-mid", "t-old"}
	for i, id := range want {
		if rows[i].TaskID != id {
			t.Fatalf("row %d = %s, want %s", i, rows[i].TaskID, id)
		}
	}
}

func TestSelectScanTaskMissingReturnsNil(t *testing.T) {
	withScanTaskFixture(t)

	got, err := SelectScanTask("nope")
	if err != nil {
		t.Fatalf("SelectScanTask: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for a missing task, got %+v", got)
	}
}

func TestUpsertScanTaskPrunesOldRows(t *testing.T) {
	withScanTaskFixture(t)

	// 造出超过上限的历史：created_at 按序号递增，最早的应被淘汰。
	total := maxScanTaskHistory + 5
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("t-%04d", i)
		at := fmt.Sprintf("2026-01-01 %02d:%02d:00", i/60, i%60)
		if err := UpsertScanTask(sampleScanTask(id, at)); err != nil {
			t.Fatalf("UpsertScanTask(%s): %v", id, err)
		}
	}

	rows, err := SelectScanTasks(0)
	if err != nil {
		t.Fatalf("SelectScanTasks: %v", err)
	}
	if len(rows) != maxScanTaskHistory {
		t.Fatalf("expected %d rows after prune, got %d", maxScanTaskHistory, len(rows))
	}

	oldest := fmt.Sprintf("t-%04d", 0)
	got, err := SelectScanTask(oldest)
	if err != nil {
		t.Fatalf("SelectScanTask(%s): %v", oldest, err)
	}
	if got != nil {
		t.Fatalf("expected the oldest row to be pruned, got %+v", got)
	}

	newest := fmt.Sprintf("t-%04d", total-1)
	if _, err := SelectScanTask(newest); err != nil {
		t.Fatalf("SelectScanTask(%s): %v", newest, err)
	}
}
