package sqlite

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jmoiron/sqlx"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
)

// newExportFixture 在临时目录建一个与实际结构一致的 sqlite，
// 避免测试依赖开发者本机的 ~/.config/afrog/afrog.db。
func newExportFixture(t *testing.T) *sqlx.DB {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "afrog.db") + "?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000"
	db, err := sqlx.Connect("sqlite3", dsn)
	if err != nil {
		t.Fatalf("connect fixture db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, ddl := range []string{db2.SqliteCreate, ledgerDDL, assetDDL, scanTaskDDL, aiDDL} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}
	return db
}

func insertResult(t *testing.T, db *sqlx.DB, id int, taskID, vulid, target, fulltarget, severity, created string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor)
		 VALUES(?, ?, ?, ?, ?, ?, ?, '', '', ?, '', '')`,
		id, taskID, vulid, "name-"+vulid, target, fulltarget, severity, created)
	if err != nil {
		t.Fatalf("insert result: %v", err)
	}
}

// seed 覆盖两个项目、三个任务，以及一个未归属项目的任务。
func seed(t *testing.T, db *sqlx.DB) {
	t.Helper()

	insertResult(t, db, 1, "t-1", "poc-a", "http://a.example", "http://a.example/1", "high", "2026-09-28 10:00:00")
	insertResult(t, db, 2, "t-1", "poc-b", "http://a.example", "http://a.example/2", "low", "2026-09-28 10:01:00")
	insertResult(t, db, 3, "t-2", "poc-a", "http://a.example", "http://a.example/1", "high", "2026-09-28 11:00:00")
	insertResult(t, db, 4, "t-3", "poc-c", "http://b.example", "http://b.example", "medium", "2026-09-28 12:00:00")
	// 未归属项目的任务：不应出现在任何项目导出里
	insertResult(t, db, 5, "t-orphan", "poc-d", "http://c.example", "http://c.example", "critical", "2026-09-28 13:00:00")

	// created_at 依次递增，让「按创建时间排序」有确定的预期结果；
	// 用 map 迭代写入会因时间戳相同而依赖 rowid，导致断言不稳定。
	links := []struct {
		taskID    string
		projectID string
		createdAt string
	}{
		{"t-1", "p-alpha", "2026-09-28 10:00:00"},
		{"t-2", "p-alpha", "2026-09-28 11:00:00"},
		{"t-3", "p-beta", "2026-09-28 12:00:00"},
	}
	for _, l := range links {
		if _, err := db.Exec(
			`INSERT INTO task_project(taskid, project_id, created_at) VALUES(?, ?, ?)`,
			l.taskID, l.projectID, l.createdAt); err != nil {
			t.Fatalf("insert task_project: %v", err)
		}
	}
}

func withFixture(t *testing.T) *sqlx.DB {
	t.Helper()
	db := newExportFixture(t)
	seed(t, db)

	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
	return db
}

func TestSelectAllByTaskReturnsWholeTask(t *testing.T) {
	withFixture(t)

	rows, err := SelectAllByTask("t-1", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllByTask: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	// severity 由查询层统一转大写
	for _, r := range rows {
		if r.Severity != "HIGH" && r.Severity != "LOW" {
			t.Fatalf("severity not normalized: %q", r.Severity)
		}
	}

	filtered, err := SelectAllByTask("t-1", "high", false, false)
	if err != nil {
		t.Fatalf("SelectAllByTask(high): %v", err)
	}
	if len(filtered) != 1 || filtered[0].VulID != "poc-a" {
		t.Fatalf("severity filter failed: %+v", filtered)
	}

	if _, err := SelectAllByTask("  ", "", false, false); err == nil {
		t.Fatal("empty task id should be rejected")
	}
}

func TestSelectAllFilteredSpansTasks(t *testing.T) {
	withFixture(t)

	rows, err := SelectAllFiltered("high", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllFiltered: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("high rows = %d, want 2 (t-1 and t-2)", len(rows))
	}

	rows, err = SelectAllFiltered("", "poc-c", false, false)
	if err != nil {
		t.Fatalf("SelectAllFiltered(keyword): %v", err)
	}
	if len(rows) != 1 || rows[0].TaskID != "t-3" {
		t.Fatalf("keyword filter failed: %+v", rows)
	}
}

// TestSelectAllByProjectJoinsTaskProject 是本功能风险最高的一段 SQL：
// 必须按任务归属聚合，且不能把未归属项目的任务混进来。
func TestSelectAllByProjectJoinsTaskProject(t *testing.T) {
	withFixture(t)

	alpha, err := SelectAllByProject("p-alpha", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllByProject: %v", err)
	}
	if len(alpha) != 3 {
		t.Fatalf("p-alpha rows = %d, want 3 (t-1 两条 + t-2 一条)", len(alpha))
	}
	for _, r := range alpha {
		if r.TaskID != "t-1" && r.TaskID != "t-2" {
			t.Fatalf("unexpected task in project export: %q", r.TaskID)
		}
	}

	beta, err := SelectAllByProject("p-beta", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllByProject(beta): %v", err)
	}
	if len(beta) != 1 || beta[0].VulID != "poc-c" {
		t.Fatalf("p-beta rows = %+v", beta)
	}

	// t-orphan 未归属项目，不应出现在任何项目报告中
	for _, r := range append(alpha, beta...) {
		if r.VulID == "poc-d" {
			t.Fatal("orphan task leaked into a project export")
		}
	}

	empty, err := SelectAllByProject("p-missing", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllByProject(missing): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("missing project rows = %d, want 0", len(empty))
	}

	if _, err := SelectAllByProject("", "", false, false); err == nil {
		t.Fatal("empty project id should be rejected")
	}
}

func TestSelectAllByProjectAppliesSeverityFilter(t *testing.T) {
	withFixture(t)

	rows, err := SelectAllByProject("p-alpha", "low", false, false)
	if err != nil {
		t.Fatalf("SelectAllByProject(low): %v", err)
	}
	if len(rows) != 1 || rows[0].TaskID != "t-1" {
		t.Fatalf("severity filter on project export failed: %+v", rows)
	}
}

func TestExportLimitIsCappedByQuery(t *testing.T) {
	db := withFixture(t)

	// 插入超过上限的行，确认查询不会把整表拉出来。
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	for i := 0; i < ExportRowLimit+50; i++ {
		if _, err := tx.Exec(
			`INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor)
			 VALUES(?, ?, ?, ?, ?, ?, ?, '', '', ?, '', '')`,
			1000+i, "t-bulk", "poc-bulk", "name-poc-bulk",
			"http://bulk.example", fmt.Sprintf("http://bulk.example/%d", i),
			"info", "2026-09-28 14:00:00"); err != nil {
			t.Fatalf("bulk insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	rows, err := SelectAllByTask("t-bulk", "", false, false)
	if err != nil {
		t.Fatalf("SelectAllByTask(bulk): %v", err)
	}
	if len(rows) != ExportRowLimit {
		t.Fatalf("bulk rows = %d, want %d", len(rows), ExportRowLimit)
	}
}

func TestSelectProjectTaskIDsIsOrdered(t *testing.T) {
	withFixture(t)

	ids, err := SelectProjectTaskIDs("p-alpha")
	if err != nil {
		t.Fatalf("SelectProjectTaskIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != "t-1" || ids[1] != "t-2" {
		t.Fatalf("task ids = %v, want [t-1 t-2]", ids)
	}

	empty, err := SelectProjectTaskIDs("")
	if err != nil || empty != nil {
		t.Fatalf("empty project id should return nil,nil; got %v,%v", empty, err)
	}
}
