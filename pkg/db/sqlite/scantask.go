package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
)

// -----------------------
// 扫描任务元数据（重启后可查）
// -----------------------
//
// 任务的实时状态活在服务进程内存里（pkg/web 的 TaskManager），属进程内存态；
// 这里只落一份「快照」，让服务重启后计划扫描的「上次执行」仍能被打开查看。
// 命中明细刻意不落本表：result 表已按 taskid 关联，两处都存只会带来不一致。

const scanTaskDDL = `CREATE TABLE IF NOT EXISTS "scan_task" (
	"taskid" TEXT PRIMARY KEY,
	"name" TEXT NOT NULL DEFAULT '',
	"status" TEXT NOT NULL DEFAULT '',
	"source" TEXT NOT NULL DEFAULT '',
	"schedule_id" TEXT NOT NULL DEFAULT '',
	"project_id" TEXT NOT NULL DEFAULT '',
	"targets" TEXT NOT NULL DEFAULT '[]',
	"hits" TEXT NOT NULL DEFAULT '{}',
	"hit_total" INTEGER NOT NULL DEFAULT 0,
	"percent" INTEGER NOT NULL DEFAULT 0,
	"finished" INTEGER NOT NULL DEFAULT 0,
	"total" INTEGER NOT NULL DEFAULT 0,
	"elapsed_ms" INTEGER NOT NULL DEFAULT 0,
	"total_targets" INTEGER NOT NULL DEFAULT 0,
	"total_pocs" INTEGER NOT NULL DEFAULT 0,
	"total_scans" INTEGER NOT NULL DEFAULT 0,
	"oob_enabled" INTEGER NOT NULL DEFAULT 0,
	"oob_status" TEXT NOT NULL DEFAULT '',
	"error" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT '',
	"started_at" TEXT NOT NULL DEFAULT '',
	"ended_at" TEXT NOT NULL DEFAULT '',
	"updated_at" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_scan_task_created"
	ON "scan_task" ("created_at");
  CREATE INDEX IF NOT EXISTS "idx_scan_task_schedule"
	ON "scan_task" ("schedule_id");`

// maxScanTaskHistory 是保留的任务快照条数：快照只为「界面能看到最近跑过什么」，
// 不是审计账本（那是 result 表），超出后按创建时间淘汰最旧的，避免库无限增长。
const maxScanTaskHistory = 200

const scanTaskTimeLayout = "2006-01-02 15:04:05"

// UpsertScanTask 写入或更新一次扫描的任务快照。
func UpsertScanTask(rec db2.ScanTaskRow) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	rec.TaskID = strings.TrimSpace(rec.TaskID)
	if rec.TaskID == "" {
		return fmt.Errorf("task id is required")
	}

	targetsRaw, err := json.Marshal(nonNilStrings(rec.Targets))
	if err != nil {
		return err
	}
	hits := rec.Hits
	if hits == nil {
		hits = map[string]int{}
	}
	hitsRaw, err := json.Marshal(hits)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dbx.ExecContext(ctx, `INSERT OR REPLACE INTO scan_task(
		taskid, name, status, source, schedule_id, project_id,
		targets, hits, hit_total, percent, finished, total, elapsed_ms,
		total_targets, total_pocs, total_scans, oob_enabled, oob_status,
		error, created_at, started_at, ended_at, updated_at
	  ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.TaskID, rec.Name, rec.Status, rec.Source, rec.ScheduleID, rec.ProjectID,
		string(targetsRaw), string(hitsRaw), rec.HitTotal, rec.Percent, rec.Finished, rec.Total, rec.ElapsedMs,
		rec.TotalTargets, rec.TotalPocs, rec.TotalScans, boolToInt(rec.OOBEnabled), rec.OOBStatus,
		rec.Error, rec.CreatedAt, rec.StartedAt, rec.EndedAt, time.Now().Format(scanTaskTimeLayout))
	if err != nil {
		return err
	}

	return pruneScanTasks(ctx)
}

// pruneScanTasks 保留最近 maxScanTaskHistory 条快照。
func pruneScanTasks(ctx context.Context) error {
	_, err := dbx.ExecContext(ctx,
		`DELETE FROM scan_task WHERE taskid NOT IN (
		   SELECT taskid FROM scan_task ORDER BY created_at DESC, rowid DESC LIMIT ?
		 )`, maxScanTaskHistory)
	return err
}

// SelectScanTasks 按创建时间倒序返回任务快照（新的在前）。
func SelectScanTasks(limit int) ([]db2.ScanTaskRow, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = maxScanTaskHistory
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows := make([]db2.ScanTaskRow, 0, 64)
	if err := dbx.SelectContext(ctx, &rows, `SELECT * FROM scan_task
		 ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit); err != nil {
		return nil, err
	}
	for i := range rows {
		decodeScanTaskRow(&rows[i])
	}
	return rows, nil
}

// SelectScanTask 返回单个任务快照；不存在时返回 nil, nil。
func SelectScanTask(taskID string) (*db2.ScanTaskRow, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var row db2.ScanTaskRow
	err := dbx.GetContext(ctx, &row, `SELECT * FROM scan_task WHERE taskid = ?`, taskID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decodeScanTaskRow(&row)
	return &row, nil
}

// decodeScanTaskRow 把存储格式还原成对外字段。解析失败时留空值：
// 一条快照的字段损坏不该让整个任务列表接口报错。
func decodeScanTaskRow(row *db2.ScanTaskRow) {
	row.Targets = []string{}
	if strings.TrimSpace(row.TargetsRaw) != "" {
		_ = json.Unmarshal([]byte(row.TargetsRaw), &row.Targets)
	}
	row.Hits = map[string]int{}
	if strings.TrimSpace(row.HitsRaw) != "" {
		_ = json.Unmarshal([]byte(row.HitsRaw), &row.Hits)
	}
}

// nonNilStrings 保证 JSON 落库是 [] 而不是 null，前端按数组使用不会崩。
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
