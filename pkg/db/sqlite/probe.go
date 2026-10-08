package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 扫描过程中的「资产发现」明细（端口 / Web 探测）。
//
// 与 scan_task 的分工一致：命中明细只认 result 表，而端口与 Web 探测在扫描时只存在于
// 事件流里，服务重启或换浏览器后就没了，详情页会「资产发现有值、列表却为空」。
// 这里把它们按 taskid 落库，让历史任务也能回看；保留策略与 scan_task 快照一致
// （见 pruneScanTasks），避免随扫描次数无限增长。
//
// data 存原始事件 JSON：前端在线渲染与离线回看用的是同一份结构，无需两套字段映射。
const probeDDL = `CREATE TABLE IF NOT EXISTS "scan_probe" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"taskid" TEXT NOT NULL DEFAULT '',
	"kind" TEXT NOT NULL DEFAULT '',
	"ts" INTEGER NOT NULL DEFAULT 0,
	"target" TEXT NOT NULL DEFAULT '',
	"port" INTEGER NOT NULL DEFAULT 0,
	"status" INTEGER NOT NULL DEFAULT 0,
	"title" TEXT NOT NULL DEFAULT '',
	"data" TEXT NOT NULL DEFAULT '{}',
	"created" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_scan_probe_task"
	ON "scan_probe" ("taskid", "id");`

// ProbeEvent 是一条资产发现记录。
//
// Kind 取 "port"（端口）或 "webprobe"（Web 探测）。DataRaw 是存储形态，
// 对外走 Data；解码失败时退回空对象，一条坏记录不该让整个列表接口报错。
type ProbeEvent struct {
	ID      int64  `db:"id" json:"id"`
	TaskID  string `db:"taskid" json:"taskid"`
	Kind    string `db:"kind" json:"kind"`
	TS      int64  `db:"ts" json:"ts"`
	Target  string `db:"target" json:"target"`
	Port    int    `db:"port" json:"port"`
	Status  int    `db:"status" json:"status"`
	Title   string `db:"title" json:"title"`
	DataRaw string `db:"data" json:"-"`
	// Data 与前端在线收到的事件载荷同构，直接透传给界面（按 JSON 对象输出）。
	Data    json.RawMessage `db:"-" json:"data"`
	Created string          `db:"created" json:"created"`
}

// InsertProbeEvent 写入一条资产发现记录；失败由调用方决定是否忽略（不能影响扫描本身）。
func InsertProbeEvent(ev ProbeEvent) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	taskID := strings.TrimSpace(ev.TaskID)
	kind := strings.TrimSpace(ev.Kind)
	if taskID == "" || kind == "" {
		return fmt.Errorf("taskid and kind are required")
	}
	data := strings.TrimSpace(string(ev.Data))
	if data == "" {
		data = "{}"
	}
	created := strings.TrimSpace(ev.Created)
	if created == "" {
		created = time.Now().Format(scanTaskTimeLayout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx,
		`INSERT INTO scan_probe(taskid, kind, ts, target, port, status, title, data, created)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		taskID, kind, ev.TS, strings.TrimSpace(ev.Target), ev.Port, ev.Status, strings.TrimSpace(ev.Title), data, created)
	return err
}

// SelectProbeEvents 按写入顺序返回某任务的资产发现记录；kind 为空表示全部。
func SelectProbeEvents(taskID, kind string) ([]ProbeEvent, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("taskid is required")
	}

	query := `SELECT id, taskid, kind, ts, target, port, status, title, data, created
	  FROM scan_probe WHERE taskid = ?`
	args := []interface{}{taskID}
	if k := strings.TrimSpace(kind); k != "" {
		query += " AND kind = ?"
		args = append(args, k)
	}
	query += " ORDER BY id ASC"

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	rows := make([]ProbeEvent, 0, 64)
	if err := dbx.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, err
	}
	decodeProbeRows(rows)
	return rows, nil
}

// ProbeByID 返回指定 id 的资产发现记录，供「加入资产」按选中项取地址。
func ProbeByID(taskID string, ids []int64) ([]ProbeEvent, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" || len(ids) == 0 {
		return nil, nil
	}

	holders := make([]string, 0, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, taskID)
	for _, id := range ids {
		holders = append(holders, "?")
		args = append(args, id)
	}
	query := `SELECT id, taskid, kind, ts, target, port, status, title, data, created
	  FROM scan_probe WHERE taskid = ? AND id IN (` + strings.Join(holders, ",") + `)`

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	rows := make([]ProbeEvent, 0, len(ids))
	if err := dbx.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, err
	}
	decodeProbeRows(rows)
	return rows, nil
}

// decodeProbeRows 把存储形态的 data 还原成对外 JSON；空值或坏数据退回空对象。
func decodeProbeRows(rows []ProbeEvent) {
	for i := range rows {
		raw := strings.TrimSpace(rows[i].DataRaw)
		if raw == "" || !json.Valid([]byte(raw)) {
			raw = "{}"
		}
		rows[i].Data = json.RawMessage(raw)
	}
}
