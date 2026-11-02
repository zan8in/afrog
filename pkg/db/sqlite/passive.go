package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 被动扫描的命中记录。
//
// 与 scan_probe 的分工：scan_probe 存「资产发现」（端口 / Web 探测），本表只存
// 「被动检测确认的漏洞」。按用户既定原则，只有 ConfidenceCertain 的结论才会
// 走到这里，因此本表不含低置信度的噪声数据。
//
// 流量本身不落库：被动扫描的原始事务只存在于内存中参与检测，落库的只有命中时
// 的那一对请求/响应，用于回溯与取证。
const passiveFindingDDL = `CREATE TABLE IF NOT EXISTS "passive_finding" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"fingerprint" TEXT NOT NULL DEFAULT '',
	"detector" TEXT NOT NULL DEFAULT '',
	"vuln_type" TEXT NOT NULL DEFAULT '',
	"severity" TEXT NOT NULL DEFAULT '',
	"confidence" TEXT NOT NULL DEFAULT '',
	"title" TEXT NOT NULL DEFAULT '',
	"target" TEXT NOT NULL DEFAULT '',
	"location" TEXT NOT NULL DEFAULT '',
	"payload" TEXT NOT NULL DEFAULT '',
	"evidence" TEXT NOT NULL DEFAULT '',
	"latency_ms" INTEGER NOT NULL DEFAULT 0,
	"traces" TEXT NOT NULL DEFAULT '[]',
	"request" TEXT NOT NULL DEFAULT '',
	"response" TEXT NOT NULL DEFAULT '',
	"extra" TEXT NOT NULL DEFAULT '{}',
	"created" TEXT NOT NULL DEFAULT '',
	"promoted" INTEGER NOT NULL DEFAULT 0,
	"result_id" TEXT NOT NULL DEFAULT ''
  );
  CREATE UNIQUE INDEX IF NOT EXISTS "idx_passive_finding_fp"
	ON "passive_finding" ("fingerprint");
  CREATE INDEX IF NOT EXISTS "idx_passive_finding_created"
	ON "passive_finding" ("created");
  CREATE INDEX IF NOT EXISTS "idx_passive_finding_promoted"
	ON "passive_finding" ("promoted");`

// PassiveFinding 是一条被动检测命中。
//
// Request / Response 不参与 JSON 序列化：列表接口返回可能成百上千条，
// 带上原文会让响应膨胀到不可用。原文只在详情接口单独返回。
type PassiveFinding struct {
	ID          int64  `db:"id" json:"id"`
	Fingerprint string `db:"fingerprint" json:"fingerprint"`
	Detector    string `db:"detector" json:"detector"`
	VulnType    string `db:"vuln_type" json:"vuln_type"`
	Severity    string `db:"severity" json:"severity"`
	Confidence  string `db:"confidence" json:"confidence"`
	Title       string `db:"title" json:"title"`
	Target      string `db:"target" json:"target"`
	Location    string `db:"location" json:"location"`
	Payload     string `db:"payload" json:"payload"`
	Evidence    string `db:"evidence" json:"evidence"`
	// LatencyMs 是触发命中的请求响应耗时（毫秒），时间盲注复核依赖它。
	LatencyMs int64  `db:"latency_ms" json:"latency_ms"`
	Extra     string `db:"extra" json:"extra"`
	// TracesRaw 是证据链（passive.Trace 数组）的 JSON 原文。
	//
	// 只存不绑定结构：db 层不该反向依赖检测器的类型。列表接口不返回它（体积大），
	// 只在详情接口取出后由上层解析。
	TracesRaw string `db:"traces" json:"-"`
	Created   string `db:"created" json:"created"`
	Promoted  int    `db:"promoted" json:"promoted"`
	ResultID  string `db:"result_id" json:"result_id"`

	Request  string `db:"request" json:"-"`
	Response string `db:"response" json:"-"`
}

// PassiveFindingDetail 是详情视图，额外携带原始请求与响应。
type PassiveFindingDetail struct {
	PassiveFinding
	Request  string `json:"request"`
	Response string `json:"response"`
}

// PassiveFindingFilter 是列表查询条件。
type PassiveFindingFilter struct {
	Detector string
	VulnType string
	Severity string
	Keyword  string
	// Promoted 为 nil 表示不筛选；0 / 1 表示只看未提升 / 已提升。
	Promoted *int
	Page     int
	PageSize int
}

// InsertPassiveFinding 写入一条命中。指纹重复时静默忽略，返回 (0, nil)。
//
// 去重在调度层已经做过一次，这里是第二道保险：服务重启后内存去重表清空，
// 数据库唯一索引仍能保证同一处漏洞不会重复堆积。
func InsertPassiveFinding(f PassiveFinding) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	if strings.TrimSpace(f.Fingerprint) == "" {
		return 0, fmt.Errorf("passive finding fingerprint is empty")
	}

	created := f.Created
	if created == "" {
		created = time.Now().Format("2006-01-02 15:04:05")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	traces := f.TracesRaw
	if strings.TrimSpace(traces) == "" {
		traces = "[]"
	}

	res, err := dbx.ExecContext(ctx, `INSERT OR IGNORE INTO "passive_finding"
		(fingerprint, detector, vuln_type, severity, confidence, title, target, location,
		 payload, evidence, latency_ms, traces, request, response, extra, created, promoted, result_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')`,
		f.Fingerprint, f.Detector, f.VulnType, f.Severity, f.Confidence, f.Title,
		f.Target, f.Location, f.Payload, f.Evidence, f.LatencyMs, traces, f.Request, f.Response, f.Extra, created)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, nil
	}
	return res.LastInsertId()
}

// SelectPassiveFindings 分页查询命中列表，同时返回总数。
func SelectPassiveFindings(flt PassiveFindingFilter) ([]PassiveFinding, int64, error) {
	if dbx == nil {
		return nil, 0, fmt.Errorf("sqlite not initialized")
	}

	page := flt.Page
	if page <= 0 {
		page = 1
	}
	pageSize := flt.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}

	where := make([]string, 0, 5)
	args := make([]any, 0, 8)

	if v := strings.TrimSpace(flt.Detector); v != "" {
		where = append(where, "detector = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.VulnType); v != "" {
		where = append(where, "vuln_type = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Severity); v != "" {
		where = append(where, "severity = ?")
		args = append(args, v)
	}
	if flt.Promoted != nil {
		where = append(where, "promoted = ?")
		args = append(args, *flt.Promoted)
	}
	if v := strings.TrimSpace(flt.Keyword); v != "" {
		where = append(where, "(target LIKE ? OR location LIKE ? OR evidence LIKE ?)")
		like := "%" + v + "%"
		args = append(args, like, like, like)
	}

	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var total int64
	if err := dbx.GetContext(ctx, &total, `SELECT COUNT(*) FROM "passive_finding"`+cond, args...); err != nil {
		return nil, 0, err
	}

	listSQL := `SELECT id, fingerprint, detector, vuln_type, severity, confidence, title,
		target, location, payload, evidence, latency_ms, extra, created, promoted, result_id
		FROM "passive_finding"` + cond + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)

	items := make([]PassiveFinding, 0, pageSize)
	if err := dbx.SelectContext(ctx, &items, listSQL, listArgs...); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// GetPassiveFinding 返回单条命中（含原始请求与响应）。
func GetPassiveFinding(id int64) (*PassiveFindingDetail, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var row struct {
		PassiveFinding
		Request  string `db:"request"`
		Response string `db:"response"`
	}
	err := dbx.GetContext(ctx, &row, `SELECT id, fingerprint, detector, vuln_type, severity,
		confidence, title, target, location, payload, evidence, latency_ms, traces, extra, created,
		promoted, result_id, request, response FROM "passive_finding" WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}

	return &PassiveFindingDetail{
		PassiveFinding: row.PassiveFinding,
		Request:        row.Request,
		Response:       row.Response,
	}, nil
}

// MarkPassiveFindingPromoted 标记命中已提升为台账记录。
func MarkPassiveFindingPromoted(id int64, resultID string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx,
		`UPDATE "passive_finding" SET promoted = 1, result_id = ? WHERE id = ? AND promoted = 0`,
		resultID, id)
	return err
}

// CountPassiveFindings 返回命中总数，供导航徽标使用。
func CountPassiveFindings() (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n, `SELECT COUNT(*) FROM "passive_finding"`)
	return n, err
}
