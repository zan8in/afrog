package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// 被动扫描的敏感信息提取记录。
//
// 与 passive_finding 的关系：两者都来自同一次被动流量，但**产物性质完全不同**。
// passive_finding 存的是「某处存在漏洞」，必须通过置信度门控；本表存的是「某处存在
// 某个字符串」（密钥、身份证号…），它不是漏洞判定，因此不做 Certain 门控，只如实
// 标注 confidence 供人判断。
//
// 聚合口径与检测层一致：fingerprint = 规则 + 值 + 目标。同一个密钥在十个 JS 文件里
// 反复出现只算一条观察，hit_count 记「又见到了多少次」，last_seen 记最近一次时间。
const passiveExtractionDDL = `CREATE TABLE IF NOT EXISTS "passive_extraction" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"project_id" TEXT NOT NULL DEFAULT '',
	"fingerprint" TEXT NOT NULL DEFAULT '',
	"detector" TEXT NOT NULL DEFAULT '',
	"rule" TEXT NOT NULL DEFAULT '',
	"category" TEXT NOT NULL DEFAULT '',
	"title" TEXT NOT NULL DEFAULT '',
	"severity" TEXT NOT NULL DEFAULT '',
	"confidence" TEXT NOT NULL DEFAULT '',
	"value" TEXT NOT NULL DEFAULT '',
	"target" TEXT NOT NULL DEFAULT '',
	"location" TEXT NOT NULL DEFAULT '',
	"latency_ms" INTEGER NOT NULL DEFAULT 0,
	"evidence" TEXT NOT NULL DEFAULT '',
	"request" TEXT NOT NULL DEFAULT '',
	"response" TEXT NOT NULL DEFAULT '',
	"extra" TEXT NOT NULL DEFAULT '{}',
	"hit_count" INTEGER NOT NULL DEFAULT 1,
	"first_seen" TEXT NOT NULL DEFAULT '',
	"last_seen" TEXT NOT NULL DEFAULT '',
	"created" TEXT NOT NULL DEFAULT ''
  );`

const passiveExtractionIndexDDL = `CREATE UNIQUE INDEX IF NOT EXISTS "idx_passive_extraction_scope"
	ON "passive_extraction" ("project_id", "fingerprint");
  CREATE INDEX IF NOT EXISTS "idx_passive_extraction_created"
	ON "passive_extraction" ("created");
  CREATE INDEX IF NOT EXISTS "idx_passive_extraction_rule"
	ON "passive_extraction" ("rule");
  CREATE INDEX IF NOT EXISTS "idx_passive_extraction_category"
	ON "passive_extraction" ("category");`

// PassiveExtraction 是一条敏感信息提取观察（按作用域聚合后）。
//
// Request / Response 不参与列表 JSON：列表可能上千条，带上原文会让响应膨胀到不可用。
type PassiveExtraction struct {
	ID int64 `db:"id" json:"id"`
	// ProjectID 是作用域：提取物的归属渗透项目。空串表示「未归属」。
	ProjectID   string `db:"project_id" json:"project_id"`
	Fingerprint string `db:"fingerprint" json:"-"`
	Detector    string `db:"detector" json:"detector"`
	Rule        string `db:"rule" json:"rule"`
	Category    string `db:"category" json:"category"`
	Title       string `db:"title" json:"title"`
	Severity    string `db:"severity" json:"severity"`
	Confidence  string `db:"confidence" json:"confidence"`
	Value       string `db:"value" json:"value"`
	Target      string `db:"target" json:"target"`
	Location    string `db:"location" json:"location"`
	LatencyMs   int64  `db:"latency_ms" json:"latency_ms"`
	Evidence    string `db:"evidence" json:"evidence"`
	Extra       string `db:"extra" json:"extra"`
	HitCount    int64  `db:"hit_count" json:"hit_count"`
	FirstSeen   string `db:"first_seen" json:"first_seen"`
	LastSeen    string `db:"last_seen" json:"last_seen"`
	Created     string `db:"created" json:"created"`

	Request  string `db:"request" json:"-"`
	Response string `db:"response" json:"-"`
}

// PassiveExtractionDetail 是详情视图，额外携带原始请求与响应。
type PassiveExtractionDetail struct {
	PassiveExtraction
	Request  string `json:"request"`
	Response string `json:"response"`
}

// PassiveExtractionFilter 是列表查询条件。
type PassiveExtractionFilter struct {
	// ProjectID 非空时只查该项目；为空表示全部（含未归属）。
	ProjectID string
	Detector  string
	Rule      string
	Category  string
	Severity  string
	Keyword   string
	Page      int
	PageSize  int
}

// UpsertPassiveExtraction 按 (project_id, fingerprint) 落一条提取观察。
//
// 首次出现 → 插入、hit_count=1；再次命中 → hit_count+1、last_seen 与证据刷新。
// 返回落库后的 id 与累计命中次数。
func UpsertPassiveExtraction(e PassiveExtraction) (int64, int64, error) {
	if dbx == nil {
		return 0, 0, fmt.Errorf("sqlite not initialized")
	}
	if strings.TrimSpace(e.Fingerprint) == "" {
		return 0, 0, fmt.Errorf("passive extraction fingerprint is empty")
	}

	extra := e.Extra
	if strings.TrimSpace(extra) == "" {
		extra = "{}"
	}
	now := passiveNow()
	created := e.Created
	if created == "" {
		created = now
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing struct {
		ID       int64 `db:"id"`
		HitCount int64 `db:"hit_count"`
	}
	err = tx.GetContext(ctx, &existing,
		`SELECT id, hit_count FROM "passive_extraction" WHERE project_id = ? AND fingerprint = ?`,
		e.ProjectID, e.Fingerprint)

	if err == sql.ErrNoRows {
		res, err := tx.ExecContext(ctx, `INSERT INTO "passive_extraction"
			(project_id, fingerprint, detector, rule, category, title, severity, confidence,
			 value, target, location, latency_ms, evidence, request, response, extra,
			 hit_count, first_seen, last_seen, created)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
			e.ProjectID, e.Fingerprint, e.Detector, e.Rule, e.Category, e.Title, e.Severity, e.Confidence,
			e.Value, e.Target, e.Location, e.LatencyMs, e.Evidence, e.Request, e.Response, extra,
			now, now, created)
		if err != nil {
			return 0, 0, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return 0, 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, 0, err
		}
		return id, 1, nil
	}
	if err != nil {
		return 0, 0, err
	}

	nextHit := existing.HitCount + 1
	_, err = tx.ExecContext(ctx, `UPDATE "passive_extraction" SET
		detector = ?, rule = ?, category = ?, title = ?, severity = ?, confidence = ?,
		value = ?, target = ?, location = ?, latency_ms = ?, evidence = ?, request = ?, response = ?, extra = ?,
		hit_count = ?, last_seen = ?
		WHERE id = ?`,
		e.Detector, e.Rule, e.Category, e.Title, e.Severity, e.Confidence,
		e.Value, e.Target, e.Location, e.LatencyMs, e.Evidence, e.Request, e.Response, extra,
		nextHit, now, existing.ID)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return existing.ID, nextHit, nil
}

// SelectPassiveExtractions 分页查询提取列表，同时返回总数。
func SelectPassiveExtractions(flt PassiveExtractionFilter) ([]PassiveExtraction, int64, error) {
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

	where := make([]string, 0, 6)
	args := make([]any, 0, 8)

	if v := strings.TrimSpace(flt.ProjectID); v != "" {
		where = append(where, "project_id = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Detector); v != "" {
		where = append(where, "detector = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Rule); v != "" {
		where = append(where, "rule = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Category); v != "" {
		where = append(where, "category = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Severity); v != "" {
		where = append(where, "severity = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(flt.Keyword); v != "" {
		where = append(where, "(value LIKE ? OR target LIKE ? OR title LIKE ?)")
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
	if err := dbx.GetContext(ctx, &total, `SELECT COUNT(*) FROM "passive_extraction"`+cond, args...); err != nil {
		return nil, 0, err
	}

	listSQL := `SELECT id, project_id, fingerprint, detector, rule, category, title, severity,
		confidence, value, target, location, latency_ms, evidence, extra, hit_count,
		first_seen, last_seen, created
		FROM "passive_extraction"` + cond + ` ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?`
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)

	items := make([]PassiveExtraction, 0, pageSize)
	if err := dbx.SelectContext(ctx, &items, listSQL, listArgs...); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// GetPassiveExtraction 返回单条提取观察（含原始请求与响应）。
func GetPassiveExtraction(id int64) (*PassiveExtractionDetail, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var row struct {
		PassiveExtraction
		Request  string `db:"request"`
		Response string `db:"response"`
	}
	err := dbx.GetContext(ctx, &row, `SELECT id, project_id, fingerprint, detector, rule, category,
		title, severity, confidence, value, target, location, latency_ms, evidence, extra, hit_count,
		first_seen, last_seen, created, request, response
		FROM "passive_extraction" WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}

	return &PassiveExtractionDetail{
		PassiveExtraction: row.PassiveExtraction,
		Request:           row.Request,
		Response:          row.Response,
	}, nil
}

// CountPassiveExtractions 返回提取总数，供导航徽标使用。
func CountPassiveExtractions() (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n, `SELECT COUNT(*) FROM "passive_extraction"`)
	return n, err
}

// CountPassiveExtractionsByProject 返回指定项目的提取总数。
func CountPassiveExtractionsByProject(projectID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM "passive_extraction" WHERE project_id = ?`, strings.TrimSpace(projectID))
	return n, err
}
