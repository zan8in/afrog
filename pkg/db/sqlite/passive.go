package sqlite

import (
	"context"
	"database/sql"
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
// 与 result 表的关键差异：result 每次命中追加一行，本表按 (project_id, fingerprint)
// 聚合成一条观察。被动扫描可能长时间驻留、同一漏洞被反复命中，逐次追加会让表
// 无界膨胀；聚合成一条、用 hit_count / first_seen / last_seen 记录时间线，既保留
// 「又打中了」这一事实，又把体积压在可控范围。
//
// 流量本身不落库：被动扫描的原始事务只存在于内存中参与检测，落库的只有命中时
// 的那一对请求/响应（保留最近一次），用于回溯与取证。
const passiveFindingDDL = `CREATE TABLE IF NOT EXISTS "passive_finding" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"project_id" TEXT NOT NULL DEFAULT '',
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
	"hit_count" INTEGER NOT NULL DEFAULT 1,
	"first_seen" TEXT NOT NULL DEFAULT '',
	"last_seen" TEXT NOT NULL DEFAULT '',
	"state" TEXT NOT NULL DEFAULT 'new',
	"created" TEXT NOT NULL DEFAULT '',
	"promoted" INTEGER NOT NULL DEFAULT 0,
	"result_id" TEXT NOT NULL DEFAULT ''
  );`

// passiveFindingIndexDDL 与建表分开执行。
//
// 关键原因：老库升级时，项目聚合用的唯一索引建立在 project_id 之上，而这一列要等
// ensurePassiveScopeColumns 的 ALTER 之后才存在。若把索引和建表放在同一条语句里，
// 老库会在「CREATE UNIQUE INDEX ... (project_id, fingerprint)」这一步直接报
// no such column，导致整个 Web 服务起不来。分开后顺序才可控。
const passiveFindingIndexDDL = `CREATE UNIQUE INDEX IF NOT EXISTS "idx_passive_finding_scope"
	ON "passive_finding" ("project_id", "fingerprint");
  CREATE INDEX IF NOT EXISTS "idx_passive_finding_created"
	ON "passive_finding" ("created");
  CREATE INDEX IF NOT EXISTS "idx_passive_finding_promoted"
	ON "passive_finding" ("promoted");
  CREATE INDEX IF NOT EXISTS "idx_passive_finding_state"
	ON "passive_finding" ("state");`

// 命中状态：新增 / 仍存在 / 已修复 / 复发。
//
// 这是系统按观察事实推导的状态，与 vuln_ledger 里人工维护的 status 是两回事：
// 前者回答「这个漏洞在时间线上的位置」，后者回答「人怎么定性它」。
const (
	// PassiveStateNew 首次在该作用域内被发现。
	PassiveStateNew = "new"
	// PassiveStatePresent 此前已发现，本次复测仍然存在。
	PassiveStatePresent = "present"
	// PassiveStateFixed 已人工确认修复。
	PassiveStateFixed = "fixed"
	// PassiveStateRegression 曾标记为已修复，之后又被命中。
	PassiveStateRegression = "regression"
)

// PassiveFinding 是一条被动检测命中（按作用域聚合后的观察）。
//
// Request / Response 不参与 JSON 序列化：列表接口返回可能成百上千条，
// 带上原文会让响应膨胀到不可用。原文只在详情接口单独返回。
type PassiveFinding struct {
	ID int64 `db:"id" json:"id"`
	// ProjectID 是作用域：命中的归属渗透项目。空串表示「未归属」。
	ProjectID   string `db:"project_id" json:"project_id"`
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
	// HitCount 是该观察被命中的累计次数，反映「又打中了多少次」。
	HitCount int64 `db:"hit_count" json:"hit_count"`
	// FirstSeen / LastSeen 是该观察的时间线，复测与报告回归依赖它们。
	FirstSeen string `db:"first_seen" json:"first_seen"`
	LastSeen  string `db:"last_seen" json:"last_seen"`
	// State 见 PassiveState* 常量。
	State   string `db:"state" json:"state"`
	Created string `db:"created" json:"created"`
	// Promoted 为 1 表示已提升为台账记录。
	Promoted int    `db:"promoted" json:"promoted"`
	ResultID string `db:"result_id" json:"result_id"`

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
	// ProjectID 非空时只查该项目；为空表示全部（含未归属）。
	ProjectID string
	Detector  string
	VulnType  string
	Severity  string
	Keyword   string
	State     []string
	// Promoted 为 nil 表示不筛选；0 / 1 表示只看未提升 / 已提升。
	Promoted *int
	Page     int
	PageSize int
}

// passiveNow 返回统一的落库时间戳。
func passiveNow() string { return time.Now().Format("2006-01-02 15:04:05") }

// UpsertPassiveFinding 按 (project_id, fingerprint) 落一条观察。
//
// 语义：
//   - 首次出现 → 插入，state=new，hit_count=1，first_seen=last_seen=now；
//   - 再次命中 → hit_count+1、last_seen 刷新、证据刷新为最近一次；
//     state 从 fixed 变为 regression，否则变为 present。
//
// 返回落库后的 state 与累计命中次数，供界面直接展示「新增 / 仍存在 / 复发」。
func UpsertPassiveFinding(f PassiveFinding) (int64, string, int64, error) {
	if dbx == nil {
		return 0, "", 0, fmt.Errorf("sqlite not initialized")
	}
	if strings.TrimSpace(f.Fingerprint) == "" {
		return 0, "", 0, fmt.Errorf("passive finding fingerprint is empty")
	}

	traces := f.TracesRaw
	if strings.TrimSpace(traces) == "" {
		traces = "[]"
	}
	extra := f.Extra
	if strings.TrimSpace(extra) == "" {
		extra = "{}"
	}
	now := passiveNow()
	created := f.Created
	if created == "" {
		created = now
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, "", 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing struct {
		ID       int64  `db:"id"`
		State    string `db:"state"`
		HitCount int64  `db:"hit_count"`
	}
	err = tx.GetContext(ctx, &existing,
		`SELECT id, state, hit_count FROM "passive_finding" WHERE project_id = ? AND fingerprint = ?`,
		f.ProjectID, f.Fingerprint)

	if err == sql.ErrNoRows {
		res, err := tx.ExecContext(ctx, `INSERT INTO "passive_finding"
			(project_id, fingerprint, detector, vuln_type, severity, confidence, title, target, location,
			 payload, evidence, latency_ms, traces, request, response, extra,
			 hit_count, first_seen, last_seen, state, created, promoted, result_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 0, '')`,
			f.ProjectID, f.Fingerprint, f.Detector, f.VulnType, f.Severity, f.Confidence, f.Title,
			f.Target, f.Location, f.Payload, f.Evidence, f.LatencyMs, traces, f.Request, f.Response, extra,
			now, now, PassiveStateNew, created)
		if err != nil {
			return 0, "", 0, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return 0, "", 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, "", 0, err
		}
		return id, PassiveStateNew, 1, nil
	}
	if err != nil {
		return 0, "", 0, err
	}

	// 已存在：状态只前进不倒退。fixed 之后再命中即「复发」，其余一律「仍存在」。
	nextState := PassiveStatePresent
	if existing.State == PassiveStateFixed {
		nextState = PassiveStateRegression
	}
	nextHit := existing.HitCount + 1

	_, err = tx.ExecContext(ctx, `UPDATE "passive_finding" SET
		detector = ?, vuln_type = ?, severity = ?, confidence = ?, title = ?, target = ?, location = ?,
		payload = ?, evidence = ?, latency_ms = ?, traces = ?, request = ?, response = ?, extra = ?,
		hit_count = ?, last_seen = ?, state = ?
		WHERE id = ?`,
		f.Detector, f.VulnType, f.Severity, f.Confidence, f.Title, f.Target, f.Location,
		f.Payload, f.Evidence, f.LatencyMs, traces, f.Request, f.Response, extra,
		nextHit, now, nextState, existing.ID)
	if err != nil {
		return 0, "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, "", 0, err
	}
	return existing.ID, nextState, nextHit, nil
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
	if sts := normalizePassiveStates(flt.State); len(sts) > 0 {
		holders := make([]string, 0, len(sts))
		for _, s := range sts {
			holders = append(holders, "?")
			args = append(args, s)
		}
		where = append(where, "state IN ("+strings.Join(holders, ",")+")")
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

	listSQL := `SELECT id, project_id, fingerprint, detector, vuln_type, severity, confidence, title,
		target, location, payload, evidence, latency_ms, extra, hit_count, first_seen, last_seen,
		state, created, promoted, result_id
		FROM "passive_finding"` + cond + ` ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?`
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)

	items := make([]PassiveFinding, 0, pageSize)
	if err := dbx.SelectContext(ctx, &items, listSQL, listArgs...); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// normalizePassiveStates 归一化状态筛选值：小写、去空白、丢弃空项。
func normalizePassiveStates(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if t := strings.ToLower(strings.TrimSpace(v)); t != "" {
			out = append(out, t)
		}
	}
	return out
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
	err := dbx.GetContext(ctx, &row, `SELECT id, project_id, fingerprint, detector, vuln_type, severity,
		confidence, title, target, location, payload, evidence, latency_ms, traces, extra, hit_count,
		first_seen, last_seen, state, created, promoted, result_id, request, response
		FROM "passive_finding" WHERE id = ?`, id)
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

// SetPassiveFindingState 人工设置命中状态（目前仅用于标记「已修复」）。
//
// 只允许在 fixed / present 之间切换：fixed 之后再被命中，由 upsert 自动转为
// regression；把 state 直接写成 regression 没有意义，故在入口拦下。
func SetPassiveFindingState(id int64, state string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	state = strings.ToLower(strings.TrimSpace(state))
	if state != PassiveStateFixed && state != PassiveStatePresent {
		return fmt.Errorf("unsupported state: %s", state)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx,
		`UPDATE "passive_finding" SET state = ? WHERE id = ?`, state, id)
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

// CountPassiveFindingsByProject 返回指定项目的命中总数。
func CountPassiveFindingsByProject(projectID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM "passive_finding" WHERE project_id = ?`, strings.TrimSpace(projectID))
	return n, err
}
