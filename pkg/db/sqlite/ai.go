package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
)

// AI 辅助相关的两张表。
//
// ai_usage 只管「这个月用了几次」——免费试用的次数必须跨重启保留，
// 否则重启一次就白送一轮额度。
// ai_cache 缓存研判结果：同一条命中重复查看时不再调用模型（用户不必为同一件事付两次钱），
// 因此缓存命中的请求不计入用量。
const aiDDL = `CREATE TABLE IF NOT EXISTS "ai_usage" (
	"month" TEXT PRIMARY KEY,
	"used" INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS "ai_cache" (
	"cache_key" TEXT PRIMARY KEY,
	"content" TEXT NOT NULL DEFAULT '',
	"model" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_ai_cache_created" ON "ai_cache" ("created_at");`

// maxAICacheRows 是缓存条数上限：这只是省钱的加速层，不该无限膨胀。
const maxAICacheRows = 500

const aiTimeLayout = "2006-01-02 15:04:05"

// AIMonthKey 返回用量归属的月份键（本地时区，形如 2026-10）。
// 与 result.created 一样用本地时间，避免 sqlite 的 UTC now() 造成跨时区错位。
func AIMonthKey(t time.Time) string {
	return t.Format("2006-01")
}

// TryUseAIQuota 尝试占用一次额度：limit<=0 表示不限次（会员）。
//
// 检查与自增在同一事务里完成，避免两个并发请求各看到「还剩 1 次」后都用掉。
// 返回的 used 是占用后的累计次数。
func TryUseAIQuota(month string, limit int) (used int, allowed bool, err error) {
	if dbx == nil {
		return 0, false, fmt.Errorf("sqlite not initialized")
	}
	month = strings.TrimSpace(month)
	if month == "" {
		return 0, false, fmt.Errorf("month is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO ai_usage(month, used) VALUES(?, 0) ON CONFLICT(month) DO NOTHING`, month); err != nil {
		return 0, false, err
	}

	var current int
	if err = tx.QueryRowContext(ctx, `SELECT used FROM ai_usage WHERE month = ?`, month).Scan(&current); err != nil {
		return 0, false, err
	}
	if limit > 0 && current >= limit {
		return current, false, nil
	}

	if _, err = tx.ExecContext(ctx, `UPDATE ai_usage SET used = used + 1 WHERE month = ?`, month); err != nil {
		return 0, false, err
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return current + 1, true, nil
}

// AIUsage 返回某个月的已用次数；没有记录时返回 0。
func AIUsage(month string) (int, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var used int
	err := dbx.GetContext(ctx, &used, `SELECT used FROM ai_usage WHERE month = ?`, strings.TrimSpace(month))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return used, nil
}

// GetAICache 读取缓存的研判结果；第二个返回值表示是否命中。
func GetAICache(cacheKey string) (string, bool, error) {
	if dbx == nil {
		return "", false, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var content string
	err := dbx.GetContext(ctx, &content, `SELECT content FROM ai_cache WHERE cache_key = ?`, strings.TrimSpace(cacheKey))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	if strings.TrimSpace(content) == "" {
		return "", false, nil
	}
	return content, true, nil
}

// PutAICache 写入研判结果缓存，并按时间裁剪旧记录。
func PutAICache(cacheKey, content, model string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	cacheKey = strings.TrimSpace(cacheKey)
	content = strings.TrimSpace(content)
	if cacheKey == "" || content == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := dbx.ExecContext(ctx,
		`INSERT OR REPLACE INTO ai_cache(cache_key, content, model, created_at) VALUES(?, ?, ?, ?)`,
		cacheKey, content, strings.TrimSpace(model), time.Now().Format(aiTimeLayout)); err != nil {
		return err
	}

	_, err := dbx.ExecContext(ctx,
		`DELETE FROM ai_cache WHERE cache_key NOT IN (
			SELECT cache_key FROM ai_cache ORDER BY created_at DESC, rowid DESC LIMIT ?
		 )`, maxAICacheRows)
	return err
}

// -----------------------
// 研判证据
// -----------------------

// SelectHitEvidence 取出一条命中用于 AI 研判的证据：PoC 元信息 + 该命中的原始请求/响应。
//
// taskID 可为空（台账视图下我们只知道 PoC 与目标，不知道来自哪次任务），
// 此时取最近一次命中。找不到返回 nil, nil —— 调用方要能区分「查不到」与「查询失败」。
func SelectHitEvidence(taskID, vulid, target, fulltarget string) (*db2.HitEvidence, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	vulid = strings.TrimSpace(vulid)
	target = strings.TrimSpace(target)
	fulltarget = strings.TrimSpace(fulltarget)
	if vulid == "" || target == "" {
		return nil, fmt.Errorf("vulid and target are required")
	}

	where := []string{"vulid = ?", "target = ?"}
	args := []interface{}{vulid, target}
	if fulltarget != "" {
		where = append(where, "fulltarget = ?")
		args = append(args, fulltarget)
	}
	if tid := strings.TrimSpace(taskID); tid != "" {
		where = append(where, "taskid = ?")
		args = append(args, tid)
	}

	query := `SELECT taskid, vulid, vulname, target, fulltarget, severity, poc, result, created
	  FROM ` + db2.TableName + `
	 WHERE ` + strings.Join(where, " AND ") + `
	 ORDER BY id DESC LIMIT 1`

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	var row struct {
		TaskID     string `db:"taskid"`
		VulID      string `db:"vulid"`
		VulName    string `db:"vulname"`
		Target     string `db:"target"`
		FullTarget string `db:"fulltarget"`
		Severity   string `db:"severity"`
		Poc        string `db:"poc"`
		Result     string `db:"result"`
		Created    string `db:"created"`
	}
	if err := dbx.GetContext(ctx, &row, query, args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	evidence := &db2.HitEvidence{
		TaskID:     row.TaskID,
		VulID:      row.VulID,
		VulName:    row.VulName,
		Severity:   strings.ToUpper(strings.TrimSpace(row.Severity)),
		Target:     row.Target,
		FullTarget: row.FullTarget,
		Created:    row.Created,
		Poc:        row.Poc,
	}

	// result 列是 []PocResult 的 JSON；取第一条带请求/响应记录的作为证据。
	var results []db2.PocResult
	if err := json.Unmarshal([]byte(row.Result), &results); err == nil {
		for _, item := range results {
			if strings.TrimSpace(item.Request) == "" && strings.TrimSpace(item.Response) == "" {
				continue
			}
			evidence.Request = item.Request
			evidence.Response = item.Response
			break
		}
	}
	return evidence, nil
}

// -----------------------
// 报告摘要
// -----------------------

// aiSummaryFindingLimit 是喂给模型的条目上限：摘要要的是「整体与重点」，
// 而不是把几百条命中塞进上下文——那既贵，也会让结论失去重点。
const aiSummaryFindingLimit = 40

// aiSummaryGroupSelect 把命中按「PoC + 目标」聚合，并带上台账的人工状态。
// 过滤条件统一用 r. 前缀（内层别名），避免内层/外层字段名混淆。
var aiSummaryGroupSelect = `SELECT
	r.vulid AS vulid,
	MAX(r.vulname) AS vulname,
	r.target AS target,
	r.fulltarget AS fulltarget,
	MAX(r.severity) AS severity,
	COUNT(*) AS hit_count,
	COALESCE(l.status, 'pending') AS status,
	MAX(COALESCE(tp.project_id, '')) AS project_id
  FROM ` + db2.TableName + ` r
  LEFT JOIN vuln_ledger l
	ON l.vulid = r.vulid AND l.target = r.target AND l.fulltarget = r.fulltarget
  LEFT JOIN task_project tp ON tp.taskid = r.taskid`

// aiSummaryConditions 组装摘要查询的过滤条件（任务 / 严重级别 / 关键字）。
func aiSummaryConditions(taskID, severity, keyword string) ([]string, []interface{}) {
	var conds []string
	var args []interface{}

	if tid := strings.TrimSpace(taskID); tid != "" {
		conds = append(conds, "r.taskid = ?")
		args = append(args, tid)
	}
	if sevs := normalizeList(strings.Split(severity, ",")); len(sevs) > 0 && len(sevs) < 5 {
		holders := make([]string, 0, len(sevs))
		for _, s := range sevs {
			holders = append(holders, "?")
			args = append(args, s)
		}
		conds = append(conds, "LOWER(r.severity) IN ("+strings.Join(holders, ",")+")")
	}
	if kw := strings.TrimSpace(keyword); kw != "" {
		conds = append(conds, "(r.vulid LIKE ? OR r.vulname LIKE ? OR r.target LIKE ?)")
		like := "%" + kw + "%"
		args = append(args, like, like, like)
	}
	return conds, args
}

// SelectSummaryData 汇总生成报告摘要所需的数据。
//
// 空任务 ID 表示「按当前筛选跨任务汇总」：这时不做任务限定，
// 由调用方在提示词里如实说明范围，避免让模型误以为是某一次扫描的结论。
func SelectSummaryData(taskID, severity, keyword string) (*db2.SummaryData, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}

	conds, args := aiSummaryConditions(taskID, severity, keyword)
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	grouped := aiSummaryGroupSelect + where + " GROUP BY r.vulid, r.target, r.fulltarget"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out := &db2.SummaryData{
		TaskID:       strings.TrimSpace(taskID),
		Severity:     strings.TrimSpace(severity),
		Keyword:      strings.TrimSpace(keyword),
		Findings:     []db2.SummaryFinding{},
		SeverityDist: map[string]int64{},
	}
	out.Scope = "filter"
	if out.TaskID != "" {
		out.Scope = "task"
	}

	rows := []struct {
		VulID      string `db:"vulid"`
		VulName    string `db:"vulname"`
		Target     string `db:"target"`
		FullTarget string `db:"fulltarget"`
		Severity   string `db:"severity"`
		HitCount   int64  `db:"hit_count"`
		Status     string `db:"status"`
		ProjectID  string `db:"project_id"`
	}{}
	// last_seen 只在聚合视图里存在，这里补一层外层查询来排序。
	wrap := "SELECT * FROM (" + grouped + ") t ORDER BY " +
		"CASE LOWER(t.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC, " +
		"t.hit_count DESC LIMIT " + strconv.Itoa(aiSummaryFindingLimit+1)
	if err := dbx.SelectContext(ctx, &rows, wrap, args...); err != nil {
		return nil, err
	}
	for i, r := range rows {
		if i >= aiSummaryFindingLimit {
			out.Truncated = true
			break
		}
		out.Findings = append(out.Findings, db2.SummaryFinding{
			VulID:      r.VulID,
			VulName:    r.VulName,
			Target:     r.Target,
			FullTarget: r.FullTarget,
			Severity:   strings.ToUpper(strings.TrimSpace(r.Severity)),
			HitCount:   r.HitCount,
			Status:     strings.TrimSpace(r.Status),
			ProjectID:  r.ProjectID,
		})
	}

	// 命中总条数（未聚合）与按级别的条目分布，让摘要里的数字有依据。
	if err := dbx.GetContext(ctx, &out.HitRows,
		"SELECT COUNT(*) FROM "+db2.TableName+" r"+where, args...); err != nil {
		return nil, err
	}
	dist := []struct {
		Severity string `db:"severity"`
		N        int64  `db:"n"`
	}{}
	if err := dbx.SelectContext(ctx, &dist,
		"SELECT LOWER(t.severity) AS severity, COUNT(*) AS n FROM ("+grouped+") t GROUP BY LOWER(t.severity)",
		args...); err != nil {
		return nil, err
	}
	for _, d := range dist {
		out.SeverityDist[strings.ToUpper(strings.TrimSpace(d.Severity))] = d.N
	}

	if out.TaskID != "" {
		meta, err := SelectScanTask(out.TaskID)
		if err != nil {
			return nil, err
		}
		if meta != nil {
			out.TaskName = meta.Name
			out.TaskSource = meta.Source
			out.TaskStatus = meta.Status
			out.CreatedAt = meta.CreatedAt
			out.StartedAt = meta.StartedAt
			out.EndedAt = meta.EndedAt
			out.TotalTargets = meta.TotalTargets
			out.TotalPocs = meta.TotalPocs
			out.TotalScans = meta.TotalScans
			if out.TaskSource == "" {
				out.TaskSource = "web"
			}
		}
	}
	return out, nil
}
