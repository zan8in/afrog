package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// 被动扫描覆盖度台账。
//
// 与 passive_finding 的分工：后者只记「确认命中」，回答「发现了什么」；本表记
// 「(资产, 检测器) 这段关系被处理成了什么状态」，回答「测没测、没测为什么」。
// 因此它必须记录 skipped —— 恰恰是「没结论」的那部分，才是查漏补缺的依据。
//
// 聚合口径是 (project_id, host, detector)，host 只取 authority（host[:port]），
// 不区分 http/https：同一台机器不应因为协议不同裂成两行。
const passiveCoverageDDL = `CREATE TABLE IF NOT EXISTS "passive_coverage" (
	"project_id" TEXT NOT NULL DEFAULT '',
	"host" TEXT NOT NULL DEFAULT '',
	"detector" TEXT NOT NULL DEFAULT '',
	"state" TEXT NOT NULL DEFAULT 'skipped',
	"reason" TEXT NOT NULL DEFAULT '',
	"samples" INTEGER NOT NULL DEFAULT 0,
	"hits" INTEGER NOT NULL DEFAULT 0,
	"skipped" INTEGER NOT NULL DEFAULT 0,
	"errors" INTEGER NOT NULL DEFAULT 0,
	"last_verdict" TEXT NOT NULL DEFAULT '',
	"first_seen" TEXT NOT NULL DEFAULT '',
	"last_seen" TEXT NOT NULL DEFAULT '',
	PRIMARY KEY ("project_id", "host", "detector")
  );
  CREATE INDEX IF NOT EXISTS "idx_passive_coverage_state"
	ON "passive_coverage" ("state");
  CREATE INDEX IF NOT EXISTS "idx_passive_coverage_last_seen"
	ON "passive_coverage" ("last_seen");
  CREATE INDEX IF NOT EXISTS "idx_passive_coverage_host"
	ON "passive_coverage" ("project_id", "host");`

// PassiveCoverage 是一行覆盖度记录。
//
// State / Reason 取「最高优先级的那次结论」：hit > tested > error > skipped。
// 计数列独立累加，所以即使状态被更高优先级覆盖，也不会丢掉「跳过过多少次」。
type PassiveCoverage struct {
	ProjectID   string `db:"project_id" json:"project_id"`
	Host        string `db:"host" json:"host"`
	Detector    string `db:"detector" json:"detector"`
	State       string `db:"state" json:"state"`
	Reason      string `db:"reason" json:"reason"`
	Samples     int64  `db:"samples" json:"samples"`
	Hits        int64  `db:"hits" json:"hits"`
	Skipped     int64  `db:"skipped" json:"skipped"`
	Errors      int64  `db:"errors" json:"errors"`
	LastVerdict string `db:"last_verdict" json:"last_verdict"`
	FirstSeen   string `db:"first_seen" json:"first_seen"`
	LastSeen    string `db:"last_seen" json:"last_seen"`
}

// PassiveCoverageFilter 是覆盖度列表的筛选条件。
type PassiveCoverageFilter struct {
	ProjectID string
	Detector  string
	State     []string
	Keyword   string
	Page      int
	PageSize  int
}

// PassiveCoverageSummary 是覆盖度的整体分布，用于页面顶部的汇总条。
type PassiveCoverageSummary struct {
	Total   int64 `json:"total"`
	Hosts   int64 `json:"hosts"`
	Hit     int64 `json:"hit"`
	Tested  int64 `json:"tested"`
	Skipped int64 `json:"skipped"`
	Error   int64 `json:"error"`
}

// coverageStateRankSQL 把状态映射成可比较的优先级，供 upsert 时「只升不降」。
//
// 降级是危险的：一条静态资源的 skip 不应该把此前「已执行、无结论」擦成「没测过」。
// 反过来，成功执行过一次检测，就应该把先前的 error 清掉。
const coverageStateRankSQL = `CASE %s
	WHEN 'hit' THEN 3
	WHEN 'tested' THEN 2
	WHEN 'error' THEN 1
	ELSE 0 END`

// UpsertPassiveCoverage 批量累加覆盖度。
//
// 一次刷盘一个事务：覆盖度是高频信号，逐条提交会把 sqlite 写放大到不可接受。
// 状态与原因按优先级更新，计数则无条件累加。
func UpsertPassiveCoverage(rows []PassiveCoverage) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if len(rows) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	query := `INSERT INTO "passive_coverage" (
		"project_id", "host", "detector", "state", "reason",
		"samples", "hits", "skipped", "errors",
		"last_verdict", "first_seen", "last_seen"
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT("project_id", "host", "detector") DO UPDATE SET
		"samples" = "passive_coverage"."samples" + excluded."samples",
		"hits" = "passive_coverage"."hits" + excluded."hits",
		"skipped" = "passive_coverage"."skipped" + excluded."skipped",
		"errors" = "passive_coverage"."errors" + excluded."errors",
		"last_seen" = excluded."last_seen",
		"last_verdict" = CASE
			WHEN excluded."last_verdict" <> '' THEN excluded."last_verdict"
			ELSE "passive_coverage"."last_verdict" END,
		"state" = CASE
			WHEN (` + fmt.Sprintf(coverageStateRankSQL, `excluded."state"`) + `) >=
			     (` + fmt.Sprintf(coverageStateRankSQL, `"passive_coverage"."state"`) + `)
			THEN excluded."state" ELSE "passive_coverage"."state" END,
		"reason" = CASE
			WHEN excluded."reason" <> '' AND
			     (` + fmt.Sprintf(coverageStateRankSQL, `excluded."state"`) + `) >=
			     (` + fmt.Sprintf(coverageStateRankSQL, `"passive_coverage"."state"`) + `)
			THEN excluded."reason" ELSE "passive_coverage"."reason" END`

	now := time.Now().Format(assetTimeLayout)
	for _, r := range rows {
		if strings.TrimSpace(r.Host) == "" || strings.TrimSpace(r.Detector) == "" {
			continue
		}
		firstSeen := r.FirstSeen
		if strings.TrimSpace(firstSeen) == "" {
			firstSeen = now
		}
		lastSeen := r.LastSeen
		if strings.TrimSpace(lastSeen) == "" {
			lastSeen = now
		}
		if _, err := tx.ExecContext(ctx, query,
			r.ProjectID, r.Host, r.Detector, r.State, r.Reason,
			r.Samples, r.Hits, r.Skipped, r.Errors,
			r.LastVerdict, firstSeen, lastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SelectPassiveCoverage 分页返回覆盖度列表。
func SelectPassiveCoverage(flt PassiveCoverageFilter) ([]PassiveCoverage, int64, error) {
	if dbx == nil {
		return nil, 0, fmt.Errorf("sqlite not initialized")
	}

	where := make([]string, 0, 4)
	args := make([]any, 0, 6)
	// 与 passive_finding 同口径：project_id 为空表示「全部项目」，不是「未归属」。
	if pid := strings.TrimSpace(flt.ProjectID); pid != "" {
		where = append(where, "project_id = ?")
		args = append(args, pid)
	}
	if d := strings.TrimSpace(flt.Detector); d != "" {
		where = append(where, "detector = ?")
		args = append(args, d)
	}
	if len(flt.State) > 0 {
		holders := make([]string, 0, len(flt.State))
		for _, s := range flt.State {
			if s = strings.TrimSpace(s); s != "" {
				holders = append(holders, "?")
				args = append(args, s)
			}
		}
		if len(holders) > 0 {
			where = append(where, "state IN ("+strings.Join(holders, ",")+")")
		}
	}
	if kw := strings.TrimSpace(flt.Keyword); kw != "" {
		where = append(where, "(host LIKE ? OR reason LIKE ?)")
		like := "%" + kw + "%"
		args = append(args, like, like)
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := dbx.Get(&total, "SELECT COUNT(*) FROM \"passive_coverage\""+cond, args...); err != nil {
		return nil, 0, err
	}

	page, pageSize := flt.Page, flt.PageSize
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}

	query := `SELECT "project_id", "host", "detector", "state", "reason",
		"samples", "hits", "skipped", "errors", "last_verdict", "first_seen", "last_seen"
		FROM "passive_coverage"` + cond + `
		ORDER BY CASE state WHEN 'hit' THEN 0 WHEN 'error' THEN 1 WHEN 'tested' THEN 2 ELSE 3 END,
			last_seen DESC
		LIMIT ? OFFSET ?`
	args = append(args, pageSize, (page-1)*pageSize)

	items := make([]PassiveCoverage, 0, pageSize)
	if err := dbx.Select(&items, query, args...); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// SelectPassiveCoverageSummary 返回覆盖度分布。
func SelectPassiveCoverageSummary(projectID string) (PassiveCoverageSummary, error) {
	var out PassiveCoverageSummary
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}

	type stateCount struct {
		State string `db:"state"`
		N     int64  `db:"n"`
	}

	// 与列表同口径：空 project_id 表示全部项目。
	cond := ""
	args := []any{}
	if pid := strings.TrimSpace(projectID); pid != "" {
		cond = " WHERE project_id = ?"
		args = append(args, pid)
	}

	var counts []stateCount
	if err := dbx.Select(&counts,
		`SELECT "state", COUNT(*) AS n FROM "passive_coverage"`+cond+` GROUP BY "state"`,
		args...); err != nil {
		return out, err
	}
	for _, c := range counts {
		out.Total += c.N
		switch c.State {
		case "hit":
			out.Hit = c.N
		case "tested":
			out.Tested = c.N
		case "skipped":
			out.Skipped = c.N
		case "error":
			out.Error = c.N
		}
	}
	if err := dbx.Get(&out.Hosts,
		`SELECT COUNT(DISTINCT "host") FROM "passive_coverage"`+cond,
		args...); err != nil {
		return out, err
	}
	return out, nil
}

// SelectCoverageHosts 返回已经进入覆盖度台账的资产集合。
func SelectCoverageHosts(projectID string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	query := `SELECT DISTINCT "host" FROM "passive_coverage"`
	args := []any{}
	if pid := strings.TrimSpace(projectID); pid != "" {
		query += " WHERE project_id = ?"
		args = append(args, pid)
	}
	var hosts []string
	if err := dbx.Select(&hosts, query, args...); err != nil {
		return out, err
	}
	for _, h := range hosts {
		out[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return out, nil
}

// SelectCoverageForHost 返回某个资产的覆盖度明细（所有检测器）。
//
// 详情页用它回答「这条命中所在的资产，其他检测器测过吗」——把命中放回覆盖度
// 上下文里，才能看出这是「只测了这一点」还是「整块都测过」。
func SelectCoverageForHost(projectID, host string) ([]PassiveCoverage, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return []PassiveCoverage{}, nil
	}
	query := `SELECT "project_id", "host", "detector", "state", "reason",
		"samples", "hits", "skipped", "errors", "last_verdict", "first_seen", "last_seen"
		FROM "passive_coverage" WHERE host = ?`
	args := []any{host}
	if pid := strings.TrimSpace(projectID); pid != "" {
		query += ` AND project_id = ?`
		args = append(args, pid)
	}
	query += ` ORDER BY CASE state WHEN 'hit' THEN 0 WHEN 'error' THEN 1 WHEN 'tested' THEN 2 ELSE 3 END, detector`
	items := make([]PassiveCoverage, 0, 8)
	if err := dbx.Select(&items, query, args...); err != nil {
		return nil, err
	}
	return items, nil
}

// SelectAssetCandidatesByHost 找出可能对应某个 authority 的资产。
//
// 只做粗筛（精确地址 + URL 前缀），精确匹配由调用方用统一的归一化函数完成：
// 这样 sqlite 侧不需要知道「默认端口要不要去掉」这类规则，避免两套口径漂移。
func SelectAssetCandidatesByHost(projectID, host string) ([]CoverageAsset, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, nil
	}

	where := []string{
		`a."archived" = 0`,
		`(lower(a."address") = ? OR lower(a."address") LIKE ? OR lower(a."address") LIKE ?)`,
	}
	args := []any{host, "http://" + host + "%", "https://" + host + "%"}
	if pid := strings.TrimSpace(projectID); pid != "" {
		where = append(where, `pa."project_id" = ?`)
		args = append(args, pid)
	}
	join := ""
	if strings.TrimSpace(projectID) != "" {
		join = ` JOIN "project_asset" pa ON pa."asset_id" = a."id"`
	}

	var out []CoverageAsset
	err := dbx.Select(&out,
		`SELECT a."id", a."address", a."type" FROM "asset" a`+join+`
		 WHERE `+strings.Join(where, " AND ")+` LIMIT 20`, args...)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return out, nil
}

// SelectAssetByID 读取单个资产，供血缘展示。
func SelectAssetByID(id string) (*CoverageAsset, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, sql.ErrNoRows
	}
	var out CoverageAsset
	if err := dbx.Get(&out,
		`SELECT "id", "address", "type" FROM "asset" WHERE "id" = ?`, id); err != nil {
		return nil, err
	}
	return &out, nil
}

// CoverageAsset 是参与「未覆盖资产」计算的最小资产信息。
type CoverageAsset struct {
	ID      string `db:"id" json:"id"`
	Address string `db:"address" json:"address"`
	Type    string `db:"type" json:"type"`
	// LastScanAt 为空表示从未主动扫描过；建议清单据此区分「没扫过」与「太久没扫」。
	LastScanAt string `db:"last_scan_at" json:"last_scan_at"`
}

// SelectAssetsForCoverage 返回可参与被动覆盖度比对的资产。
//
// 只取 url / hostport / domain / ip：cidr 与被动流量的 authority 无法一一对应，
// 把它们算成「未覆盖」只会制造假清单。归档资产不参与。
func SelectAssetsForCoverage(projectID string) ([]CoverageAsset, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	const types = `a."type" IN ('url','hostport','domain','ip') AND a."archived" = 0`
	var out []CoverageAsset
	var err error
	if strings.TrimSpace(projectID) == "" {
		err = dbx.Select(&out,
			`SELECT a."id", a."address", a."type", a."last_scan_at" FROM "asset" a WHERE `+types+` ORDER BY a."last_scan_at" DESC`)
	} else {
		err = dbx.Select(&out,
			`SELECT a."id", a."address", a."type", a."last_scan_at" FROM "asset" a
			 JOIN "project_asset" pa ON pa."asset_id" = a."id"
			 WHERE pa."project_id" = ? AND `+types+` ORDER BY a."last_scan_at" DESC`, projectID)
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return out, nil
}

// ensurePassiveCoverage 建表。与其它建表一致，重复执行安全。
func ensurePassiveCoverage() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := execBusyRetry(passiveCoverageDDL)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}
