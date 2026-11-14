package sqlite

import (
	"fmt"
	"time"
)

// 覆盖度空洞：该主机上所有已记录的检测器都只产生过 skipped，从未真正执行过。
//
// 与「未被覆盖」（连一条记录都没有）是两类问题：这里是有流量、但每个检测器都
// 因参数/响应/范围被挡在门外，通常意味着使用者该检查参数化或扫描范围。
func SelectCoverageGapHosts(limit int) ([]string, int64, error) {
	if dbx == nil {
		return nil, 0, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 20
	}

	const gapCond = `SELECT "host" FROM "passive_coverage"
		GROUP BY "host"
		HAVING SUM(CASE WHEN "state" IN ('hit','tested','error') THEN 1 ELSE 0 END) = 0`

	var total int64
	if err := dbx.Get(&total, `SELECT COUNT(*) FROM (`+gapCond+`)`); err != nil {
		return nil, 0, err
	}

	var hosts []string
	if err := dbx.Select(&hosts, gapCond+` ORDER BY "host" LIMIT ?`, limit); err != nil {
		return nil, 0, err
	}
	if hosts == nil {
		hosts = []string{}
	}
	return hosts, total, nil
}

// SelectStaleAssets 返回超过指定天数没有扫描过的资产。
//
// 只统计「扫过」的资产：last_scan_at 为空说明从未扫描，那属于「未覆盖」范畴，
// 两边都报会让建议清单重复。
func SelectStaleAssets(days, limit int) ([]CoverageAsset, int64, error) {
	if dbx == nil {
		return nil, 0, fmt.Errorf("sqlite not initialized")
	}
	if days <= 0 {
		days = 30
	}
	if limit <= 0 {
		limit = 20
	}
	cutoff := time.Now().AddDate(0, 0, -days).Format(assetTimeLayout)

	const cond = `"archived" = 0 AND "last_scan_at" <> '' AND "last_scan_at" < ?`
	var total int64
	if err := dbx.Get(&total, `SELECT COUNT(*) FROM "asset" WHERE `+cond, cutoff); err != nil {
		return nil, 0, err
	}

	items := make([]CoverageAsset, 0, limit)
	if err := dbx.Select(&items,
		`SELECT "id","address","type" FROM "asset" WHERE `+cond+`
		 ORDER BY "last_scan_at" ASC LIMIT ?`, cutoff, limit); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// PassiveFindingBrief 是建议清单里展示的命中摘要。
type PassiveFindingBrief struct {
	ID       int64  `db:"id" json:"id"`
	Target   string `db:"target" json:"target"`
	Title    string `db:"title" json:"title"`
	Detector string `db:"detector" json:"detector"`
}

// SelectUnpromotedPassiveFindings 返回尚未进入台账、且未被人工标记为已修复的被动命中。
//
// 这类命中已经过了零误报门控，留在被动面板里不进入报告等于白发现。
func SelectUnpromotedPassiveFindings(limit int) ([]PassiveFindingBrief, int64, error) {
	if dbx == nil {
		return nil, 0, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 20
	}

	const cond = `"promoted" = 0 AND "state" <> 'fixed'`
	var total int64
	if err := dbx.Get(&total, `SELECT COUNT(*) FROM "passive_finding" WHERE `+cond); err != nil {
		return nil, 0, err
	}

	items := make([]PassiveFindingBrief, 0, limit)
	if err := dbx.Select(&items,
		`SELECT "id","target","title","detector" FROM "passive_finding" WHERE `+cond+`
		 ORDER BY "last_seen" DESC LIMIT ?`, limit); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
