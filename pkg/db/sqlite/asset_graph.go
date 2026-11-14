package sqlite

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// 资产图：只保存「程序可计算」的父子关系。
//
// 设计约束：关系全部由地址本身推导（URL → authority → IP → /24 网段），
// 不引入 DNS 解析、不引入公共后缀表。宁可少一层，也不制造需要人工纠错的关系。
//
// 边的方向固定为「父（更粗）→ 子（更细）」：
//   - authority → url       （kind=host）
//   - ip/domain → hostport  （kind=ip / host）
//   - ip/24     → ip        （kind=cidr）
//
// 因此「下游」= 更细的资产（穿透，例如从网段一路看到具体 URL），
// 「上游」= 归属反查（例如从一条 URL 找到它所在的 IP 与网段）。
const assetEdgeDDL = `CREATE TABLE IF NOT EXISTS "asset_edge" (
	"parent_id" TEXT NOT NULL DEFAULT '',
	"child_id" TEXT NOT NULL DEFAULT '',
	"kind" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT '',
	PRIMARY KEY ("parent_id", "child_id", "kind")
  );
  CREATE INDEX IF NOT EXISTS "idx_asset_edge_child"
	ON "asset_edge" ("child_id");
  CREATE INDEX IF NOT EXISTS "idx_asset_edge_parent"
	ON "asset_edge" ("parent_id");`

// AssetEdge 是资产图上的一条有向边（父 → 子）。
type AssetEdge struct {
	ParentID  string `db:"parent_id" json:"parent_id"`
	ChildID   string `db:"child_id" json:"child_id"`
	Kind      string `db:"kind" json:"kind"`
	CreatedAt string `db:"created_at" json:"created_at"`
}

// AssetNodeRow 是资产图上的一个节点（资产的最小展示字段）。
type AssetNodeRow struct {
	ID       string `db:"id" json:"id"`
	Address  string `db:"address" json:"address"`
	Type     string `db:"type" json:"type"`
	Source   string `db:"source" json:"source"`
	Starred  int    `db:"starred" json:"starred"`
	Archived int    `db:"archived" json:"archived"`
}

// AssetCoverageSummary 是某个主机节点上的被动覆盖汇总。
type AssetCoverageSummary struct {
	Host         string `db:"host" json:"host"`
	Detectors    int64  `db:"detectors" json:"detectors"`
	HitDetectors int64  `db:"hit_detectors" json:"hit_detectors"`
	Samples      int64  `db:"samples" json:"samples"`
	Errors       int64  `db:"errors" json:"errors"`
	// State 是节点级的归纳结论：任一检测器命中即 hit，其次 error / tested / skipped。
	State string `json:"state"`
}

// assetParent 是一个程序化推导出的上级节点。
type assetParent struct {
	Address string
	Type    string
	Kind    string
}

// ClassifyAssetAddress 判定归一化后地址的类型，供列表分组与图推导共用。
func ClassifyAssetAddress(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i > 0 {
		return "url"
	}
	if ip := net.ParseIP(s); ip != nil {
		return "ip"
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return "cidr"
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return "hostport"
	}
	return "domain"
}

// deriveAssetChain 返回从直接上级开始、逐级向上的父链（不含自身）。
//
// 最多向上 3 层（url → hostport → ip → cidr），足以覆盖当前支持的全部推导，
// 同时给异常输入一个硬上限。
func deriveAssetChain(addr, typ string) []assetParent {
	chain := make([]assetParent, 0, 3)
	currentAddr := strings.ToLower(strings.TrimSpace(addr))
	currentType := typ
	if currentAddr == "" {
		return chain
	}
	seen := map[string]struct{}{currentAddr: {}}
	for i := 0; i < 3; i++ {
		p, ok := directAssetParent(currentAddr, currentType)
		if !ok {
			break
		}
		if _, dup := seen[p.Address]; dup || p.Address == "" || p.Address == currentAddr {
			break
		}
		seen[p.Address] = struct{}{}
		chain = append(chain, p)
		currentAddr, currentType = p.Address, p.Type
	}
	return chain
}

// directAssetParent 计算一个资产的直接上级；无法推导时返回 false。
func directAssetParent(addr, typ string) (assetParent, bool) {
	switch typ {
	case "url":
		u, err := url.Parse(addr)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return assetParent{}, false
		}
		authority := strings.ToLower(u.Host)
		return assetParent{Address: authority, Type: ClassifyAssetAddress(authority), Kind: "host"}, true
	case "hostport":
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return assetParent{}, false
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if host == "" {
			return assetParent{}, false
		}
		if net.ParseIP(host) != nil {
			return assetParent{Address: host, Type: "ip", Kind: "ip"}, true
		}
		return assetParent{Address: host, Type: "domain", Kind: "host"}, true
	case "ip":
		ip := net.ParseIP(addr)
		if ip == nil {
			return assetParent{}, false
		}
		v4 := ip.To4()
		if v4 == nil {
			// IPv6 的「网段」默认值争议大（/64 与 /48 各有道理），宁可不推导。
			return assetParent{}, false
		}
		mask := net.CIDRMask(24, 32)
		cidr := (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String()
		return assetParent{Address: cidr, Type: "cidr", Kind: "cidr"}, true
	}
	return assetParent{}, false
}

// applyAssetGraph 在资产入库的同一个事务里补齐图上的父子边。
//
// 只写边、不写节点：父节点（authority / IP / 网段）未必是用户认可的资产，
// 把它们塞进资产表会让「资产总数 / 未整理」凭空膨胀。边的两端都是地址，
// 而资产 id 本身就是地址，因此缺失的节点可以在读取时按需合成。
// 与资产写入共用事务，保证不会出现写入一半的边集合。
func applyAssetGraph(ctx context.Context, tx assetTx, rows []AssetInput, now string) error {
	if len(rows) == 0 {
		return nil
	}

	edges := make([]AssetEdge, 0, len(rows)*2)
	seenEdge := make(map[string]struct{}, len(rows)*2)

	for _, r := range rows {
		child := r.Address
		for _, p := range deriveAssetChain(r.Address, r.Type) {
			key := p.Address + "|" + child + "|" + p.Kind
			if _, ok := seenEdge[key]; !ok {
				seenEdge[key] = struct{}{}
				edges = append(edges, AssetEdge{
					ParentID: p.Address, ChildID: child, Kind: p.Kind, CreatedAt: now,
				})
			}
			child = p.Address
		}
	}

	if len(edges) == 0 {
		return nil
	}

	const colsPerRow = 4
	for _, chunk := range chunkSlice(edges, assetInsertRows) {
		placeholders := make([]string, 0, len(chunk))
		args := make([]interface{}, 0, len(chunk)*colsPerRow)
		for _, e := range chunk {
			placeholders = append(placeholders, "(?,?,?,?)")
			args = append(args, e.ParentID, e.ChildID, e.Kind, e.CreatedAt)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO "asset_edge"("parent_id","child_id","kind","created_at")
			 VALUES `+strings.Join(placeholders, ","), args...); err != nil {
			return err
		}
	}
	return nil
}

// SelectAssetEdges 返回与给定节点直接相邻的全部边。
func SelectAssetEdges(ids []string) ([]AssetEdge, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(ids)
	if len(clean) == 0 {
		return []AssetEdge{}, nil
	}
	out := make([]AssetEdge, 0, len(clean)*2)
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk)*2)
		for _, id := range chunk {
			args = append(args, id)
		}
		for _, id := range chunk {
			args = append(args, id)
		}
		var rows []AssetEdge
		if err := dbx.Select(&rows,
			`SELECT "parent_id","child_id","kind","created_at" FROM "asset_edge"
			 WHERE "parent_id" IN (`+holders+`) OR "child_id" IN (`+holders+`)`, args...); err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// SelectAssetNodes 按 id 批量读取节点。
func SelectAssetNodes(ids []string) ([]AssetNodeRow, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(ids)
	out := make([]AssetNodeRow, 0, len(clean))
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		var rows []AssetNodeRow
		if err := dbx.Select(&rows,
			`SELECT "id","address","type","source","starred","archived" FROM "asset"
			 WHERE "id" IN (`+holders+`)`, args...); err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// SelectAssetCoverageByHosts 批量读取主机节点的覆盖汇总。
func SelectAssetCoverageByHosts(hosts []string) (map[string]AssetCoverageSummary, error) {
	out := make(map[string]AssetCoverageSummary)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(hosts)
	if len(clean) == 0 {
		return out, nil
	}

	type row struct {
		Host         string `db:"host"`
		Detectors    int64  `db:"detectors"`
		HitDetectors int64  `db:"hit_detectors"`
		Tested       int64  `db:"tested"`
		Samples      int64  `db:"samples"`
		Errors       int64  `db:"errors"`
	}
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, h := range chunk {
			args = append(args, h)
		}
		var rows []row
		if err := dbx.Select(&rows,
			`SELECT "host",
				COUNT(*) AS detectors,
				SUM(CASE WHEN hits > 0 THEN 1 ELSE 0 END) AS hit_detectors,
				SUM(CASE WHEN state = 'tested' THEN 1 ELSE 0 END) AS tested,
				SUM(samples) AS samples,
				SUM(errors) AS errors
			 FROM "passive_coverage" WHERE "host" IN (`+holders+`) GROUP BY "host"`, args...); err != nil {
			return out, err
		}
		for _, r := range rows {
			state := "skipped"
			switch {
			case r.HitDetectors > 0:
				state = "hit"
			case r.Errors > 0:
				state = "error"
			case r.Tested > 0:
				state = "tested"
			}
			out[r.Host] = AssetCoverageSummary{
				Host: r.Host, Detectors: r.Detectors, HitDetectors: r.HitDetectors,
				Samples: r.Samples, Errors: r.Errors, State: state,
			}
		}
	}
	return out, nil
}

// SelectPassiveFindingCountsByAsset 返回每个资产上已锚定的被动命中数。
func SelectPassiveFindingCountsByAsset(ids []string) (map[string]int64, error) {
	out := make(map[string]int64)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(ids)
	if len(clean) == 0 {
		return out, nil
	}
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		var rows []struct {
			AssetID string `db:"asset_id"`
			N       int64  `db:"n"`
		}
		if err := dbx.Select(&rows,
			`SELECT "asset_id", COUNT(*) AS n FROM "passive_finding"
			 WHERE "asset_id" IN (`+holders+`) GROUP BY "asset_id"`, args...); err != nil {
			return out, err
		}
		for _, r := range rows {
			out[r.AssetID] = r.N
		}
	}
	return out, nil
}

// normalizeIDList 去空白、去重、保持稳定顺序。
func normalizeIDList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// BackfillAssetGraph 为历史资产补建父子边。
//
// 老库里的资产是在图功能之前写入的，没有边。启动时补一次：只处理 URL /
// hostport / IP 三类（domain 与 cidr 没有上级，不会被误判成缺失）。
// 幂等：已有子边的资产会被跳过；带限量保护，剩余部分下次启动继续。
func BackfillAssetGraph(limit int) (int, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 2000
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rows []struct {
		Address string `db:"address"`
		Type    string `db:"type"`
	}
	if err := dbx.SelectContext(ctx, &rows,
		`SELECT "address","type" FROM "asset"
		 WHERE "archived" = 0 AND "type" IN ('url','hostport','ip')
		   AND "id" NOT IN (SELECT "child_id" FROM "asset_edge")
		 LIMIT ?`, limit); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	inputs := make([]AssetInput, 0, len(rows))
	for _, r := range rows {
		inputs = append(inputs, AssetInput{Address: r.Address, Type: r.Type})
	}

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := applyAssetGraph(ctx, tx, inputs, time.Now().Format(assetTimeLayout)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(inputs), nil
}

// ensureAssetEdge 建表，重复执行安全。
func ensureAssetEdge() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := execBusyRetry(assetEdgeDDL)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}
