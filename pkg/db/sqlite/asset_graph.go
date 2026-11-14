package sqlite

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/ref"
)

// 资产图：只保存「程序可计算」的父子关系。
//
// 设计约束：关系全部由地址本身推导（URL → authority → IP → /24 网段），
// 不引入 DNS 解析、不引入公共后缀表。宁可少一层，也不制造需要人工纠错的关系。
//
// 边的方向固定为「父（更粗）→ 子（更细）」：
//   - authority → url / endpoint （kind=host / service）
//   - endpoint  → param         （kind=param）
//   - ip/domain → hostport      （kind=ip / host）
//   - ip/24     → ip            （kind=cidr）
//
// 因此「下游」= 更细的资产（穿透，例如从网段一路看到具体参数），
// 「上游」= 归属反查（例如从一条 URL 找到它所在的 IP 与网段）。
//
// endpoint / param 只写边、不写 asset 行：它们是扫描或被动流量里「看到过」的地址，
// 不是用户认可的扫描目标；落进资产表会把「资产总数 / 未整理」撑成噪声。读取时按
// 地址合成节点，与 authority / IP 等推导节点的处理方式一致。
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

// paramAssetSep 分隔端点与其参数：http://a.example/login#query:user。
//
// 用 '#' 而不是新列：参数节点不是资产行，id 就是地址本身；而 '#' 在归一化
// 端点里本来就会被丢掉，不会与真实 URL 冲突。
const paramAssetSep = "#"

// paramLocationPrefixes 是「这是一个可注入参数」的位置前缀（与 passive.ParamLocation 对齐）。
//
// 只有这些前缀才建参数节点：misconfig 的 cookie-secure:sid、fingerprint 的 response
// 是规则名而不是参数，混进图里会污染「端点有哪些参数」这一层事实。
var paramLocationPrefixes = map[string]struct{}{
	"query": {}, "body": {}, "cookie": {}, "header": {},
	"json": {}, "path": {}, "xml": {}, "multipart": {},
}

// ParamAssetID 把端点与参数位置拼成参数节点 id；位置不是可注入参数时返回 false。
func ParamAssetID(endpoint, location string) (string, bool) {
	location = strings.TrimSpace(location)
	i := strings.Index(location, ":")
	if i <= 0 || i == len(location)-1 {
		return "", false
	}
	if _, ok := paramLocationPrefixes[strings.ToLower(location[:i])]; !ok {
		return "", false
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.Contains(endpoint, paramAssetSep) {
		return "", false
	}
	return endpoint + paramAssetSep + location, true
}

// SplitParamAssetID 拆出参数节点 id 的端点部分；不是参数节点时返回 false。
func SplitParamAssetID(id string) (endpoint, location string, ok bool) {
	i := strings.LastIndex(id, paramAssetSep)
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	endpoint, location = id[:i], id[i+1:]
	if _, valid := ParamAssetID(endpoint, location); !valid {
		return "", "", false
	}
	return endpoint, location, true
}

// techAssetPrefix / pocAssetPrefix 是推导节点的地址前缀。
//
// 技术栈与 PoC 没有网络地址，但需要在图里作为「端点 → 技术栈 → 候选 PoC」的一环。
// 用前缀把它们与真实地址区分开：这两类节点永远只在边里出现，读取时按地址合成，
// 不会进入资产表。
const (
	techAssetPrefix = "tech:"
	pocAssetPrefix  = "poc:"
)

// TechAssetID 返回技术栈节点 id；名字为空时返回空串。
func TechAssetID(name string) string {
	name = strings.ToLower(strings.Join(strings.Fields(name), " "))
	if name == "" {
		return ""
	}
	return techAssetPrefix + name
}

// PocAssetID 返回 PoC 节点 id；id 为空时返回空串。
func PocAssetID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return pocAssetPrefix + id
}

// ClassifyAssetAddress 判定归一化后地址的类型，供列表分组与图推导共用。
func ClassifyAssetAddress(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	// 必须在 hostport 判断之前：net.SplitHostPort("tech:php") 也会成功。
	if strings.HasPrefix(lower, techAssetPrefix) {
		return "tech"
	}
	if strings.HasPrefix(lower, pocAssetPrefix) {
		return "poc"
	}
	if _, _, ok := SplitParamAssetID(s); ok {
		return "param"
	}
	if i := strings.Index(s, "://"); i > 0 {
		u, err := url.Parse(s)
		if err == nil && (strings.Trim(u.Path, "/") != "" || u.RawQuery != "") {
			return "endpoint"
		}
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
		return urlAuthorityParent(addr, "host")
	case "endpoint":
		return urlAuthorityParent(addr, "service")
	case "param":
		endpoint, _, ok := SplitParamAssetID(addr)
		if !ok {
			return assetParent{}, false
		}
		return assetParent{Address: endpoint, Type: ClassifyAssetAddress(endpoint), Kind: "param"}, true
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

// urlAuthorityParent 返回 URL（含端点）所在的 authority 节点；kind 区分种子 URL 与端点。
func urlAuthorityParent(addr, kind string) (assetParent, bool) {
	u, err := url.Parse(addr)
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return assetParent{}, false
	}
	authority := strings.ToLower(u.Host)
	return assetParent{Address: authority, Type: ClassifyAssetAddress(authority), Kind: kind}, true
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
	return insertAssetEdges(ctx, tx, edges)
}

// insertAssetEdges 批量写边；重复边由主键忽略。
func insertAssetEdges(ctx context.Context, tx assetTx, edges []AssetEdge) error {
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

// EnsureEndpointGraph 记录「端点 → 参数」的观测边，不写资产节点。
//
// 触发点是「看到了一个 URL」：被动命中、Web 探测、Agent 主动探测。target 不是
// 绝对 URL 时静默跳过——观测事实不完整不该阻断调用方的主流程。
// 根路径 URL 不入图：它已经由资产行（type=url）表达，重复建点没有增量信息。
func EnsureEndpointGraph(target, location string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	endpoint, err := ref.NormalizeEndpoint(target)
	if err != nil {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || strings.Trim(u.Path, "/") == "" {
		return nil
	}
	parent, ok := urlAuthorityParent(endpoint, "service")
	if !ok {
		return nil
	}

	now := time.Now().Format(assetTimeLayout)
	edges := []AssetEdge{{
		ParentID: parent.Address, ChildID: endpoint, Kind: "service", CreatedAt: now,
	}}
	if paramID, ok := ParamAssetID(endpoint, location); ok {
		edges = append(edges, AssetEdge{
			ParentID: endpoint, ChildID: paramID, Kind: "param", CreatedAt: now,
		})
	}
	return insertAssetEdges(context.Background(), dbx, edges)
}

// EnsureTechGraph 记录「端点 → 技术栈 → 候选 PoC」的推导边，不写资产节点。
//
// candidates 是技术名到 PoC id 的映射，由调用方按 PoC 索引（info.requires）算出：
// sqlite 不解析 PoC，只负责把关系落成边。候选是有依据的线索而不是结论——它回答
// 「这个技术栈有哪些现成 PoC 值得试」，判定仍发生在 verify 阶段。
func EnsureTechGraph(endpoint string, techs []string, candidates map[string][]string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	endpoint, err := ref.NormalizeEndpoint(endpoint)
	if err != nil {
		return nil
	}

	now := time.Now().Format(assetTimeLayout)
	edges := make([]AssetEdge, 0, len(techs)*2)
	seen := make(map[string]struct{}, len(techs)*2)
	add := func(parent, child, kind string) {
		if parent == "" || child == "" {
			return
		}
		key := parent + "|" + child + "|" + kind
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		edges = append(edges, AssetEdge{ParentID: parent, ChildID: child, Kind: kind, CreatedAt: now})
	}

	for _, name := range techs {
		techID := TechAssetID(name)
		if techID == "" {
			continue
		}
		add(endpoint, techID, "tech")
		for _, pocID := range candidates[name] {
			add(techID, PocAssetID(pocID), "candidate")
		}
	}
	if len(edges) == 0 {
		return nil
	}
	return insertAssetEdges(context.Background(), dbx, edges)
}

// TrimTechAssetID 把技术栈推导节点 id 还原成名字；不是技术栈节点时返回空串。
func TrimTechAssetID(id string) string {
	trimmed, ok := trimAssetPrefix(id, techAssetPrefix)
	if !ok {
		return ""
	}
	return trimmed
}

// TrimPocAssetID 把 PoC 推导节点 id 还原成 poc id；不是 PoC 节点时返回空串。
func TrimPocAssetID(id string) string {
	trimmed, ok := trimAssetPrefix(id, pocAssetPrefix)
	if !ok {
		return ""
	}
	return trimmed
}

func trimAssetPrefix(id, prefix string) (string, bool) {
	id = strings.TrimSpace(id)
	if len(id) <= len(prefix) || !strings.HasPrefix(strings.ToLower(id), prefix) {
		return "", false
	}
	return id[len(prefix):], true
}

// TechCandidate 是「端点 → 技术栈 → 候选 PoC」连接出的一条线索。
type TechCandidate struct {
	Endpoint string `db:"endpoint"`
	Tech     string `db:"tech"`
	PocID    string `db:"poc_id"`
}

// SelectTechCandidates 读取图上已有的候选线索三元组。
//
// root 为空表示全库；under 为 true 时按 URL 前缀匹配（「这台主机下的所有端点」），
// 否则要求端点完全相等。只返回已经识别出技术栈的端点——候选 PoC 的前提就是这个
// 技术栈被真实观测到过。
func SelectTechCandidates(root string, under bool) ([]TechCandidate, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	query := `SELECT e1."parent_id" AS endpoint, e1."child_id" AS tech, e2."child_id" AS poc_id
		FROM "asset_edge" e1
		JOIN "asset_edge" e2 ON e2."parent_id" = e1."child_id" AND e2."kind" = 'candidate'
		WHERE e1."kind" = 'tech'`
	args := make([]interface{}, 0, 1)
	root = strings.TrimSpace(root)
	if root != "" {
		escaped := escapeLike(strings.TrimRight(root, "/"))
		query += ` AND (e1."parent_id" = ?`
		args = append(args, root)
		if under {
			query += ` OR e1."parent_id" LIKE ? ESCAPE '\')`
			args = append(args, escaped+"/%")
		} else {
			query += `)`
		}
	}

	var rows []TechCandidate
	if err := dbx.Select(&rows, query, args...); err != nil {
		return nil, err
	}
	return rows, nil
}

// SelectEndpointsWithoutTech 返回图上存在、但还没有技术栈边的端点。
//
// 这是「未知面」：确认过它在（被动流量或探测看到过），却还没识别出任何技术栈。
// 端点来自 kind=service 的边——与 EnsureEndpointGraph 的写入口径一致。
func SelectEndpointsWithoutTech(root string, under bool) ([]string, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	query := `SELECT DISTINCT e."child_id"
		FROM "asset_edge" e
		WHERE e."kind" = 'service'
		  AND NOT EXISTS (
			SELECT 1 FROM "asset_edge" t
			WHERE t."parent_id" = e."child_id" AND t."kind" = 'tech')`
	args := make([]interface{}, 0, 1)
	root = strings.TrimSpace(root)
	if root != "" {
		escaped := escapeLike(strings.TrimRight(root, "/"))
		query += ` AND (e."child_id" = ?`
		args = append(args, root)
		if under {
			query += ` OR e."child_id" LIKE ? ESCAPE '\')`
			args = append(args, escaped+"/%")
		} else {
			query += `)`
		}
	}

	var rows []string
	if err := dbx.Select(&rows, query, args...); err != nil {
		return nil, err
	}
	return rows, nil
}

// SelectTechEndpoints 返回已经识别出技术栈的端点（kind=tech 边的父节点）。
//
// 与 SelectEndpointsWithoutTech 一起，用于判断「这台主机整体是否已经指纹过」：
// 同一 origin 下只要有一个端点识别出了技术栈，就不必再对整个 origin 重复指纹。
func SelectTechEndpoints(root string, under bool) ([]string, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	query := `SELECT DISTINCT e."parent_id"
		FROM "asset_edge" e
		WHERE e."kind" = 'tech'`
	args := make([]interface{}, 0, 1)
	root = strings.TrimSpace(root)
	if root != "" {
		escaped := escapeLike(strings.TrimRight(root, "/"))
		query += ` AND (e."parent_id" = ?`
		args = append(args, root)
		if under {
			query += ` OR e."parent_id" LIKE ? ESCAPE '\')`
			args = append(args, escaped+"/%")
		} else {
			query += `)`
		}
	}

	var rows []string
	if err := dbx.Select(&rows, query, args...); err != nil {
		return nil, err
	}
	return rows, nil
}

// FindingOverlap 是一条「已经有结论」的命中记录（PoC + 被命中的完整目标）。
type FindingOverlap struct {
	PocID      string `db:"vulid"`
	FullTarget string `db:"fulltarget"`
}

// SelectFindingOverlaps 读取这批 PoC 在历史上已经产生过命中的目标。
//
// 用途是「不要重复提议已经确认过的组合」：结果行是既有事实，规划器只读它，
// 不推断漏洞状态（状态归台账管）。projectID 为空表示跨项目口径——与台账一致，
// 项目归属经 task_project 由任务推导。
func SelectFindingOverlaps(pocIDs []string, projectID string) ([]FindingOverlap, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(pocIDs)
	if len(clean) == 0 {
		return nil, nil
	}
	projectID = strings.TrimSpace(projectID)

	out := make([]FindingOverlap, 0, len(clean))
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		args := make([]interface{}, 0, len(chunk)+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		query := `SELECT DISTINCT r."vulid", r."fulltarget" FROM "result" r`
		if projectID != "" {
			query += ` JOIN "task_project" tp ON tp."taskid" = r."taskid"`
		}
		query += ` WHERE r."vulid" IN (` + placeholders(len(chunk)) + `)`
		if projectID != "" {
			query += ` AND tp."project_id" = ?`
			args = append(args, projectID)
		}
		var rows []FindingOverlap
		if err := dbx.Select(&rows, query, args...); err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
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
	return SelectAssetCoverageByHostsScoped(hosts, "")
}

// SelectAssetCoverageByHostsScoped 按项目口径读取主机覆盖汇总。
// projectID 为空表示跨项目的全局口径。
func SelectAssetCoverageByHostsScoped(hosts []string, projectID string) (map[string]AssetCoverageSummary, error) {
	out := make(map[string]AssetCoverageSummary)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(hosts)
	if len(clean) == 0 {
		return out, nil
	}
	projectID = strings.TrimSpace(projectID)

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
		args := make([]interface{}, 0, len(chunk)+1)
		for _, h := range chunk {
			args = append(args, h)
		}
		filter := `"host" IN (` + holders + `)`
		if projectID != "" {
			filter += ` AND "project_id" = ?`
			args = append(args, projectID)
		}
		var rows []row
		if err := dbx.Select(&rows,
			`SELECT "host",
				COUNT(*) AS detectors,
				SUM(CASE WHEN hits > 0 THEN 1 ELSE 0 END) AS hit_detectors,
				SUM(CASE WHEN state = 'tested' THEN 1 ELSE 0 END) AS tested,
				SUM(samples) AS samples,
				SUM(errors) AS errors
			 FROM "passive_coverage" WHERE `+filter+` GROUP BY "host"`, args...); err != nil {
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
	return SelectPassiveFindingCountsByAssetScoped(ids, "")
}

// SelectPassiveFindingCountsByAssetScoped 按项目口径统计资产上的被动命中数。
func SelectPassiveFindingCountsByAssetScoped(ids []string, projectID string) (map[string]int64, error) {
	out := make(map[string]int64)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(ids)
	if len(clean) == 0 {
		return out, nil
	}
	projectID = strings.TrimSpace(projectID)

	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk)+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		filter := `"asset_id" IN (` + holders + `)`
		if projectID != "" {
			filter += ` AND "project_id" = ?`
			args = append(args, projectID)
		}
		var rows []struct {
			AssetID string `db:"asset_id"`
			N       int64  `db:"n"`
		}
		if err := dbx.Select(&rows,
			`SELECT "asset_id", COUNT(*) AS n FROM "passive_finding"
			 WHERE `+filter+` GROUP BY "asset_id"`, args...); err != nil {
			return out, err
		}
		for _, r := range rows {
			out[r.AssetID] = r.N
		}
	}
	return out, nil
}

// PassiveTargetCount 是一条被动命中按「目标 + 位置」聚合后的次数。
//
// 端点/参数不是资产行，命中数要按 target 归集：端点取归一化 URL，参数再叠加
// location。放在这里而不是 passive.go，是因为它只服务资产图的聚合口径。
type PassiveTargetCount struct {
	Target   string `db:"target"`
	Location string `db:"location"`
	Count    int64  `db:"n"`
}

// SelectPassiveTargetCountsScoped 读取一批资产上的命中分布（按 target/location 分组）。
//
// 用 asset_id 收口，避免为了构图扫全表：被动命中的血缘锚点本来就在主机资产上，
// 端点与参数是它们的下级。
func SelectPassiveTargetCountsScoped(assetIDs []string, projectID string) ([]PassiveTargetCount, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeIDList(assetIDs)
	if len(clean) == 0 {
		return nil, nil
	}
	projectID = strings.TrimSpace(projectID)

	out := make([]PassiveTargetCount, 0, len(clean))
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk)+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		filter := `"asset_id" IN (` + holders + `)`
		if projectID != "" {
			filter += ` AND "project_id" = ?`
			args = append(args, projectID)
		}
		var rows []PassiveTargetCount
		if err := dbx.Select(&rows,
			`SELECT "target","location",COUNT(*) AS n FROM "passive_finding"
			 WHERE `+filter+` GROUP BY "target","location"`, args...); err != nil {
			return nil, err
		}
		out = append(out, rows...)
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
// 老库里的资产是在图功能之前写入的，没有边。启动时补一次：只处理 URL / endpoint /
// hostport / IP 四类（domain 与 cidr 没有上级，不会被误判成缺失）。
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
		 WHERE "archived" = 0 AND "type" IN ('url','endpoint','hostport','ip')
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

// BackfillEndpointGraph 为历史被动命中补建「端点 → 参数」边。
//
// 端点图是随命中实时写的；老库里的历史命中没有这些边，启动时补一次。
// 幂等：已有边由主键忽略，重复启动不会产生新行；带限量保护，按最近命中优先。
func BackfillEndpointGraph(limit int) (int, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 2000
	}

	var rows []struct {
		Target   string `db:"target"`
		Location string `db:"location"`
	}
	if err := dbx.Select(&rows,
		`SELECT "target","location" FROM "passive_finding"
		 WHERE "target" LIKE '%://%'
		 GROUP BY "target","location"
		 ORDER BY MAX("last_seen") DESC, MAX("id") DESC LIMIT ?`, limit); err != nil {
		return 0, err
	}
	processed := 0
	for _, r := range rows {
		if err := EnsureEndpointGraph(r.Target, r.Location); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
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
