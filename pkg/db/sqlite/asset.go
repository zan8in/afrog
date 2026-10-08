package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
)

// -----------------------
// 资产（目标唯一真源）
// -----------------------
//
// 设计要点：
//   - 「资产」= 一个可扫描条目，address（归一化后）就是唯一键，没有第二份目标存储。
//   - 标签是分组方式（逗号分隔存储），不再有「集合/文件」这种容器概念。
//   - 目标进入资产的唯一入口是 upsert：扫描起跑时沉淀、手工新增时沉淀。
//     因此 last_scan_at / scan_count / scan_target 三个字段共同构成「扫过什么」的轨迹。
const assetDDL = `CREATE TABLE IF NOT EXISTS "asset" (
	"id" TEXT PRIMARY KEY,
	"address" TEXT NOT NULL DEFAULT '',
	"type" TEXT NOT NULL DEFAULT '',
	"tags" TEXT NOT NULL DEFAULT '',
	"source" TEXT NOT NULL DEFAULT '',
	"source_ref" TEXT NOT NULL DEFAULT '',
	"starred" INTEGER NOT NULL DEFAULT 0,
	"archived" INTEGER NOT NULL DEFAULT 0,
	"note" TEXT NOT NULL DEFAULT '',
	"first_seen_at" TEXT NOT NULL DEFAULT '',
	"last_scan_at" TEXT NOT NULL DEFAULT '',
	"last_task_id" TEXT NOT NULL DEFAULT '',
	"scan_count" INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS "idx_asset_type"
	ON "asset" ("type");
  CREATE INDEX IF NOT EXISTS "idx_asset_archived"
	ON "asset" ("archived");
  CREATE INDEX IF NOT EXISTS "idx_asset_last_scan"
	ON "asset" ("last_scan_at");

  CREATE TABLE IF NOT EXISTS "scan_target" (
	"taskid" TEXT NOT NULL DEFAULT '',
	"address" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT '',
	PRIMARY KEY ("taskid", "address")
  );
  CREATE INDEX IF NOT EXISTS "idx_scan_target_address"
	ON "scan_target" ("address");

  CREATE TABLE IF NOT EXISTS "project_asset" (
	"project_id" TEXT NOT NULL DEFAULT '',
	"asset_id" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT '',
	PRIMARY KEY ("project_id", "asset_id")
  );
  CREATE INDEX IF NOT EXISTS "idx_project_asset_asset"
	ON "project_asset" ("asset_id");`

// assetTimeLayout 与 result.created 保持一致，避免跨时区比较出错。
const assetTimeLayout = "2006-01-02 15:04:05"

// AssetInput 是一条待入库的目标：地址必须在调用前完成归一化，类型也由调用方判定。
type AssetInput struct {
	Address string
	Type    string
}

// AssetSinkResult 是入库结果，用于给用户「新增 N · 已存在 M · 忽略 K」的明确反馈。
type AssetSinkResult struct {
	Added    int `json:"added"`
	Existing int `json:"existing"`
	Invalid  int `json:"invalid"`
}

// AssetFilter 是资产列表的筛选条件。
//
// View 决定看哪一片：
//   - ""（默认）：我的资产 —— 收藏 / 有标签 / 扫过的
//   - "unorganized"：未整理 —— 自动沉淀进来但还没被用户认领的
//   - "starred"：收藏
//   - "all"：全部（不含归档）
type AssetFilter struct {
	View            string
	Keyword         string
	Tags            []string
	Type            string
	Source          string
	StaleDays       int
	IncludeArchived bool
	Page            int
	PageSize        int
}

// AssetPage 是资产分页结果，附带各视图数量，供左侧筛选直接展示。
type AssetPage struct {
	Items    []db2.AssetRow `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Stats    AssetStats     `json:"stats"`
}

// AssetStats 是各视图的数量分布。
type AssetStats struct {
	Total       int64 `db:"total" json:"total"`
	Mine        int64 `db:"mine" json:"mine"`
	Unorganized int64 `db:"unorganized" json:"unorganized"`
	Starred     int64 `db:"starred" json:"starred"`
	Archived    int64 `db:"archived" json:"archived"`
}

// AssetFacetItem 是筛选项及其数量。
type AssetFacetItem struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// AssetFacets 是筛选器可选项（标签 / 类型 / 来源）。
type AssetFacets struct {
	Tags    []AssetFacetItem `json:"tags"`
	Types   []AssetFacetItem `json:"types"`
	Sources []AssetFacetItem `json:"sources"`
}

// assetUpsertOptions 收敛 upsert 的两种用法：扫描沉淀 vs 手工新增/导入。
type assetUpsertOptions struct {
	Source    string
	SourceRef string
	// Tags 是本次要附加的标签（手工新增/导入时用）。
	Tags []string
	// TaskID 非空表示这次入库来自一次扫描：会更新扫描轨迹并写 scan_target。
	TaskID string
	// AddTags 为真时把 Tags 合并进已存在的行（用户显式打标签的语义）。
	AddTags bool
}

// SinkAssets 把一次扫描的目标沉淀成资产，并记录该任务扫过哪些目标。
func SinkAssets(taskID, source, sourceRef string, inputs []AssetInput) (AssetSinkResult, error) {
	return upsertAssets(inputs, assetUpsertOptions{
		Source:    source,
		SourceRef: sourceRef,
		TaskID:    strings.TrimSpace(taskID),
	})
}

// CreateAssets 手工新增/导入资产：不写扫描轨迹，可附带标签。
func CreateAssets(source, sourceRef string, tags []string, inputs []AssetInput) (AssetSinkResult, error) {
	return upsertAssets(inputs, assetUpsertOptions{
		Source:    source,
		SourceRef: sourceRef,
		Tags:      tags,
		AddTags:   true,
	})
}

// upsertAssets 把一批目标写进资产表。
//
// 全程批量：先一次性查出哪些已存在，再用多行 INSERT 落库，扫描轨迹与标签追加也都
// 按块更新。目标是「一次扫描 1 万条目标」时语句数与目标数无关，而不是 1 万 × 3 条。
func upsertAssets(inputs []AssetInput, opts assetUpsertOptions) (AssetSinkResult, error) {
	out := AssetSinkResult{}
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}
	if len(inputs) == 0 {
		return out, nil
	}

	// 批内去重：重复项按「已存在」计数，保持与逐条插入时一致的语义。
	rows := make([]AssetInput, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		addr := strings.TrimSpace(in.Address)
		if addr == "" {
			out.Invalid++
			continue
		}
		if _, ok := seen[addr]; ok {
			out.Existing++
			continue
		}
		seen[addr] = struct{}{}
		rows = append(rows, AssetInput{Address: addr, Type: strings.TrimSpace(in.Type)})
	}
	if len(rows) == 0 {
		return out, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	now := time.Now().Format(assetTimeLayout)
	tagsCSV := strings.Join(normalizeTagList(opts.Tags), ",")

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()

	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.Address)
	}
	existing, err := existingAssetIDsTx(ctx, tx, ids)
	if err != nil {
		return out, err
	}
	out.Added += len(rows) - len(existing)
	out.Existing += len(existing)

	// 新行批量落库；已存在的由 INSERT OR IGNORE 跳过，保留用户原有整理。
	if err := insertAssetRows(ctx, tx, rows, opts.Source, opts.SourceRef, tagsCSV, now); err != nil {
		return out, err
	}

	// 显式打标签只作用于已存在的行，避免覆盖用户自己的整理结果。
	if opts.AddTags && tagsCSV != "" && len(existing) > 0 {
		if err := mergeAssetTagsBatch(ctx, tx, existing, opts.Tags); err != nil {
			return out, err
		}
	}

	if opts.TaskID != "" {
		if err := touchScannedAssets(ctx, tx, ids, opts.TaskID, now); err != nil {
			return out, err
		}
	}

	return out, tx.Commit()
}

// insertAssetRows 多行批量插入；已存在的行由 INSERT OR IGNORE 跳过。
func insertAssetRows(ctx context.Context, tx assetTx, rows []AssetInput, source, sourceRef, tagsCSV, now string) error {
	const colsPerRow = 7
	for _, chunk := range chunkSlice(rows, assetInsertRows) {
		placeholders := make([]string, 0, len(chunk))
		args := make([]interface{}, 0, len(chunk)*colsPerRow)
		for _, r := range chunk {
			placeholders = append(placeholders, "(?,?,?,?,?,?,?)")
			args = append(args, r.Address, r.Address, r.Type, tagsCSV, source, sourceRef, now)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO asset(id, address, type, tags, source, source_ref, first_seen_at)
			 VALUES `+strings.Join(placeholders, ","), args...); err != nil {
			return err
		}
	}
	return nil
}

// existingAssetIDsTx 查出入参里已经存在于资产表的 id。
func existingAssetIDsTx(ctx context.Context, tx assetTx, ids []string) (map[string]struct{}, error) {
	exists := make(map[string]struct{}, len(ids))
	for _, chunk := range chunkSlice(ids, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		found := make([]string, 0, len(chunk))
		if err := tx.SelectContext(ctx, &found,
			`SELECT id FROM asset WHERE id IN (`+holders+`)`, args...); err != nil {
			return nil, err
		}
		for _, id := range found {
			exists[id] = struct{}{}
		}
	}
	return exists, nil
}

// mergeAssetTagsBatch 给已存在的资产追加标签。
//
// 先按块取回现有标签算出合并结果，再按「合并结果」分组批量写回：同一批里合并结果
// 相同的行只发一条 UPDATE（批量打同一个标签时通常只有少数几种结果）。
func mergeAssetTagsBatch(ctx context.Context, tx assetTx, existing map[string]struct{}, add []string) error {
	addList := normalizeTagList(add)
	if len(addList) == 0 || len(existing) == 0 {
		return nil
	}
	existingIDs := make([]string, 0, len(existing))
	for id := range existing {
		existingIDs = append(existingIDs, id)
	}

	groups := make(map[string][]string, 8)
	for _, chunk := range chunkSlice(existingIDs, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		rows := make([]struct {
			ID   string `db:"id"`
			Tags string `db:"tags"`
		}, 0, len(chunk))
		if err := tx.SelectContext(ctx, &rows,
			`SELECT id, tags FROM asset WHERE id IN (`+holders+`)`, args...); err != nil {
			return err
		}
		for _, r := range rows {
			merged := strings.Join(normalizeTagList(append(splitTagCSV(r.Tags), addList...)), ",")
			if merged == r.Tags {
				continue
			}
			groups[merged] = append(groups[merged], r.ID)
		}
	}

	for merged, groupIDs := range groups {
		for _, chunk := range chunkSlice(groupIDs, idChunkSize) {
			holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
			args := make([]interface{}, 0, len(chunk)+1)
			args = append(args, merged)
			for _, id := range chunk {
				args = append(args, id)
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE asset SET tags = ? WHERE id IN (`+holders+`)`, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

// touchScannedAssets 批量记一次「这些资产被这个任务扫过」。
func touchScannedAssets(ctx context.Context, tx assetTx, ids []string, taskID, now string) error {
	for _, chunk := range chunkSlice(ids, idChunkSize) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk)+2)
		args = append(args, now, taskID)
		for _, id := range chunk {
			args = append(args, id)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE asset SET last_scan_at = ?, last_task_id = ?, scan_count = scan_count + 1
			  WHERE id IN (`+holders+`)`, args...); err != nil {
			return err
		}

		placeholders := make([]string, 0, len(chunk))
		targs := make([]interface{}, 0, len(chunk)*3)
		for _, id := range chunk {
			placeholders = append(placeholders, "(?,?,?)")
			targs = append(targs, taskID, id, now)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO scan_target(taskid, address, created_at) VALUES `+
				strings.Join(placeholders, ","), targs...); err != nil {
			return err
		}
	}
	return nil
}

// ListAssets 按筛选条件分页返回资产。
func ListAssets(f AssetFilter) (*AssetPage, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	where, args := assetConditions(f)
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := dbx.GetContext(ctx, &total,
		`SELECT COUNT(*) FROM asset`+whereSQL, args...); err != nil {
		return nil, err
	}

	stats, err := assetStats(ctx)
	if err != nil {
		return nil, err
	}

	page, pageSize := normalizePageArgs(f.Page, f.PageSize)
	rows := make([]db2.AssetRow, 0, pageSize)
	queryArgs := make([]interface{}, 0, len(args)+2)
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, pageSize, (page-1)*pageSize)
	// 扫过的排前面（按最近扫描倒序），没扫过的按入库时间兜底。
	err = dbx.SelectContext(ctx, &rows,
		`SELECT id, address, type, tags, source, source_ref, starred, archived, note,
		        first_seen_at, last_scan_at, last_task_id, scan_count
		   FROM asset`+whereSQL+
			` ORDER BY (last_scan_at = '') ASC, last_scan_at DESC, first_seen_at DESC
			  LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		tags := splitTagCSV(rows[i].TagsRaw)
		if tags == nil {
			// nil 切片会被序列化成 null；前端按数组使用会直接崩掉渲染，统一给空数组。
			tags = []string{}
		}
		rows[i].Tags = tags
	}

	return &AssetPage{
		Items:    rows,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Stats:    stats,
	}, nil
}

func assetConditions(f AssetFilter) ([]string, []interface{}) {
	where := make([]string, 0, 8)
	where = append(where, viewConditions(f)...)

	attrWhere, attrArgs := assetAttributeConditions(
		f.Keyword, f.Type, f.Source, f.Tags, f.StaleDays)
	return append(where, attrWhere...), attrArgs
}

// viewConditions 组装「归档 + 视图」这两个决定看哪一片的条件（无绑定参数）。
func viewConditions(f AssetFilter) []string {
	view := strings.TrimSpace(f.View)
	where := make([]string, 0, 2)
	// 「已归档」视图本身就是只看归档项，因此不再叠加 archived = 0。
	if !f.IncludeArchived && view != "archived" {
		where = append(where, "archived = 0")
	}
	switch view {
	case "all":
		// 不加视图条件
	case "archived":
		where = append(where, "archived = 1")
	case "starred":
		where = append(where, "starred = 1")
	case "unorganized":
		where = append(where, "NOT (starred = 1 OR tags <> '' OR last_scan_at <> '')")
	default: // 默认视图：收藏 / 有标签 / 扫过
		where = append(where, "(starred = 1 OR tags <> '' OR last_scan_at <> '')")
	}
	return where
}

// assetAttributeConditions 组装与「视图」无关的属性过滤（关键词/类型/来源/标签/未扫天数）。
func assetAttributeConditions(keyword, typeFilter, source string, tags []string, staleDays int) ([]string, []interface{}) {
	where := make([]string, 0, 5)
	args := make([]interface{}, 0, 5)

	if kw := strings.TrimSpace(keyword); kw != "" {
		where = append(where, "address LIKE ?")
		args = append(args, "%"+kw+"%")
	}
	if t := strings.TrimSpace(typeFilter); t != "" {
		where = append(where, "type = ?")
		args = append(args, t)
	}
	if s := strings.TrimSpace(source); s != "" {
		where = append(where, "source = ?")
		args = append(args, s)
	}
	// 标签按「整段匹配」比较，避免 prod 命中 production；大小写不敏感。
	for _, t := range normalizeTagList(tags) {
		where = append(where, "(',' || LOWER(tags) || ',') LIKE ?")
		args = append(args, "%,"+strings.ToLower(t)+",%")
	}
	if staleDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -staleDays).Format(assetTimeLayout)
		where = append(where, "(last_scan_at = '' OR last_scan_at < ?)")
		args = append(args, cutoff)
	}
	return where, args
}

func assetStats(ctx context.Context) (AssetStats, error) {
	var s AssetStats
	err := dbx.GetContext(ctx, &s, `SELECT
		COALESCE(SUM(CASE WHEN archived = 0 THEN 1 ELSE 0 END), 0) AS total,
		COALESCE(SUM(CASE WHEN archived = 0 AND (starred = 1 OR tags <> '' OR last_scan_at <> '') THEN 1 ELSE 0 END), 0) AS mine,
		COALESCE(SUM(CASE WHEN archived = 0 AND starred = 0 AND tags = '' AND last_scan_at = '' THEN 1 ELSE 0 END), 0) AS unorganized,
		COALESCE(SUM(CASE WHEN archived = 0 AND starred = 1 THEN 1 ELSE 0 END), 0) AS starred,
		COALESCE(SUM(CASE WHEN archived = 1 THEN 1 ELSE 0 END), 0) AS archived
	  FROM asset`)
	return s, err
}

// LoadAssetFacets 汇总筛选器可选项，按数量倒序。
func LoadAssetFacets() (*AssetFacets, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows := make([]db2.AssetRow, 0, 512)
	if err := dbx.SelectContext(ctx, &rows,
		`SELECT id, address, type, tags, source FROM asset WHERE archived = 0`); err != nil {
		return nil, err
	}

	tagCount := map[string]int64{}
	tagLabel := map[string]string{}
	typeCount := map[string]int64{}
	sourceCount := map[string]int64{}
	for _, r := range rows {
		for _, t := range splitTagCSV(r.TagsRaw) {
			key := strings.ToLower(t)
			if _, ok := tagLabel[key]; !ok {
				tagLabel[key] = t
			}
			tagCount[key]++
		}
		if r.Type != "" {
			typeCount[r.Type]++
		}
		if r.Source != "" {
			sourceCount[r.Source]++
		}
	}

	return &AssetFacets{
		Tags:    facetItemsWithLabel(tagCount, tagLabel),
		Types:   facetItems(typeCount),
		Sources: facetItems(sourceCount),
	}, nil
}

// UpdateAssets 批量改资产属性。starred/archived/note 传 nil 表示不改；
// 标签按增量合并/移除，避免覆盖用户在别处做的整理。
func UpdateAssets(ids []string, addTags, removeTags []string, starred, archived *bool, note *string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	add := normalizeTagList(addTags)
	remove := make(map[string]struct{}, len(removeTags))
	for _, t := range normalizeTagList(removeTags) {
		remove[strings.ToLower(t)] = struct{}{}
	}

	var affected int64
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}

		var current string
		if err := tx.GetContext(ctx, &current, `SELECT tags FROM asset WHERE id = ?`, id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return 0, err
		}

		next := make([]string, 0, len(add)+4)
		for _, t := range splitTagCSV(current) {
			if _, drop := remove[strings.ToLower(t)]; drop {
				continue
			}
			next = append(next, t)
		}
		next = normalizeTagList(append(next, add...))

		sets := []string{"tags = ?"}
		args := []interface{}{strings.Join(next, ",")}
		if starred != nil {
			sets = append(sets, "starred = ?")
			args = append(args, boolToInt(*starred))
		}
		if archived != nil {
			sets = append(sets, "archived = ?")
			args = append(args, boolToInt(*archived))
		}
		if note != nil {
			sets = append(sets, "note = ?")
			args = append(args, *note)
		}
		args = append(args, id)

		res, err := tx.ExecContext(ctx,
			`UPDATE asset SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		affected += n
	}

	return affected, tx.Commit()
}

// DeleteAssets 批量删除资产，同时清掉它们的扫描轨迹与项目引用，避免留下孤儿记录。
// 按块执行，删除上万条时不会因为 IN 里的占位符过多而失败。
func DeleteAssets(ids []string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeAssetIDList(ids)
	if len(clean) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	for _, chunk := range chunkSlice(clean, idChunkSize) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}

		// 项目引用必须跟着删除，否则会留下指向不存在资产的悬空引用。
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM project_asset WHERE asset_id IN (`+holders+`)`, args...); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM scan_target WHERE address IN (`+holders+`)`, args...); err != nil {
			return 0, err
		}
		res, err := tx.ExecContext(ctx,
			`DELETE FROM asset WHERE id IN (`+holders+`)`, args...)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, tx.Commit()
}

// CountAssets 返回资产总数（不含归档），供概览与角标使用。
func CountAssets() (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n, `SELECT COUNT(*) FROM asset WHERE archived = 0`)
	return n, err
}

// -----------------------
// 项目 ↔ 资产（引用关系）
// -----------------------
//
// 关系存在关联表 project_asset 里，而不是塞进 projects.json：一个项目可能引用上万条
// 资产，放进 JSON 会让「读项目列表」变成读几 MB 文本，批量增删也退化成 N 条语句。
// 因此批量动作一律下沉成 SQL，id 不逐条经过 Go，也从不回传给浏览器。

// idChunkSize 是「按 id 批量操作」的单批上限，避免撞 SQLite 的绑定参数上限
// （旧版编译默认 999，多列插入时更紧张）。
const idChunkSize = 200

// assetInsertRows 是单条多行 INSERT 的行数上限：7 列 × 100 行 = 700 个参数，留足余量。
const assetInsertRows = 100

// assetAddressRow 只取地址一列，避免用 []string 直接接 sqlx 查询结果。
type assetAddressRow struct {
	Address string `db:"address"`
}

// ReplaceProjectAssets 用给定 id 整体替换项目成员（保存项目、迁移旧数据都用它）。
// 入参需要是已经存在于资产表里的 id。
func ReplaceProjectAssets(projectID string, ids []string) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return 0, fmt.Errorf("project id is required")
	}
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeAssetIDList(ids)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := dbx.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM project_asset WHERE project_id = ?`, projectID); err != nil {
		return 0, err
	}
	now := time.Now().Format(assetTimeLayout)
	n, err := insertProjectAssetRows(ctx, tx, projectID, clean, now)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// AppendProjectAssets 把给定 id 追加进项目成员，已存在的引用保持不变。
//
// 与 ReplaceProjectAssets 的区别：后者是「保存项目」时的全量替换语义，
// 这里用于「把扫描发现批量加进项目」这类增量动作，不会动用户已有的成员。
func AppendProjectAssets(projectID string, ids []string) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return 0, fmt.Errorf("project id is required")
	}
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	clean := normalizeAssetIDList(ids)
	if len(clean) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	n, err := insertProjectAssetRows(ctx, dbx, projectID, clean, time.Now().Format(assetTimeLayout))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteProjectAssets 清空一个项目的全部成员（删除项目时调用）。
func DeleteProjectAssets(projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if dbx == nil || projectID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx,
		`DELETE FROM project_asset WHERE project_id = ?`, projectID)
	return err
}

// CountProjectAssets 返回项目的成员数。
func CountProjectAssets(projectID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM project_asset WHERE project_id = ?`, projectID)
	return n, err
}

// ProjectAssetAddresses 返回项目成员的可扫描地址（按加入顺序），供起扫与报告使用。
func ProjectAssetAddresses(projectID string) ([]string, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rows := make([]assetAddressRow, 0, 64)
	err := dbx.SelectContext(ctx, &rows,
		`SELECT a.address AS address FROM project_asset pa
		   JOIN asset a ON a.id = pa.asset_id
		  WHERE pa.project_id = ?
		  ORDER BY pa.created_at ASC, pa.rowid ASC`, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Address)
	}
	return out, nil
}

// ProjectAssetPreview 返回项目的前几条成员地址，供项目卡片预览。
func ProjectAssetPreview(projectID string, limit int) ([]string, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return []string{}, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows := make([]assetAddressRow, 0, limit)
	err := dbx.SelectContext(ctx, &rows,
		`SELECT a.address AS address FROM project_asset pa
		   JOIN asset a ON a.id = pa.asset_id
		  WHERE pa.project_id = ?
		  ORDER BY pa.created_at ASC, pa.rowid ASC
		  LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Address)
	}
	return out, nil
}

// insertProjectAssetRows 分批写入项目成员，返回新插入的行数。
func insertProjectAssetRows(ctx context.Context, tx assetTx, projectID string, ids []string, now string) (int64, error) {
	var total int64
	for _, chunk := range chunkSlice(ids, idChunkSize) {
		placeholders := make([]string, 0, len(chunk))
		args := make([]interface{}, 0, len(chunk)*3)
		for _, id := range chunk {
			placeholders = append(placeholders, "(?,?,?)")
			args = append(args, projectID, id, now)
		}
		res, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO project_asset(project_id, asset_id, created_at) VALUES `+
				strings.Join(placeholders, ","), args...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// assetTx 收敛批量读写需要的最小 sqlx 能力（*sqlx.Tx 与 *sqlx.DB 都满足）。
type assetTx interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	SelectContext(context.Context, interface{}, string, ...interface{}) error
}

// chunkSlice 把大列表切成小块，避免绑定参数超出 SQLite 上限。
func chunkSlice[T any](in []T, size int) [][]T {
	if size <= 0 {
		size = 1
	}
	out := make([][]T, 0, (len(in)+size-1)/size)
	for start := 0; start < len(in); start += size {
		end := start + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, in[start:end])
	}
	return out
}

// normalizeAssetIDList 去空白、丢弃空项、按序去重。
func normalizeAssetIDList(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// -----------------------
// 小工具
// -----------------------

// normalizeTagList 统一标签口径：去空白、按小写去重，但**保留用户输入的原始写法**
// （标签是给人看的，不该被系统改成全小写）。
func normalizeTagList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		for _, part := range strings.Split(raw, ",") {
			t := strings.TrimSpace(part)
			if t == "" {
				continue
			}
			key := strings.ToLower(t)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

func splitTagCSV(csv string) []string {
	csv = strings.Trim(strings.TrimSpace(csv), ",")
	if csv == "" {
		return nil
	}
	return normalizeTagList(strings.Split(csv, ","))
}

func facetItems(counts map[string]int64) []AssetFacetItem {
	items := make([]AssetFacetItem, 0, len(counts))
	for v, c := range counts {
		items = append(items, AssetFacetItem{Value: v, Count: c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Value < items[j].Value
	})
	return items
}

// facetItemsWithLabel 用于标签：计数按小写归并，展示用用户原始写法。
func facetItemsWithLabel(counts map[string]int64, labels map[string]string) []AssetFacetItem {
	items := make([]AssetFacetItem, 0, len(counts))
	for key, c := range counts {
		label := labels[key]
		if label == "" {
			label = key
		}
		items = append(items, AssetFacetItem{Value: label, Count: c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Value < items[j].Value
	})
	return items
}

func normalizePageArgs(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	return page, pageSize
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
