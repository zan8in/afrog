package sqlite

import (
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
)

// withAssetFixture 使用空的隔离库（只建表，不塞 result 数据）来测资产相关逻辑。
func withAssetFixture(t *testing.T) *sqlx.DB {
	t.Helper()
	db := newExportFixture(t)

	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
	return db
}

// TestSinkAssetsBatchCountsAndTrajectory 锁定批量沉淀的计数口径与扫描轨迹。
func TestSinkAssetsBatchCountsAndTrajectory(t *testing.T) {
	withAssetFixture(t)

	inputs := []AssetInput{
		{Address: "https://a.example", Type: "url"},
		{Address: "https://b.example", Type: "url"},
		{Address: "https://a.example", Type: "url"}, // 批内重复
		{Address: "   ", Type: "url"},               // 空地址
	}

	res, err := SinkAssets("t-1", "scan", "", inputs)
	if err != nil {
		t.Fatalf("SinkAssets: %v", err)
	}
	if res.Added != 2 || res.Existing != 1 || res.Invalid != 1 {
		t.Fatalf("首次沉淀 = %+v, want added=2 existing=1 invalid=1", res)
	}

	res2, err := SinkAssets("t-2", "scan", "", inputs)
	if err != nil {
		t.Fatalf("SinkAssets(第二次): %v", err)
	}
	if res2.Added != 0 || res2.Existing != 3 || res2.Invalid != 1 {
		t.Fatalf("再次沉淀 = %+v, want added=0 existing=3 invalid=1", res2)
	}

	page, err := ListAssets(AssetFilter{View: "all", PageSize: 10})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if page.Total != 2 {
		t.Fatalf("资产总数 = %d, want 2", page.Total)
	}
	for _, it := range page.Items {
		if it.ScanCount != 2 {
			t.Errorf("资产 %s scan_count = %d, want 2", it.ID, it.ScanCount)
		}
		if it.LastTaskID != "t-2" {
			t.Errorf("资产 %s last_task_id = %q, want t-2", it.ID, it.LastTaskID)
		}
		if it.LastScanAt == "" {
			t.Errorf("资产 %s 没有记录 last_scan_at", it.ID)
		}
	}

	var n int64
	if err := dbx.Get(&n, `SELECT COUNT(*) FROM scan_target`); err != nil {
		t.Fatalf("count scan_target: %v", err)
	}
	if n != 4 {
		t.Fatalf("scan_target 行数 = %d, want 4（2 个任务 × 2 个地址）", n)
	}
}

// TestArchivedViewSeesOnlyArchived 锁定「已归档」视图：默认视图看不到归档项，
// view=archived 只看得到归档项。否则用户归档后便无从找回（等于变相删除）。
func TestArchivedViewSeesOnlyArchived(t *testing.T) {
	withAssetFixture(t)

	if _, err := SinkAssets("t-1", "scan", "", []AssetInput{
		{Address: "https://keep.example", Type: "url"},
		{Address: "https://gone.example", Type: "url"},
	}); err != nil {
		t.Fatalf("SinkAssets: %v", err)
	}

	archived := true
	if _, err := UpdateAssets([]string{"https://gone.example"}, nil, nil, nil, &archived, nil); err != nil {
		t.Fatalf("UpdateAssets(archive): %v", err)
	}

	all, err := ListAssets(AssetFilter{View: "all", PageSize: 10})
	if err != nil {
		t.Fatalf("ListAssets(all): %v", err)
	}
	if all.Total != 1 || all.Items[0].Address != "https://keep.example" {
		t.Fatalf("默认视图应看不到归档项，got total=%d", all.Total)
	}
	if all.Stats.Archived != 1 {
		t.Fatalf("stats.archived = %d, want 1（前端「已归档」角标用它）", all.Stats.Archived)
	}

	arch, err := ListAssets(AssetFilter{View: "archived", PageSize: 10})
	if err != nil {
		t.Fatalf("ListAssets(archived): %v", err)
	}
	if arch.Total != 1 || arch.Items[0].Address != "https://gone.example" {
		t.Fatalf("已归档视图应只见归档项，got total=%d", arch.Total)
	}

	// 连同 id 取消归档后，已归档视图应为空
	keep := false
	if _, err := UpdateAssets([]string{"https://gone.example"}, nil, nil, nil, &keep, nil); err != nil {
		t.Fatalf("UpdateAssets(unarchive): %v", err)
	}
	back, err := ListAssets(AssetFilter{View: "archived", PageSize: 10})
	if err != nil {
		t.Fatalf("ListAssets(archived after unarchive): %v", err)
	}
	if back.Total != 0 {
		t.Fatalf("取消归档后已归档视图应为空，got %d", back.Total)
	}
}

// TestSinkAssetsLargeBatchKeepsCountsExact 大批量走的是分块多行插入，
// 计数必须仍然精确（1000 条会跨多个 chunk）。
func TestSinkAssetsLargeBatchKeepsCountsExact(t *testing.T) {
	withAssetFixture(t)

	const total = 1000
	inputs := make([]AssetInput, 0, total)
	for i := 0; i < total; i++ {
		inputs = append(inputs, AssetInput{
			Address: fmt.Sprintf("https://h-%04d.example", i),
			Type:    "url",
		})
	}

	res, err := SinkAssets("t-big", "scan", "", inputs)
	if err != nil {
		t.Fatalf("SinkAssets: %v", err)
	}
	if res.Added != total || res.Existing != 0 || res.Invalid != 0 {
		t.Fatalf("大批量沉淀 = %+v, want added=%d", res, total)
	}

	n, err := CountAssets()
	if err != nil {
		t.Fatalf("CountAssets: %v", err)
	}
	if n != total {
		t.Fatalf("资产总数 = %d, want %d", n, total)
	}

	var st int64
	if err := dbx.Get(&st, `SELECT COUNT(*) FROM scan_target WHERE taskid = ?`, "t-big"); err != nil {
		t.Fatalf("count scan_target: %v", err)
	}
	if st != total {
		t.Fatalf("scan_target 行数 = %d, want %d", st, total)
	}
}

// TestMergeAssetTagsAppendsWithoutLosingExisting 批量追加标签是「合并」而不是覆盖。
func TestMergeAssetTagsAppendsWithoutLosingExisting(t *testing.T) {
	withAssetFixture(t)

	if _, err := CreateAssets("manual", "", []string{"现有"},
		[]AssetInput{{Address: "https://a.example", Type: "url"}}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}
	if _, err := CreateAssets("manual", "", []string{"新增"},
		[]AssetInput{{Address: "https://a.example", Type: "url"}}); err != nil {
		t.Fatalf("CreateAssets(追加): %v", err)
	}

	page, err := ListAssets(AssetFilter{View: "all", PageSize: 10})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("资产数 = %d, want 1", len(page.Items))
	}
	got := map[string]bool{}
	for _, tag := range page.Items[0].Tags {
		got[tag] = true
	}
	if len(page.Items[0].Tags) != 2 || !got["现有"] || !got["新增"] {
		t.Fatalf("tags = %v, want 现有 + 新增", page.Items[0].Tags)
	}
}

// TestDeleteAssetsCascadesProjectMembership 删除资产必须连带清掉项目成员与扫描轨迹。
func TestDeleteAssetsCascadesProjectMembership(t *testing.T) {
	withAssetFixture(t)

	if _, err := CreateAssets("manual", "", nil, []AssetInput{
		{Address: "https://a.example", Type: "url"},
		{Address: "https://b.example", Type: "url"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}
	if _, err := ReplaceProjectAssets("p-1", []string{"https://a.example", "https://b.example"}); err != nil {
		t.Fatalf("ReplaceProjectAssets: %v", err)
	}
	if n, err := CountProjectAssets("p-1"); err != nil || n != 2 {
		t.Fatalf("成员数 = %d, %v; want 2", n, err)
	}

	if _, err := DeleteAssets([]string{"https://a.example"}); err != nil {
		t.Fatalf("DeleteAssets: %v", err)
	}

	if n, err := CountProjectAssets("p-1"); err != nil || n != 1 {
		t.Fatalf("删除后成员数 = %d, %v; want 1", n, err)
	}
	var orphans int64
	if err := dbx.Get(&orphans,
		`SELECT COUNT(*) FROM project_asset WHERE asset_id = 'https://a.example'`); err != nil {
		t.Fatalf("count orphan: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("仍残留 %d 条指向已删除资产的成员关系", orphans)
	}
}
