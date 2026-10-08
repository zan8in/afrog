package sqlite

import "testing"

// strPtr 是测试里构造 *string 的小工具：nil 表示「只改状态、保留备注」。
func strPtr(s string) *string { return &s }

// TestCountResultsSinceUsesHalfOpenBoundary 校验「今日新增」的边界：
// created 等于时间点要算在内，早一毫秒不算。
func TestCountResultsSinceUsesHalfOpenBoundary(t *testing.T) {
	withFixture(t)

	cases := []struct {
		since string
		want  int64
	}{
		{"2026-09-28 00:00:00", 5},
		{"2026-09-28 10:00:00", 5}, // 包含 10:00:00 本身
		{"2026-09-28 10:00:01", 4},
		{"2026-09-28 11:00:00", 3},
		{"2026-09-28 13:00:00", 1},
		{"2026-09-29 00:00:00", 0},
	}

	for _, c := range cases {
		got, err := CountResultsSince(c.since)
		if err != nil {
			t.Fatalf("CountResultsSince(%q): %v", c.since, err)
		}
		if got != c.want {
			t.Errorf("CountResultsSince(%q) = %d, want %d", c.since, got, c.want)
		}
	}
}

// TestCountLedgerPendingFollowsStatusOverlay 校验待确认数与台账页同一口径：
// 按 PoC + 目标 + 完整目标聚合后，再叠加人工状态。
func TestCountLedgerPendingFollowsStatusOverlay(t *testing.T) {
	withFixture(t)

	// 夹具里 4 个聚合单元，都没有人工状态记录，因此全部计入待确认。
	got, err := CountLedgerPending()
	if err != nil {
		t.Fatalf("CountLedgerPending: %v", err)
	}
	if got != 4 {
		t.Fatalf("pending = %d, want 4", got)
	}

	// 把其中一条标记为已确认，待确认数应减一。
	if err := UpsertLedgerStatus("poc-a", "http://a.example", "http://a.example/1", "confirmed", strPtr("")); err != nil {
		t.Fatalf("UpsertLedgerStatus: %v", err)
	}

	got, err = CountLedgerPending()
	if err != nil {
		t.Fatalf("CountLedgerPending after update: %v", err)
	}
	if got != 3 {
		t.Fatalf("pending = %d, want 3", got)
	}
}

// TestUpsertLedgerStatusNilNoteKeepsExistingNote 校验「只改状态」不再清空备注，
// 并确认报告详情查询能带回台账的人工状态与备注。
func TestUpsertLedgerStatusNilNoteKeepsExistingNote(t *testing.T) {
	withFixture(t)

	const (
		vulid      = "poc-a"
		target     = "http://a.example"
		fulltarget = "http://a.example/1"
		note       = "已手工确认的备注"
	)

	if err := UpsertLedgerStatus(vulid, target, fulltarget, "confirmed", strPtr(note)); err != nil {
		t.Fatalf("写入状态+备注失败: %v", err)
	}

	// 只改状态（note 传 nil）：备注必须原样保留。
	if err := UpsertLedgerStatus(vulid, target, fulltarget, "fixed", nil); err != nil {
		t.Fatalf("只改状态失败: %v", err)
	}

	// 报告详情应 LEFT JOIN 出该行的台账状态与备注（result id=1 对应上面的键）。
	row, err := GetByID("1", false, false)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if row.LedgerStatus != "fixed" {
		t.Fatalf("ledger_status = %q, want fixed", row.LedgerStatus)
	}
	if row.LedgerNote != note {
		t.Fatalf("nil note 应保留原备注：got %q, want %q", row.LedgerNote, note)
	}

	// 显式传值（含空串）仍应覆盖备注，语义与原来的 INSERT OR REPLACE 一致。
	if err := UpsertLedgerStatus(vulid, target, fulltarget, "false_positive", strPtr("")); err != nil {
		t.Fatalf("覆盖备注失败: %v", err)
	}
	after, err := GetByID("1", false, false)
	if err != nil {
		t.Fatalf("GetByID(覆盖后): %v", err)
	}
	if after.LedgerStatus != "false_positive" || after.LedgerNote != "" {
		t.Fatalf("显式空串应清空备注：status=%q note=%q", after.LedgerStatus, after.LedgerNote)
	}
}
