package sqlite

import "testing"

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
	if err := UpsertLedgerStatus("poc-a", "http://a.example", "http://a.example/1", "confirmed", ""); err != nil {
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
