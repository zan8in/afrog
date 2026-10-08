package web

import (
	"testing"
	"time"
)

// 「剩余 N 天」必须向上取整：刚激活时还剩 29 天 23 小时，截断成 29 会让用户以为授权少了一天。
func TestRemainingDaysRoundsUp(t *testing.T) {
	now := time.Date(2026, 10, 8, 19, 30, 0, 0, time.UTC)

	cases := []struct {
		name string
		exp  time.Time
		want int
	}{
		{"刚激活（还剩 29 天 23 小时）", now.Add(29*24*time.Hour + 23*time.Hour), 30},
		{"还剩 29 天整", now.Add(29 * 24 * time.Hour), 29},
		{"还剩 2 小时", now.Add(2 * time.Hour), 1},
		{"还剩 1 分钟", now.Add(time.Minute), 1},
		{"刚过期", now.Add(-time.Minute), 0},
	}

	for _, c := range cases {
		if got := remainingDays(c.exp, now); got != c.want {
			t.Errorf("%s: remainingDays = %d, want %d", c.name, got, c.want)
		}
	}
}
