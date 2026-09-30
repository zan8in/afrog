package web

import (
	"testing"
	"time"
)

func TestParseClock(t *testing.T) {
	cases := []struct {
		in   string
		h, m int
		ok   bool
	}{
		{"09:00", 9, 0, true},
		{"9:5", 9, 5, true},
		{"23:59", 23, 59, true},
		{"24:00", 0, 0, false},
		{"09:60", 0, 0, false},
		{"", 0, 0, false},
		{"09", 0, 0, false},
		{"aa:bb", 0, 0, false},
	}
	for _, c := range cases {
		h, m, ok := parseClock(c.in)
		if ok != c.ok || (ok && (h != c.h || m != c.m)) {
			t.Fatalf("parseClock(%q) = (%d,%d,%v), want (%d,%d,%v)", c.in, h, m, ok, c.h, c.m, c.ok)
		}
	}
}

func TestNormalizeClock(t *testing.T) {
	if got := normalizeClock("9:5"); got != "09:05" {
		t.Fatalf("normalizeClock(9:5) = %q, want 09:05", got)
	}
	if got := normalizeClock("bogus"); got != "09:00" {
		t.Fatalf("normalizeClock(bogus) = %q, want 09:00", got)
	}
}

// 时间推算用固定时区构造基准点，避免本机时区影响断言。
func TestComputeNextRun(t *testing.T) {
	loc := time.Local
	base := time.Date(2026, 9, 30, 10, 30, 0, 0, loc) // 周三

	t.Run("hourly", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqHourly, IntervalHours: 6}, base)
		want := base.Add(6 * time.Hour)
		if !got.Equal(want) {
			t.Fatalf("hourly = %v, want %v", got, want)
		}
	})

	t.Run("hourly default interval", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqHourly}, base)
		if !got.Equal(base.Add(time.Hour)) {
			t.Fatalf("hourly default = %v, want %v", got, base.Add(time.Hour))
		}
	})

	t.Run("daily later today", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqDaily, AtTime: "23:00"}, base)
		want := time.Date(2026, 9, 30, 23, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("daily = %v, want %v", got, want)
		}
	})

	t.Run("daily rolls to tomorrow", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqDaily, AtTime: "08:00"}, base)
		want := time.Date(2026, 10, 1, 8, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("daily next = %v, want %v", got, want)
		}
	})

	t.Run("weekly same weekday later today", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqWeekly, AtTime: "20:00", Weekday: int(time.Wednesday)}, base)
		want := time.Date(2026, 9, 30, 20, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("weekly = %v, want %v", got, want)
		}
	})

	t.Run("weekly next Monday", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqWeekly, AtTime: "08:30", Weekday: int(time.Monday)}, base)
		want := time.Date(2026, 10, 5, 8, 30, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("weekly monday = %v, want %v", got, want)
		}
	})

	t.Run("weekly already passed rolls a week", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqWeekly, AtTime: "09:00", Weekday: int(time.Wednesday)}, base)
		want := time.Date(2026, 10, 7, 9, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("weekly roll = %v, want %v", got, want)
		}
	})
}

// normalizeSchedule 会按频率清掉无关字段，避免切换频率后残留脏数据。
func TestNormalizeSchedule(t *testing.T) {
	s := Schedule{Name: "  nightly  ", Freq: "WEEKLY", IntervalHours: 6, AtTime: "9:5", Weekday: 9}
	normalizeSchedule(&s)
	if s.Name != "nightly" {
		t.Fatalf("name = %q, want nightly", s.Name)
	}
	if s.IntervalHours != 0 {
		t.Fatalf("weekly interval_hours = %d, want 0", s.IntervalHours)
	}
	if s.AtTime != "09:05" {
		t.Fatalf("at_time = %q, want 09:05", s.AtTime)
	}
	if s.Weekday != 0 {
		t.Fatalf("weekday = %d, want 0 (非法值收敛)", s.Weekday)
	}
	if s.NextRunAt == "" {
		t.Fatal("next_run_at 应被计算出来")
	}

	h := Schedule{Freq: "hourly", IntervalHours: 0, AtTime: "08:00", Weekday: 3}
	normalizeSchedule(&h)
	if h.IntervalHours != 1 {
		t.Fatalf("hourly interval = %d, want 1", h.IntervalHours)
	}
	if h.AtTime != "" || h.Weekday != 0 {
		t.Fatalf("hourly 应清空 at_time/weekday, got %q/%d", h.AtTime, h.Weekday)
	}
}
