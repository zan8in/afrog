package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
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

	t.Run("monthly later today", func(t *testing.T) {
		// day_of_month 合法区间是 1-28，所以基准点取当月 28 日。
		sep28 := time.Date(2026, 9, 28, 10, 0, 0, 0, loc)
		got := computeNextRun(Schedule{Freq: freqMonthly, AtTime: "23:00", DayOfMonth: 28}, sep28)
		want := time.Date(2026, 9, 28, 23, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("monthly = %v, want %v", got, want)
		}
	})

	t.Run("monthly rolls to next month", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqMonthly, AtTime: "09:00", DayOfMonth: 15}, base)
		want := time.Date(2026, 10, 15, 9, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("monthly next = %v, want %v", got, want)
		}
	})

	t.Run("monthly rolls across year boundary", func(t *testing.T) {
		dec := time.Date(2026, 12, 20, 10, 0, 0, 0, loc)
		got := computeNextRun(Schedule{Freq: freqMonthly, AtTime: "09:00", DayOfMonth: 5}, dec)
		want := time.Date(2027, 1, 5, 9, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("monthly year roll = %v, want %v", got, want)
		}
	})

	t.Run("monthly clamps illegal day to 1", func(t *testing.T) {
		got := computeNextRun(Schedule{Freq: freqMonthly, AtTime: "09:00", DayOfMonth: 31}, base)
		want := time.Date(2026, 10, 1, 9, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("monthly clamp = %v, want %v", got, want)
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

	m := Schedule{Freq: "MONTHLY", IntervalHours: 6, AtTime: "8:0", Weekday: 3, DayOfMonth: 31}
	normalizeSchedule(&m)
	if m.IntervalHours != 0 || m.Weekday != 0 {
		t.Fatalf("monthly 应清空 interval_hours/weekday, got %d/%d", m.IntervalHours, m.Weekday)
	}
	if m.AtTime != "08:00" {
		t.Fatalf("monthly at_time = %q, want 08:00", m.AtTime)
	}
	if m.DayOfMonth != 1 {
		t.Fatalf("monthly day_of_month = %d, want 1 (31 收敛到 1)", m.DayOfMonth)
	}
}

// scheduleSaveBody 组装一条计划的保存请求体。
func scheduleSaveBody(name, nodeURL string, targets []string) string {
	body := map[string]any{
		"name": name,
		"freq": freqHourly,
		"scan": map[string]any{"targets": targets},
	}
	if nodeURL != "" {
		body["node_url"] = nodeURL
	}
	b, _ := json.Marshal(body)
	return string(b)
}

func postSchedule(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	schedulesSaveHandler(rec, httptest.NewRequest(http.MethodPost, "/api/schedules", strings.NewReader(body)))
	return rec
}

// 执行节点校验：空=本机；未登记或未配令牌都要在保存时就拦住。
func TestValidateScheduleNode(t *testing.T) {
	fp := newFakePeer(t, "shared-token")

	if err := validateScheduleNode(""); err != nil {
		t.Fatalf("空节点应视为本机执行：%v", err)
	}

	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})
	if err := validateScheduleNode("http://127.0.0.1:9"); err == nil {
		t.Fatal("未登记节点应报错")
	}
	if err := validateScheduleNode(fp.srv.URL); err != nil {
		t.Fatalf("已登记节点 + 有令牌应通过：%v", err)
	}

	// 有同伴但没配令牌：派不出去，保存时就该拒绝。
	withCluster(t, config.Cluster{Peers: []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}}})
	if err := validateScheduleNode(fp.srv.URL); err == nil {
		t.Fatal("未配置 cluster.token 时应报错")
	}
}

// 计划配了执行节点：扫描派发给同伴，本机只留镜像记录（来源 remote + schedule_id）。
func TestScheduledScanDispatchesToNode(t *testing.T) {
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	const planID = "s_remote_1"
	taskID, _, err := launchScheduledScan(planID, "夜间巡检", fp.srv.URL, ScanCreateRequest{Targets: []string{"http://a.example"}})
	if err != nil {
		t.Fatalf("远程计划应起扫成功：%v", err)
	}
	if strings.TrimSpace(taskID) == "" {
		t.Fatal("应返回影子任务号")
	}
	if findTask(taskID) != nil {
		t.Fatal("远程计划不应在本机创建真实任务")
	}

	sent := fp.lastDispatch()
	if len(sent.Request.Targets) != 1 || sent.Request.Targets[0] != "http://a.example" {
		t.Fatalf("执行节点收到的目标不对：%+v", sent.Request.Targets)
	}

	rt := getRemoteTask(taskID)
	if rt == nil {
		t.Fatal("影子记录未创建")
	}
	item := remoteTaskItem(rt)
	if item.Source != scanSourceRemote {
		t.Fatalf("来源应为 remote，实际 %q", item.Source)
	}
	if item.ScheduleID != planID {
		t.Fatalf("应带 schedule_id=%s，实际 %q", planID, item.ScheduleID)
	}
}

// 执行节点连不上：不算致命失败，影子记录保留、标记失联，交给对账继续重试。
func TestScheduledScanNodeUnreachableKeepsRecord(t *testing.T) {
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	nodeURL := fp.srv.URL
	fp.srv.Close()
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: nodeURL}})

	taskID, _, err := launchScheduledScan("s_remote_2", "夜间巡检", nodeURL, ScanCreateRequest{Targets: []string{"http://a.example"}})
	if err != nil {
		t.Fatalf("节点连不上不该视为致命失败：%v", err)
	}
	rt := getRemoteTask(taskID)
	if rt == nil {
		t.Fatal("影子记录应保留，等待对账重试")
	}
	item := remoteTaskItem(rt)
	if item.NodeOK {
		t.Fatal("节点不可达时 node_ok 应为 false")
	}
	if strings.TrimSpace(item.Error) == "" {
		t.Fatal("应写明不可达原因")
	}
	if item.Status != string(TaskStarting) {
		t.Fatalf("状态应为 starting（不误判 failed），实际 %q", item.Status)
	}
}

// 保存计划时的节点校验与持久化（含展示名）。
func TestSchedulesSaveValidatesNode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := postSchedule(t, scheduleSaveBody("带节点", "http://127.0.0.1:9", []string{"https://a.example"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未登记节点应 400，实际 %d %s", rec.Code, rec.Body.String())
	}

	rec = postSchedule(t, scheduleSaveBody("带节点", fp.srv.URL, []string{"https://a.example"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("已登记节点应保存成功：%d %s", rec.Code, rec.Body.String())
	}
	store, err := loadSchedules()
	if err != nil {
		t.Fatalf("loadSchedules: %v", err)
	}
	if len(store.Items) != 1 || store.Items[0].NodeURL != fp.srv.URL {
		t.Fatalf("node_url 未持久化：%+v", store.Items)
	}
	if view := toScheduleView(store.Items[0]); view.NodeName != "节点A" {
		t.Fatalf("视图应带节点展示名，实际 %q", view.NodeName)
	}
}
