package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSender 收集实际发出的消息，并按需返回错误。
type fakeSender struct {
	mu    sync.Mutex
	got   []Message
	gotCh []Channel
	err   error
	// notify 每收到一条就推一次，供测试等待「某条消息已发出」。
	notify chan struct{}
}

func newFakeSender() *fakeSender {
	return &fakeSender{notify: make(chan struct{}, 64)}
}

func (f *fakeSender) send(_ context.Context, ch Channel, msg Message) error {
	f.mu.Lock()
	f.got = append(f.got, msg)
	f.gotCh = append(f.gotCh, ch)
	f.err = nil
	f.mu.Unlock()

	select {
	case f.notify <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeSender) messages() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.got...)
}

// waitFor 等待至少 n 条消息发出，超时即失败。
func (f *fakeSender) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if len(f.messages()) >= n {
			return
		}
		select {
		case <-f.notify:
		case <-deadline:
			t.Fatalf("timed out waiting for %d messages, got %d", n, len(f.messages()))
		}
	}
}

func testChannel() Channel {
	return Channel{ID: "n_1", Type: ChannelWebhook, Name: "test", Enabled: true, Target: "http://127.0.0.1:1/hook"}
}

func newTestNotifier(sender Sender, cfg Config) *Notifier {
	n := NewNotifier()
	n.sender = sender
	n.SetConfig(cfg)
	return n
}

func fullConfig() Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxPerTask = 3
	cfg.Channels = []Channel{testChannel()}
	return cfg
}

func TestOnHitDedupesSamePocAndTarget(t *testing.T) {
	sender := newFakeSender()
	n := newTestNotifier(sender.send, fullConfig())
	n.OnTaskStart("t-1", "任务一")

	// 同一 PoC + 目标重复命中，只推第一条
	n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
	n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
	n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
	// 换目标属于新的一条，用它作为「前面的确已经处理完」的同步点
	n.OnHit("t-1", "high", "poc-a", "A", "http://b.example")

	sender.waitFor(t, 2)
	// 再等一小会儿，确认第三条不会被补发
	time.Sleep(50 * time.Millisecond)

	msgs := sender.messages()
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2（重复的 poc+目标 不应重复推送）", len(msgs))
	}

	// 异步发送不保证顺序，按目标集合断言。
	targets := map[string]bool{}
	for _, m := range msgs {
		for _, line := range m.Lines {
			if strings.HasPrefix(line, "目标：") {
				targets[strings.TrimPrefix(line, "目标：")] = true
			}
		}
	}
	if !targets["http://a.example"] || !targets["http://b.example"] {
		t.Fatalf("targets = %v, want both a.example and b.example", targets)
	}
}

func TestOnHitRespectsSeverityThreshold(t *testing.T) {
	sender := newFakeSender()
	cfg := fullConfig()
	cfg.Severity = []string{"critical", "high"}
	n := newTestNotifier(sender.send, cfg)
	n.OnTaskStart("t-1", "任务一")

	n.OnHit("t-1", "medium", "poc-m", "M", "http://m.example")   // 低于阈值
	n.OnHit("t-1", "info", "poc-i", "I", "http://i.example")     // 低于阈值
	n.OnHit("t-1", "CRITICAL", "poc-c", "C", "http://c.example") // 大小写不敏感，应推送

	sender.waitFor(t, 1)
	time.Sleep(50 * time.Millisecond)

	msgs := sender.messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1（只有 critical 达到阈值）", len(msgs))
	}
	if !strings.Contains(msgs[0].Text(), "CRITICAL") {
		t.Fatalf("message should carry the uppercased level: %s", msgs[0].Text())
	}
}

func TestOnHitCapsPerTaskAndReportsSuppressed(t *testing.T) {
	sender := newFakeSender()
	cfg := fullConfig()
	cfg.MaxPerTask = 2
	n := newTestNotifier(sender.send, cfg)
	n.OnTaskStart("t-1", "任务一")

	// 5 条互不相同的命中，上限 2 → 只推 2 条，其余 3 条被压制
	for i := 0; i < 5; i++ {
		n.OnHit("t-1", "high", "poc-x", "X", "http://x.example/"+string(rune('a'+i)))
	}

	sender.waitFor(t, 2)
	time.Sleep(50 * time.Millisecond)
	if got := len(sender.messages()); got != 2 {
		t.Fatalf("messages = %d, want 2（受 MaxPerTask 限制）", got)
	}

	// 汇总消息必须说明被压制的条数，否则用户会以为漏报
	n.OnTaskDone("t-1", TaskResult{TaskName: "任务一", Status: "completed", Hits: 5})
	sender.waitFor(t, 3)

	summary := sender.messages()[2].Text()
	if !strings.Contains(summary, "另有 3 条未单独推送") {
		t.Fatalf("summary should mention suppressed hits: %s", summary)
	}
}

func TestOnTaskDoneSkipsWhenDisabledOrEventOff(t *testing.T) {
	t.Run("总开关关闭", func(t *testing.T) {
		sender := newFakeSender()
		cfg := fullConfig()
		cfg.Enabled = false
		n := newTestNotifier(sender.send, cfg)

		n.OnTaskStart("t-1", "任务一")
		n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
		n.OnTaskDone("t-1", TaskResult{Status: "completed", Hits: 1})

		time.Sleep(80 * time.Millisecond)
		if got := len(sender.messages()); got != 0 {
			t.Fatalf("messages = %d, want 0", got)
		}
	})

	t.Run("事件开关关闭", func(t *testing.T) {
		sender := newFakeSender()
		cfg := fullConfig()
		cfg.Events = Events{TaskCompleted: false, VulnFound: false, TaskFailed: false}
		n := newTestNotifier(sender.send, cfg)

		n.OnTaskStart("t-1", "任务一")
		n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
		n.OnTaskDone("t-1", TaskResult{Status: "failed", Err: "boom"})

		time.Sleep(80 * time.Millisecond)
		if got := len(sender.messages()); got != 0 {
			t.Fatalf("messages = %d, want 0", got)
		}
	})
}

func TestOnTaskDoneSendsFailureNotice(t *testing.T) {
	sender := newFakeSender()
	n := newTestNotifier(sender.send, fullConfig())
	n.OnTaskStart("t-1", "任务一")

	n.OnTaskDone("t-1", TaskResult{TaskName: "任务一", Status: "failed", Err: "子进程退出码 1"})

	sender.waitFor(t, 1)
	msg := sender.messages()[0]
	if msg.Title != "afrog 扫描异常" {
		t.Fatalf("title = %q", msg.Title)
	}
	if !strings.Contains(msg.Text(), "失败") || !strings.Contains(msg.Text(), "子进程退出码 1") {
		t.Fatalf("failure message should carry status and error: %s", msg.Text())
	}
}

func TestOnHitIgnoredForUnknownTask(t *testing.T) {
	sender := newFakeSender()
	n := newTestNotifier(sender.send, fullConfig())

	// 未登记的任务（例如进程重启前的旧任务）不推送
	n.OnHit("t-unknown", "high", "poc-a", "A", "http://a.example")

	time.Sleep(80 * time.Millisecond)
	if got := len(sender.messages()); got != 0 {
		t.Fatalf("messages = %d, want 0", got)
	}
}

// TestProjectSubscriptionFilter 锁定「按项目订阅」的语义：
// 不配白名单就全推；配了白名单则只推订阅项目，且不属于任何项目的任务不推。
func TestProjectSubscriptionFilter(t *testing.T) {
	resolver := func(taskID string) string {
		switch taskID {
		case "t-in":
			return "p_a"
		case "t-out":
			return "p_b"
		default:
			return ""
		}
	}

	cases := []struct {
		name       string
		projectIDs []string
		taskID     string
		want       int
	}{
		{"未配置白名单时全部放行", nil, "t-out", 2},
		{"订阅项目内的任务放行", []string{"p_a"}, "t-in", 2},
		{"订阅项目外的任务拦截", []string{"p_a"}, "t-out", 0},
		{"不属于任何项目的任务拦截", []string{"p_a"}, "t-none", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := newFakeSender()
			cfg := fullConfig()
			cfg.ProjectIDs = tc.projectIDs
			n := newTestNotifier(sender.send, cfg)
			n.SetProjectResolver(resolver)

			// 一条实时命中 + 一条汇总，放行时应收到 2 条
			n.OnTaskStart(tc.taskID, "任务一")
			n.OnHit(tc.taskID, "high", "poc-a", "A", "http://a.example")
			n.OnTaskDone(tc.taskID, TaskResult{TaskName: "任务一", Status: "completed", Hits: 1})

			time.Sleep(80 * time.Millisecond)
			if got := len(sender.messages()); got != tc.want {
				t.Fatalf("messages = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDeliveryLogRecordsAndResend 覆盖「发送记录」与「重发」这两条新路径。
func TestDeliveryLogRecordsAndResend(t *testing.T) {
	sender := newFakeSender()
	n := newTestNotifier(sender.send, fullConfig())

	n.OnTaskStart("t-1", "任务一")
	n.OnHit("t-1", "high", "poc-a", "A", "http://a.example")
	sender.waitFor(t, 1)
	time.Sleep(50 * time.Millisecond)

	items, stats := n.RecentDeliveries(10)
	if stats.Total != 1 || stats.OK != 1 || stats.Failed != 0 {
		t.Fatalf("stats = %+v, want total=1 ok=1 failed=0", stats)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	first := items[0]
	if first.Event != "vuln_found" || first.TaskName != "任务一" || !first.OK || first.Attempts != 1 {
		t.Fatalf("record = %+v, want vuln_found/任务一/ok/attempts=1", first)
	}
	if first.ChannelName != "test" {
		t.Fatalf("channel = %q, want test", first.ChannelName)
	}

	// 重发应新增一条记录，而不是覆盖原记录
	resent, err := n.Resend(first.ID)
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if !resent.OK || resent.ID == first.ID {
		t.Fatalf("resent = %+v, want a new ok record", resent)
	}
	if _, after := n.RecentDeliveries(10); after.Total != 2 {
		t.Fatalf("total = %d, want 2", after.Total)
	}

	// 不存在的记录要报错，不能静默成功
	if _, err := n.Resend(9999); err == nil {
		t.Fatal("resend of unknown id should fail")
	}
}

func TestTestSendTargetsSelectedChannels(t *testing.T) {
	sender := newFakeSender()
	cfg := DefaultConfig()
	cfg.Channels = []Channel{
		{ID: "n_on", Type: ChannelWebhook, Name: "启用", Enabled: true, Target: "http://a/hook"},
		{ID: "n_off", Type: ChannelWebhook, Name: "停用", Enabled: false, Target: "http://b/hook"},
	}
	n := newTestNotifier(sender.send, cfg)

	// 指定停用的渠道也要能测（用户就是在配它的时候要测）
	results, err := n.Test(context.Background(), "n_off")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(results) != 1 || !results[0].OK || results[0].ChannelID != "n_off" {
		t.Fatalf("results = %+v", results)
	}

	// 不指定渠道时只测已启用的
	sender.mu.Lock()
	sender.got = nil
	sender.mu.Unlock()

	results, err = n.Test(context.Background(), "")
	if err != nil {
		t.Fatalf("Test(all): %v", err)
	}
	if len(results) != 1 || results[0].ChannelID != "n_on" {
		t.Fatalf("results = %+v, want only the enabled channel", results)
	}

	if _, err := n.Test(context.Background(), "n_missing"); err == nil {
		t.Fatal("unknown channel should error")
	}
}

// -----------------------
// 渠道 payload
// -----------------------

// captureServer 起一个本地 HTTP 服务并记录收到的请求。
type capture struct {
	contentType string
	body        []byte
}

func newCaptureServer(t *testing.T, status int, respBody string) (*httptest.Server, *capture) {
	t.Helper()

	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.contentType = r.Header.Get("Content-Type")
		cap.body = raw
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func TestSendWebhookPayload(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, `{"ok":true}`)

	ch := Channel{Type: ChannelWebhook, Target: srv.URL}
	msg := Message{
		Title: "afrog 扫描完成",
		Level: "high",
		Lines: []string{"命中总数：3"},
		Extra: map[string]any{"event": "task_completed", "hits": 3},
	}
	if err := sendChannel(context.Background(), ch, msg); err != nil {
		t.Fatalf("sendChannel: %v", err)
	}

	if !strings.Contains(cap.contentType, "application/json") {
		t.Fatalf("content type = %q", cap.contentType)
	}

	var payload webhookPayload
	if err := json.Unmarshal(cap.body, &payload); err != nil {
		t.Fatalf("payload is not json: %s", cap.body)
	}
	if payload.Source != "afrog" || payload.Title != "afrog 扫描完成" || payload.Level != "high" {
		t.Fatalf("payload = %+v", payload)
	}
	if !strings.Contains(payload.Text, "命中总数：3") {
		t.Fatalf("text = %q", payload.Text)
	}
	if payload.Extra["event"] != "task_completed" {
		t.Fatalf("extra = %+v", payload.Extra)
	}
}

func TestSendFeishuPayloadAndBusinessCode(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, `{"code":0,"msg":"success"}`)
	ch := Channel{Type: ChannelFeishu, Target: srv.URL}

	if err := sendChannel(context.Background(), ch, Message{Title: "标题", Lines: []string{"正文"}}); err != nil {
		t.Fatalf("sendChannel: %v", err)
	}

	var payload struct {
		MsgType string            `json:"msg_type"`
		Content map[string]string `json:"content"`
	}
	if err := json.Unmarshal(cap.body, &payload); err != nil {
		t.Fatalf("payload is not json: %s", cap.body)
	}
	if payload.MsgType != "text" || !strings.Contains(payload.Content["text"], "标题") {
		t.Fatalf("payload = %+v", payload)
	}

	// 飞书失败时返回 HTTP 200 + 非 0 业务码，必须被识别为失败
	badSrv, _ := newCaptureServer(t, http.StatusOK, `{"code":9499,"msg":"Bad Request"}`)
	err := sendChannel(context.Background(), Channel{Type: ChannelFeishu, Target: badSrv.URL},
		Message{Title: "x", Lines: []string{"y"}})
	if err == nil || !strings.Contains(err.Error(), "9499") {
		t.Fatalf("expected business code error, got %v", err)
	}
}

func TestSendServerChanFormAndBusinessCode(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, `{"code":0,"message":"ok"}`)

	old := serverChanBase
	serverChanBase = srv.URL
	t.Cleanup(func() { serverChanBase = old })

	ch := Channel{Type: ChannelServerChan, Target: "SCT_test_key"}
	if err := sendChannel(context.Background(), ch, Message{Title: "标题", Lines: []string{"第一行", "第二行"}}); err != nil {
		t.Fatalf("sendChannel: %v", err)
	}

	if !strings.Contains(cap.contentType, "application/x-www-form-urlencoded") {
		t.Fatalf("content type = %q", cap.contentType)
	}
	body := string(cap.body)
	if !strings.Contains(body, "title=") || !strings.Contains(body, "desp=") {
		t.Fatalf("form body = %q", body)
	}
	if !strings.Contains(body, "%E6%A0%87%E9%A2%98") { // “标题” 的 urlencoded
		t.Fatalf("title should be url-encoded: %q", body)
	}
}

func TestDoRequestRejectsNonHTTPScheme(t *testing.T) {
	err := sendChannel(context.Background(),
		Channel{Type: ChannelWebhook, Target: "file:///etc/passwd"},
		Message{Title: "x", Lines: []string{"y"}})
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("expected scheme rejection, got %v", err)
	}
}

func TestPostJSONReportsHTTPError(t *testing.T) {
	srv, _ := newCaptureServer(t, http.StatusInternalServerError, "boom")
	err := sendChannel(context.Background(),
		Channel{Type: ChannelWebhook, Target: srv.URL},
		Message{Title: "x", Lines: []string{"y"}})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected http error, got %v", err)
	}
}

// -----------------------
// 配置清洗
// -----------------------

func TestNormalizeConfig(t *testing.T) {
	cfg := Config{
		MaxPerTask: 9999,
		Severity:   []string{"HIGH", "high", "bogus", "", "critical"},
		Channels: []Channel{
			{Type: "WEBHOOK", Target: " http://a/hook "}, // 类型大小写与空格都要清洗
			{Type: "webhook", Target: ""},                // 无凭据 -> 丢弃
			{Type: "nope", Target: "http://b/hook"},      // 未知类型 -> 丢弃
			{ID: "n_dup", Type: "feishu", Target: "http://c/hook"},
			{ID: "n_dup", Type: "feishu", Target: "http://d/hook"}, // ID 冲突要重新分配
		},
	}
	normalize(&cfg)

	if cfg.MaxPerTask != maxMaxPerTask {
		t.Errorf("MaxPerTask = %d, want %d", cfg.MaxPerTask, maxMaxPerTask)
	}
	if len(cfg.Severity) != 2 || cfg.Severity[0] != "high" || cfg.Severity[1] != "critical" {
		t.Errorf("Severity = %v, want [high critical]", cfg.Severity)
	}
	if len(cfg.Channels) != 3 {
		t.Fatalf("Channels = %d, want 3", len(cfg.Channels))
	}
	if cfg.Channels[0].Type != ChannelWebhook || cfg.Channels[0].Target != "http://a/hook" {
		t.Errorf("channel[0] = %+v", cfg.Channels[0])
	}
	if cfg.Channels[0].ID == "" || cfg.Channels[1].ID == "" {
		t.Error("channel IDs should be generated")
	}
	if cfg.Channels[1].ID == cfg.Channels[2].ID {
		t.Errorf("duplicate channel IDs were not reassigned: %s", cfg.Channels[1].ID)
	}
}

func TestDefaultConfigIsInert(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("默认应关闭，避免用户没配就被推送")
	}
	if len(cfg.Channels) != 0 {
		t.Errorf("Channels = %d, want 0", len(cfg.Channels))
	}
	if cfg.MaxPerTask != defaultMaxPerTask {
		t.Errorf("MaxPerTask = %d", cfg.MaxPerTask)
	}
}
