package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// drainEvents 取出订阅通道里已经发布的事件（publish 是同步写入带缓冲通道的）。
func drainEvents(ch chan ScanEvent) []ScanEvent {
	var out []ScanEvent
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// eventTypes 按顺序返回事件类型，便于断言前端看到的序列。
func eventTypes(events []ScanEvent) []string {
	types := make([]string, 0, len(events))
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	return types
}

// 引擎的 NDJSON 事件必须逐项翻译成前端既有的事件类型与字段：F6 验收要求
// 「前端零改动」，这层映射就是保证。
func TestTranslateScanEvent_MapsEngineEventsForFrontend(t *testing.T) {
	task := &Task{ID: "t1", status: TaskRunning, targets: []string{"a", "b", "c", "d", "e", "f", "g"}}
	ch, _ := addSubscriber(task, 0, false)
	defer removeSubscriber(task, ch)

	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeScanInfo, ScanInfo: &scanstream.ScanInfoEvent{
		TotalTargets: 7, TotalPocs: 9, TotalScans: 12, OOBEnabled: true, OOBStatus: "ok",
	}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeProgress, Progress: &scanstream.ProgressEvent{
		Percent: 40, Finished: 4, Total: 12, ElapsedMs: 2000,
	}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypePhase, Phase: &scanstream.PhaseEvent{
		Phase: "portscan", Status: "running", Finished: 2, Total: 10, Percent: 20,
	}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeResult, Result: &scanstream.ResultEvent{
		Severity: "HIGH", PocID: "poc-1", PocName: "demo", Target: "https://a.example",
	}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypePort, Port: &scanstream.PortEvent{Host: "a.example", Port: 443}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeHost, Host: &scanstream.HostEvent{Host: "a.example"}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeWebProbe, WebProbe: &scanstream.WebProbeEvent{
		URL: "https://a.example", Status: 200, Title: "home", Fingerprint: "nginx,php",
	}})
	translateScanEvent(task, &scanstream.Event{Type: scanstream.TypeLog, Log: &scanstream.LogEvent{Level: "info", Text: "diagnostic"}})

	want := []string{"scan_info", "progress", "phase_progress", "result", "port", "host", "webprobe"}
	if got := eventTypes(drainEvents(ch)); !equalStrings(got, want) {
		t.Fatalf("event types\n got: %v\nwant: %v", got, want)
	}

	info := task.getScanInfo()
	if info == nil {
		t.Fatal("scan_info not recorded on the task")
	}
	if info.TotalScans != 12 || info.TotalPocs != 9 || !info.OOBEnabled {
		t.Fatalf("scan_info mismatch: %+v", info)
	}
	if got := scanInfoPayload(task, info)["targets"].([]string); len(got) != 5 {
		t.Fatalf("scan_info targets = %d, want the first 5 only", len(got))
	}

	if got := task.hitCount(); got != 1 {
		t.Fatalf("hitCount = %d, want 1", got)
	}
	if _, ok := task.SeverityStats["high"]; !ok {
		t.Fatalf("severity stats = %v, want a lower-cased high key", task.SeverityStats)
	}
}

// done 之后的最终快照必须是「完成 + 100%」，finished 用实际执行数修正。
func TestProgressSnapshot_FinalisesFromDoneSummary(t *testing.T) {
	task := &Task{ID: "t1", status: TaskRunning}
	task.setStarted(time.Now().Add(-3 * time.Second))
	task.setProgress(&scanstream.ProgressEvent{Percent: 99, Finished: 3625, Total: 3626, ElapsedMs: 3000})
	task.setDone("completed", &scanstream.Summary{Executed: 3626, Found: 2, ElapsedMs: 3100})

	snap := progressSnapshot(task)
	if snap.Percent != 99 {
		t.Fatalf("Percent = %d while running, want the engine value 99", snap.Percent)
	}
	if snap.Finished != 3626 || snap.Total != 3626 {
		t.Fatalf("progress = %d/%d, want 3626/3626", snap.Finished, snap.Total)
	}

	task.setStatus(TaskCompleted)
	if got := progressSnapshot(task).Percent; got != 100 {
		t.Fatalf("Percent = %d after completion, want 100", got)
	}
}

// 前置阶段（主机发现/端口扫描/Web 探测）里引擎还没算出任务总数，此间的 progress
// 事件会带 total=0；快照必须用 scan_info 里的权威总数，不能显示成 0。
func TestProgressSnapshot_UsesAuthoritativeTotalFromScanInfo(t *testing.T) {
	task := &Task{ID: "t1", status: TaskRunning}
	task.setStarted(time.Now())
	task.setScanInfo(&scanstream.ScanInfoEvent{TotalTargets: 3, TotalPocs: 1, TotalScans: 3})
	task.setProgress(&scanstream.ProgressEvent{Percent: 0, Finished: 0, Total: 0, ElapsedMs: 1200})
	task.setDone("completed", &scanstream.Summary{Executed: 3, ElapsedMs: 1300})
	task.setStatus(TaskCompleted)

	snap := progressSnapshot(task)
	if snap.Total != 3 {
		t.Fatalf("Total = %d, want the authoritative 3 from scan_info", snap.Total)
	}
	if snap.Finished != 3 || snap.Percent != 100 {
		t.Fatalf("snapshot = %+v, want 3/3 at 100%%", snap)
	}
}

// finalizeTask 必须把最终状态同时体现在 status 事件上，订阅者据此停止等待。
func TestFinalizeTask_PublishesTerminalStatus(t *testing.T) {
	m := newTaskManager()
	m.running = 1
	task := &Task{ID: "t1", status: TaskRunning, targets: []string{"https://a.example"}}
	m.tasks[task.ID] = task
	task.setProgress(&scanstream.ProgressEvent{Percent: 50, Finished: 1, Total: 2})

	ch, _ := addSubscriber(task, 0, false)
	defer removeSubscriber(task, ch)

	finalizeTask(m, task, TaskCancelled)

	types := eventTypes(drainEvents(ch))
	if !equalStrings(types, []string{"progress", "status"}) {
		t.Fatalf("event types = %v, want [progress status]", types)
	}
	if got := task.Status(); got != TaskCancelled {
		t.Fatalf("Status() = %q, want %q", got, TaskCancelled)
	}
}

// 「补录」场景：计划扫描触发的任务由前端事后发现，必须能补看开扫以来的事件
// （Web 探测、端口、命中），否则这些内容在前端永远是空的。
func TestAddSubscriber_ReplaysBufferedEvents(t *testing.T) {
	task := &Task{ID: "t1", status: TaskRunning}
	for _, typ := range []string{"scan_info", "webprobe", "result"} {
		publish(task, ScanEvent{Type: typ, Data: map[string]string{"k": typ}})
	}

	// 从头补发：拿到全部 3 条，且序号连续递增。
	ch, history := addSubscriber(task, 0, true)
	defer removeSubscriber(task, ch)
	if got := eventTypes(history); !equalStrings(got, []string{"scan_info", "webprobe", "result"}) {
		t.Fatalf("replay from 0 = %v, want all buffered events", got)
	}
	for i, ev := range history {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("seq = %d at %d, want %d", ev.Seq, i, i+1)
		}
	}

	// 从第 2 条之后续传：只补发其后的（浏览器重连带 Last-Event-ID 时走这条路）。
	ch2, history2 := addSubscriber(task, 2, true)
	defer removeSubscriber(task, ch2)
	if got := eventTypes(history2); !equalStrings(got, []string{"result"}) {
		t.Fatalf("replay from 2 = %v, want only the events after seq 2", got)
	}

	// 默认（不补发）：只收新事件，避免与本地已有记录重复。
	ch3, history3 := addSubscriber(task, 0, false)
	defer removeSubscriber(task, ch3)
	if len(history3) != 0 {
		t.Fatalf("no-replay subscriber got %d history events, want 0", len(history3))
	}
}

// 缓冲窗口按 eventBufferSize 截断，只保留最近的事件，避免内存无限增长。
func TestPublish_TrimsEventBuffer(t *testing.T) {
	task := &Task{ID: "t1", status: TaskRunning}
	const trimmed = 10
	for i := 0; i < eventBufferSize+trimmed; i++ {
		publish(task, ScanEvent{Type: "progress", Data: map[string]int{"i": i}})
	}

	ch, history := addSubscriber(task, 0, true)
	defer removeSubscriber(task, ch)
	if len(history) != eventBufferSize {
		t.Fatalf("buffered = %d events, want %d", len(history), eventBufferSize)
	}
	if history[0].Seq != uint64(trimmed+1) {
		t.Fatalf("oldest seq = %d, want %d", history[0].Seq, trimmed+1)
	}
}

// 订阅起点解析：显式补发 > 浏览器 Last-Event-ID > 客户端自报 last_seq > 只订阅新事件。
func TestSubscriptionStart(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		lastID   string
		wantSeq  uint64
		wantRepl bool
	}{
		{"default subscribes from now", "/events", "", 0, false},
		{"explicit replay", "/events?replay=1", "", 0, true},
		{"browser reconnect", "/events", "42", 42, true},
		{"client reported seq", "/events?last_seq=7", "", 7, true},
		{"invalid seq falls back to now", "/events?last_seq=abc", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.target, nil)
			if c.lastID != "" {
				req.Header.Set("Last-Event-ID", c.lastID)
			}
			seq, replay := subscriptionStart(req)
			if seq != c.wantSeq || replay != c.wantRepl {
				t.Fatalf("subscriptionStart = (%d,%v), want (%d,%v)", seq, replay, c.wantSeq, c.wantRepl)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 监听地址 ":16868" 不是浏览器能用的地址，启动日志与 base_url 都必须转成可访问的形式。
func TestBrowsableAddr(t *testing.T) {
	cases := map[string]string{
		":16868":         "127.0.0.1:16868",
		"127.0.0.1:8080": "127.0.0.1:8080",
		"0.0.0.0:9000":   "0.0.0.0:9000",
		"":               "127.0.0.1",
		"  :16868  ":     "127.0.0.1:16868",
	}
	for in, want := range cases {
		if got := browsableAddr(in); got != want {
			t.Errorf("browsableAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// Cancelling a scan reaches finalizeTask from two directions at once: the stop
// handler calls it directly, and the drain goroutine calls it when the scanner
// closes its streams. Releasing the manager slot twice would let the queue
// admit more concurrent scans than maxRunning allows.
func TestFinalizeTask_ReleasesTheSlotExactlyOnce(t *testing.T) {
	m := newTaskManager()
	m.running = 3

	task := &Task{ID: "t1", status: TaskRunning}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			finalizeTask(m, task, TaskCancelled)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	running := m.running
	m.mu.Unlock()

	if running != 2 {
		t.Fatalf("running = %d after 16 concurrent finalize calls, want 2", running)
	}
	if got := task.Status(); got != TaskCancelled {
		t.Fatalf("Status() = %q, want %q", got, TaskCancelled)
	}
}

// A second finalize for the same task must not pull another task off the
// queue: that would start it while the first promotion is still running.
func TestFinalizeTask_DuplicateCallDoesNotDrainTheQueue(t *testing.T) {
	m := newTaskManager()
	m.running = 2

	queued := &Task{ID: "queued", status: TaskStarting}
	m.tasks[queued.ID] = queued
	m.queue = []string{queued.ID}

	done := &Task{ID: "done", status: TaskRunning}
	done.finalized.Store(true) // stands in for an earlier finalize
	finalizeTask(m, done, TaskCompleted)

	m.mu.Lock()
	queueLen := len(m.queue)
	m.mu.Unlock()
	if queueLen != 1 {
		t.Fatalf("queue length = %d after a duplicate finalize, want 1", queueLen)
	}
}

// The task fields are read and written from HTTP handlers and the drain
// goroutine at the same time. This test is meaningful under -race.
func TestTask_ConcurrentFieldAccessIsRaceFree(t *testing.T) {
	task := &Task{ID: "t1", status: TaskStarting}
	sub, _ := addSubscriber(task, 0, false)
	go func() {
		for range sub {
		}
	}()

	statuses := []TaskStatus{TaskRunning, TaskPaused, TaskCancelled, TaskCompleted}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(4)
		go func() { defer wg.Done(); task.setStatus(statuses[i%len(statuses)]) }()
		go func() { defer wg.Done(); _ = isActive(task.Status()) }()
		go func() { defer wg.Done(); task.setStarted(time.Now()); _ = task.started() }()
		go func() {
			defer wg.Done()
			publish(task, ScanEvent{Type: "status", Data: map[string]string{"status": "running"}})
		}()
	}

	waited := make(chan struct{})
	go func() { defer close(waited); wg.Wait() }()

	select {
	case <-waited:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent task field access deadlocked")
	}
	removeSubscriber(task, sub)
}

func TestBuildScanSpec_PocScopeMatchesCLISemantics(t *testing.T) {
	t.Run("default web scan appends curated and my dirs", func(t *testing.T) {
		spec := buildScanSpec(
			ScanCreateRequest{},
			[]string{"https://example.com"},
			"",
			[]string{"/tmp/pocs-curated", "/tmp/pocs-my"},
			false,
		)
		if spec.PocFile != "" {
			t.Fatalf("PocFile = %q, want empty so builtin pocs stay in scope", spec.PocFile)
		}
		if len(spec.AppendPocs) != 2 {
			t.Fatalf("AppendPocs = %v, want the two source dirs", spec.AppendPocs)
		}
	})

	t.Run("explicit poc file is exclusive", func(t *testing.T) {
		spec := buildScanSpec(
			ScanCreateRequest{},
			[]string{"https://example.com"},
			"/tmp/custom.yaml",
			nil,
			false,
		)
		if spec.PocFile != "/tmp/custom.yaml" {
			t.Fatalf("PocFile = %q, want /tmp/custom.yaml", spec.PocFile)
		}
		if len(spec.AppendPocs) != 0 {
			t.Fatalf("AppendPocs = %v, want none in exclusive mode", spec.AppendPocs)
		}
	})

	t.Run("explicit source is exclusive", func(t *testing.T) {
		spec := buildScanSpec(
			ScanCreateRequest{PocSource: "my"},
			[]string{"https://example.com"},
			"",
			[]string{"/tmp/pocs-my"},
			false,
		)
		if spec.PocFile != "/tmp/pocs-my" {
			t.Fatalf("PocFile = %q, want the single source dir", spec.PocFile)
		}
		if len(spec.AppendPocs) != 0 {
			t.Fatalf("AppendPocs = %v, want none in exclusive mode", spec.AppendPocs)
		}
	})

	// poc_ids 已经把 PoC 逐个落成文件交给 -P，再叠加 -s/-S 只会缩窄范围。
	t.Run("poc ids skip search and severity", func(t *testing.T) {
		spec := buildScanSpec(
			ScanCreateRequest{Search: "tomcat", Severity: "high"},
			[]string{"https://example.com"},
			"/tmp/pocids",
			nil,
			true,
		)
		if spec.Search != "" || spec.Severity != "" {
			t.Fatalf("Search/Severity = %q/%q, want empty when poc_ids is used", spec.Search, spec.Severity)
		}
	})

	t.Run("request options are carried over", func(t *testing.T) {
		spec := buildScanSpec(
			ScanCreateRequest{
				Concurrency:    30,
				RateLimit:      200,
				Timeout:        15,
				Retries:        2,
				MaxHostError:   4,
				Proxy:          " http://127.0.0.1:8080 ",
				Smart:          true,
				PortScanCompat: true,
				Ports:          "80,443",
				SkipHostDisc:   true,
				WebFingerprint: true,
				EnableOOB:      true,
				OOB:            "dnslogcn",
			},
			[]string{"https://example.com"},
			"",
			nil,
			false,
		)
		if spec.Concurrency != 30 || spec.RateLimit != 200 || spec.TimeoutSeconds != 15 || spec.Retries != 2 {
			t.Fatalf("performance options not mapped: %+v", spec)
		}
		if spec.MaxHostError != 4 || spec.Proxy != "http://127.0.0.1:8080" || !spec.Smart {
			t.Fatalf("network options not mapped: %+v", spec)
		}
		if !spec.PortScan || spec.Ports != "80,443" || !spec.SkipHostDiscovery || !spec.WebFingerprint {
			t.Fatalf("pre-scan options not mapped: %+v", spec)
		}
		if !spec.EnableOOB || spec.OOBAdapter != "dnslogcn" {
			t.Fatalf("oob options not mapped: %+v", spec)
		}
	})
}
