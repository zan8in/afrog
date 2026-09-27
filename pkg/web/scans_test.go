package web

import (
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
	ch := addSubscriber(task)
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

	ch := addSubscriber(task)
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
	sub := addSubscriber(task)
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
