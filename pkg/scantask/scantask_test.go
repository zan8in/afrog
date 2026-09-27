package scantask

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// ---------------------------------------------------------------------------
// 测试替身：完全掌控子进程行为与事件时序，避免依赖真实 afrog 二进制。
// ---------------------------------------------------------------------------

type fakeHandle struct {
	events   chan *scanstream.Event
	done     chan struct{}
	paused   bool
	pauseErr error

	closeOnce sync.Once
	mu        sync.Mutex
	exited    bool
}

func (h *fakeHandle) Events() <-chan *scanstream.Event { return h.events }
func (h *fakeHandle) Done() <-chan struct{}            { return h.done }
func (h *fakeHandle) Err() error                       { return nil }
func (h *fakeHandle) PID() int                         { return 4242 }

func (h *fakeHandle) Pause() error {
	if h.pauseErr != nil {
		return h.pauseErr
	}
	h.mu.Lock()
	h.paused = true
	h.mu.Unlock()
	return nil
}

func (h *fakeHandle) Resume() error {
	if h.pauseErr != nil {
		return h.pauseErr
	}
	h.mu.Lock()
	h.paused = false
	h.mu.Unlock()
	return nil
}

// Cancel 模拟「进程被杀掉 → 事件流结束」。
func (h *fakeHandle) Cancel() error {
	h.mu.Lock()
	already := h.exited
	h.exited = true
	h.mu.Unlock()
	if already {
		return executor.ErrAlreadyDone
	}
	h.closeOnce.Do(func() { close(h.events) })
	close(h.done)
	return nil
}

func (h *fakeHandle) isPaused() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.paused
}

type fakeExecutor struct {
	mu      sync.Mutex
	handles map[string]*fakeHandle
	specs   map[string]*executor.Spec
	// startErr 非空时 Start 直接失败。
	startErr error
	// pauseErr 传给每个 handle。
	pauseErr error
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{handles: map[string]*fakeHandle{}, specs: map[string]*executor.Spec{}}
}

func (f *fakeExecutor) Start(_ context.Context, taskID string, spec *executor.Spec) (executor.Handle, error) {
	f.mu.Lock()
	startErr, pauseErr := f.startErr, f.pauseErr
	if startErr != nil {
		f.mu.Unlock()
		return nil, startErr
	}
	h := &fakeHandle{
		events:   make(chan *scanstream.Event, 512),
		done:     make(chan struct{}),
		pauseErr: pauseErr,
	}
	f.handles[taskID] = h
	f.specs[taskID] = spec
	f.mu.Unlock()
	return h, nil
}

func (f *fakeExecutor) setStartErr(err error) {
	f.mu.Lock()
	f.startErr = err
	f.mu.Unlock()
}

func (f *fakeExecutor) setPauseErr(err error) {
	f.mu.Lock()
	f.pauseErr = err
	f.mu.Unlock()
}

func (f *fakeExecutor) handle(t *testing.T, taskID string) *fakeHandle {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.handles[taskID]
	if !ok {
		t.Fatalf("no handle for task %s", taskID)
	}
	return h
}

func (f *fakeExecutor) spec(t *testing.T, taskID string) *executor.Spec {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.specs[taskID]
	if !ok {
		t.Fatalf("no spec for task %s", taskID)
	}
	return s
}

// emit 追加一条事件；finish 追加 done 事件并结束事件流。
func (f *fakeExecutor) emit(t *testing.T, taskID, typ string, fill func(*scanstream.Event)) {
	t.Helper()
	ev := &scanstream.Event{Type: typ}
	if fill != nil {
		fill(ev)
	}
	f.handle(t, taskID).events <- ev
}

func (f *fakeExecutor) finish(t *testing.T, taskID, doneStatus string) {
	t.Helper()
	f.emit(t, taskID, scanstream.TypeDone, func(ev *scanstream.Event) {
		ev.Done = &scanstream.DoneEvent{Status: doneStatus, Summary: &scanstream.Summary{Executed: 3, Found: 1}}
	})
	if err := f.handle(t, taskID).Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
		t.Fatalf("finish: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type testRig struct {
	mgr  *Manager
	exec *fakeExecutor
	mu   sync.Mutex
	n    int
}

func newRig(t *testing.T, opts Options) *testRig {
	t.Helper()
	rig := &testRig{exec: newFakeExecutor()}
	opts.Executor = rig.exec
	if opts.IDGenerator == nil {
		opts.IDGenerator = func() string {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			rig.n++
			return "task-" + strconv.Itoa(rig.n)
		}
	}
	mgr, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rig.mgr = mgr
	return rig
}

func submit(t *testing.T, rig *testRig, targets ...string) string {
	t.Helper()
	if len(targets) == 0 {
		targets = []string{"http://a.example"}
	}
	snap, err := rig.mgr.Submit(Request{Targets: targets})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return snap.ID
}

// collect 读完订阅通道，返回全部事件。
func collect(t *testing.T, sub *Subscription, timeout time.Duration) []*scanstream.Event {
	t.Helper()
	deadline := time.After(timeout)
	var out []*scanstream.Event
	for {
		select {
		case ev, ok := <-sub.Events():
			if !ok {
				if err := sub.Err(); err != nil {
					t.Fatalf("subscription closed with %v", err)
				}
				return out
			}
			out = append(out, ev)
		case <-deadline:
			t.Fatalf("timeout waiting for events, got %d", len(out))
		}
	}
}

// waitTerminal 等到任务进入终态。
func waitTerminal(t *testing.T, rig *testRig, taskID string, timeout time.Duration) *Snapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snap := rig.task(t, taskID).Snapshot()
		if snap.Status.Terminal() {
			return snap
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach a terminal status", taskID)
	return nil
}

func (r *testRig) task(t *testing.T, taskID string) *Task {
	t.Helper()
	task, ok := r.mgr.Get(taskID)
	if !ok {
		t.Fatalf("task %s not found", taskID)
	}
	return task
}

// assertContiguous 断言 seq 从 1 开始严格连续递增。
func assertContiguous(t *testing.T, events []*scanstream.Event) {
	t.Helper()
	for i, ev := range events {
		if want := uint64(i + 1); ev.Seq != want {
			t.Fatalf("event %d seq = %d, want %d (types=%v)", i, ev.Seq, want, eventTypes(events))
		}
	}
}

func eventTypes(events []*scanstream.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Type)
	}
	return out
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

func TestSubmit_RejectsEmptyTargets(t *testing.T) {
	rig := newRig(t, Options{})
	if _, err := rig.mgr.Submit(Request{Targets: []string{"  ", ""}}); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("err = %v, want ErrNoTargets", err)
	}
}

// 一次完整扫描：控制面广播生命周期状态，并把执行器的事件按自己的编号转发。
func TestSubmit_BroadcastsLifecycleAndRelayedEvents(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// 等子进程真的被拉起后再灌事件（事件必须来自执行器）。
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	rig.exec.emit(t, id, scanstream.TypeScanInfo, func(ev *scanstream.Event) {
		ev.ScanInfo = &scanstream.ScanInfoEvent{TotalTargets: 1, TotalPocs: 2, TotalScans: 3, OOBEnabled: true}
	})
	rig.exec.emit(t, id, scanstream.TypeProgress, func(ev *scanstream.Event) {
		ev.Progress = &scanstream.ProgressEvent{Percent: 66, Finished: 2, Total: 3, ElapsedMs: 1500}
	})
	rig.exec.emit(t, id, scanstream.TypeResult, func(ev *scanstream.Event) {
		ev.Result = &scanstream.ResultEvent{Severity: "HIGH", PocID: "poc-1", Target: "http://a.example"}
	})
	rig.exec.finish(t, id, "completed")

	events := collect(t, sub, 10*time.Second)
	assertContiguous(t, events)

	want := []string{
		scanstream.TypeStatus, // starting
		scanstream.TypeStatus, // running
		scanstream.TypeScanInfo,
		scanstream.TypeProgress,
		scanstream.TypeResult,
		scanstream.TypeDone,
		scanstream.TypeProgress, // 收尾补发的权威进度
		scanstream.TypeScanInfo, // 收尾补发的权威汇总
		scanstream.TypeStatus,   // completed
	}
	if got := eventTypes(events); len(got) != len(want) {
		t.Fatalf("event types\n got: %v\nwant: %v", got, want)
	}
	for i := range want {
		if events[i].Type != want[i] {
			t.Fatalf("event %d type = %s, want %s (all: %v)", i, events[i].Type, want[i], eventTypes(events))
		}
	}

	snap := rig.task(t, id).Snapshot()
	if snap.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", snap.Status)
	}
	if snap.Progress.Total != 3 || snap.Progress.Finished != 3 || snap.Progress.Percent != 100 {
		t.Fatalf("progress = %+v, want 3/3 at 100%%", snap.Progress)
	}
	if snap.Hits["high"] != 1 || snap.HitTotal != 1 {
		t.Fatalf("hits = %v, want one high", snap.Hits)
	}
	if snap.ScanInfo.TotalPocs != 2 || !snap.ScanInfo.OOBEnabled {
		t.Fatalf("scan info = %+v", snap.ScanInfo)
	}
	if snap.Summary == nil || snap.Summary.Executed != 3 {
		t.Fatalf("summary = %+v", snap.Summary)
	}
}

// 控制面自己维护状态：执行器上报的 status 不会被重复广播（否则订阅者会看到矛盾状态）。
func TestApply_IgnoresExecutorStatusEvents(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	rig.exec.emit(t, id, scanstream.TypeStatus, func(ev *scanstream.Event) {
		ev.Status = &scanstream.StatusEvent{Status: "running"}
	})
	rig.exec.finish(t, id, "completed")
	waitTerminal(t, rig, id, 10*time.Second)

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	events := collect(t, sub, 5*time.Second)
	statuses := 0
	for _, ev := range events {
		if ev.Type == scanstream.TypeStatus {
			statuses++
		}
	}
	if statuses != 3 { // starting / running / completed
		t.Fatalf("status events = %d, want 3 (all: %v)", statuses, eventTypes(events))
	}
}

// F4：断线重连靠 seq 补齐，不丢不重。
func TestSubscribe_FromSeqReplaysExactlyTheMissingEvents(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	scriptTask(t, rig, id)
	waitTerminal(t, rig, id, 10*time.Second)

	all := collectFrom(t, rig, id, 0)
	if len(all) < 5 {
		t.Fatalf("expected a non-trivial stream, got %v", eventTypes(all))
	}
	assertContiguous(t, all)

	for cut := 0; cut < len(all); cut++ {
		last := all[cut].Seq
		rest := collectFrom(t, rig, id, last)
		if len(rest) != len(all)-cut-1 {
			t.Fatalf("from_seq=%d got %d events, want %d", last, len(rest), len(all)-cut-1)
		}
		for i, ev := range rest {
			want := all[cut+1+i]
			if ev.Seq != want.Seq || ev.Type != want.Type {
				t.Fatalf("from_seq=%d event %d = %d/%s, want %d/%s", last, i, ev.Seq, ev.Type, want.Seq, want.Type)
			}
		}
	}
}

// 实时订阅与补发得到的序列必须一致（不因订阅时机不同而丢事件）。
func TestSubscribe_LiveStreamMatchesReplayOfFinishedTask(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	scriptTask(t, rig, id)
	waitTerminal(t, rig, id, 10*time.Second)
	live := collect(t, sub, 10*time.Second)

	replay := collectFrom(t, rig, id, 0)
	if len(live) != len(replay) {
		t.Fatalf("live %d events vs replay %d (%v vs %v)",
			len(live), len(replay), eventTypes(live), eventTypes(replay))
	}
	for i := range live {
		if live[i].Seq != replay[i].Seq || live[i].Type != replay[i].Type {
			t.Fatalf("event %d differs: live %d/%s replay %d/%s",
				i, live[i].Seq, live[i].Type, replay[i].Seq, replay[i].Type)
		}
	}
}

// 请求的位置早于保留窗口时，先收到一条不参与去重的截断通知。
func TestSubscribe_NotifiesWhenRequestedSeqFellOutOfWindow(t *testing.T) {
	rig := newRig(t, Options{EventBuffer: 4})
	id := submit(t, rig)
	scriptTask(t, rig, id)
	waitTerminal(t, rig, id, 10*time.Second)

	snap := rig.task(t, id).Snapshot()
	if !snap.Truncated {
		t.Fatal("snapshot should report Truncated")
	}
	if snap.BufferedFrom <= 1 {
		t.Fatalf("BufferedFrom = %d, want > 1", snap.BufferedFrom)
	}

	events := collectFrom(t, rig, id, 1)
	if len(events) == 0 || events[0].Type != scanstream.TypeError {
		t.Fatalf("first event = %v, want an events_truncated notice", eventTypes(events))
	}
	if events[0].Seq != 0 || events[0].Error.Code != "events_truncated" {
		t.Fatalf("notice = %+v, want seq 0 / events_truncated", events[0])
	}
	if got := events[1].Seq; got != snap.BufferedFrom {
		t.Fatalf("first replayed seq = %d, want %d", got, snap.BufferedFrom)
	}

	// 请求窗口内的位置时不应再出现通知。
	events = collectFrom(t, rig, id, snap.BufferedFrom)
	if len(events) == 0 || events[0].Type == scanstream.TypeError {
		t.Fatalf("unexpected notice inside the window: %v", eventTypes(events))
	}
}

func TestControl_PauseResumeCancel(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	// 等子进程被拉起
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := rig.mgr.Control(id, ActionPause); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if !rig.exec.handle(t, id).isPaused() {
		t.Fatal("handle was not paused")
	}
	paused := rig.task(t, id).Snapshot()
	if paused.Status != StatusPaused || !paused.Pausable {
		t.Fatalf("snapshot = %+v, want paused and pausable", paused)
	}

	if err := rig.mgr.Control(id, ActionResume); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rig.exec.handle(t, id).isPaused() {
		t.Fatal("handle still paused")
	}
	if got := rig.task(t, id).Snapshot().Status; got != StatusRunning {
		t.Fatalf("status = %s, want running", got)
	}

	if err := rig.mgr.Control(id, ActionCancel); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	snap := waitTerminal(t, rig, id, 10*time.Second)
	if snap.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", snap.Status)
	}
	if snap.Pausable {
		t.Fatal("finished task must not be pausable")
	}

	types := eventTypes(collect(t, sub, 5*time.Second))
	if types[len(types)-1] != scanstream.TypeStatus {
		t.Fatalf("last event = %v, want a status event", types)
	}
}

func TestControl_PauseUnsupportedPlatformIsReported(t *testing.T) {
	rig := newRig(t, Options{})
	rig.exec.pauseErr = executor.ErrPauseUnsupported
	id := submit(t, rig)
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	if err := rig.mgr.Control(id, ActionPause); !errors.Is(err, executor.ErrPauseUnsupported) {
		t.Fatalf("err = %v, want ErrPauseUnsupported", err)
	}
	if got := rig.task(t, id).Snapshot().Status; got != StatusRunning {
		t.Fatalf("status = %s, want to stay running", got)
	}
}

func TestControl_UnknownTask(t *testing.T) {
	rig := newRig(t, Options{})
	if err := rig.mgr.Control("nope", ActionPause); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("err = %v, want ErrTaskNotFound", err)
	}
}

// 并发已满时任务排队；收尾后自动放行。
func TestSubmit_QueuesWhenConcurrencyIsExhausted(t *testing.T) {
	rig := newRig(t, Options{MaxRunning: 1})
	first := submit(t, rig)
	waitStatus(t, rig, first, StatusRunning, 10*time.Second)

	second := submit(t, rig)
	if got := rig.task(t, second).Snapshot().Status; got != StatusQueued {
		t.Fatalf("second task status = %s, want queued", got)
	}

	rig.exec.finish(t, first, "completed")
	waitStatus(t, rig, second, StatusRunning, 10*time.Second)
	rig.exec.finish(t, second, "completed")
	waitTerminal(t, rig, second, 10*time.Second)
}

// 排队中的任务可以直接取消，且不会误伤正在运行的名额。
func TestControl_CancelsQueuedTaskWithoutStealingASlot(t *testing.T) {
	rig := newRig(t, Options{MaxRunning: 1})
	running := submit(t, rig)
	waitStatus(t, rig, running, StatusRunning, 10*time.Second)

	queued := submit(t, rig)
	if err := rig.mgr.Control(queued, ActionCancel); err != nil {
		t.Fatalf("cancel queued: %v", err)
	}
	snap := waitTerminal(t, rig, queued, 5*time.Second)
	if snap.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", snap.Status)
	}

	// 取消排队任务不能释放第一个任务占用的名额：再来一个仍应排队。
	third := submit(t, rig)
	if got := rig.task(t, third).Snapshot().Status; got != StatusQueued {
		t.Fatalf("third task status = %s, want queued (第一个任务仍占用名额)", got)
	}

	rig.exec.finish(t, running, "completed")
	waitStatus(t, rig, third, StatusRunning, 10*time.Second)
}

// 启动失败要落到 failed，并把名额还回去。
func TestSubmit_StartFailureFinalisesAsFailed(t *testing.T) {
	rig := newRig(t, Options{MaxRunning: 1})
	rig.exec.startErr = errors.New("boom")

	id := submit(t, rig)
	snap := waitTerminal(t, rig, id, 5*time.Second)
	if snap.Status != StatusFailed || snap.Error == "" {
		t.Fatalf("snapshot = %+v, want failed with an error message", snap)
	}

	// 名额已释放：下一个任务能立刻拿到。
	rig.exec.startErr = nil
	next := submit(t, rig)
	waitStatus(t, rig, next, StatusRunning, 10*time.Second)
}

// 引擎报错但进程正常退出时，仍要判为失败。
func TestRun_EngineErrorEventMarksTaskFailed(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	rig.exec.emit(t, id, scanstream.TypeError, func(ev *scanstream.Event) {
		ev.Error = &scanstream.ErrorEvent{Code: "scan_failed", Message: "runner failed"}
	})
	rig.exec.finish(t, id, "completed")

	snap := waitTerminal(t, rig, id, 5*time.Second)
	if snap.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", snap.Status)
	}
	if snap.Error != "runner failed" {
		t.Fatalf("error = %q, want runner failed", snap.Error)
	}
}

func TestRun_StoppedStatusBecomesCancelled(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)
	rig.exec.finish(t, id, "stopped")

	if snap := waitTerminal(t, rig, id, 5*time.Second); snap.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", snap.Status)
	}
}

// 订阅者消费太慢时会被断开并给出明确原因，客户端可带 last_seq 重连补齐。
func TestSubscribe_SlowConsumerIsDisconnectedWithReason(t *testing.T) {
	rig := newRig(t, Options{EventBuffer: 2})
	id := submit(t, rig)
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// 不消费，直接灌满通道。
	for i := 0; i < 200; i++ {
		rig.exec.emit(t, id, scanstream.TypeLog, func(ev *scanstream.Event) {
			ev.Log = &scanstream.LogEvent{Level: "info", Text: "x"}
		})
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-sub.Events():
			if !ok {
				if !errors.Is(sub.Err(), ErrSlowSubscriber) {
					t.Fatalf("Err = %v, want ErrSlowSubscriber", sub.Err())
				}
				return
			}
		case <-deadline:
			t.Fatal("slow subscriber was never disconnected")
		}
	}
}

// 任务 ID 必须跨进程唯一。
//
// 序号是进程内计数器，重启后会从 1 重来；若 ID 只有「日期-序号」，同一天里先后来起的
// 进程会生成同一个 ID，而 sqlite 的命中是按 task_id 关联的——旧任务的命中会串到新任务上。
func TestNextID_IsUniqueAcrossProcesses(t *testing.T) {
	const runs = 20
	day := time.Now().Format("20060102")
	seen := make(map[string]bool, runs)

	for i := 0; i < runs; i++ {
		mgr, err := New(Options{Executor: newFakeExecutor()})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		id := mgr.nextID()
		if !strings.HasPrefix(id, day+"-00001-") {
			t.Fatalf("id = %q, want the %s-00001-<suffix> shape", id, day)
		}
		if seen[id] {
			t.Fatalf("two processes generated the same task id %q", id)
		}
		seen[id] = true
	}
}

func TestList_PreservesSubmissionOrder(t *testing.T) {
	rig := newRig(t, Options{MaxRunning: 1})
	first := submit(t, rig)
	second := submit(t, rig)
	waitStatus(t, rig, first, StatusRunning, 10*time.Second)

	list := rig.mgr.List()
	if len(list) != 2 || list[0].ID != first || list[1].ID != second {
		t.Fatalf("list = %+v, want [%s %s]", list, first, second)
	}
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// scriptTask 给任务灌入一段固定的事件序列并结束它。
func scriptTask(t *testing.T, rig *testRig, id string) {
	t.Helper()
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)
	rig.exec.emit(t, id, scanstream.TypeScanInfo, func(ev *scanstream.Event) {
		ev.ScanInfo = &scanstream.ScanInfoEvent{TotalTargets: 1, TotalPocs: 2, TotalScans: 3}
	})
	for i := 1; i <= 3; i++ {
		finished := i
		rig.exec.emit(t, id, scanstream.TypeProgress, func(ev *scanstream.Event) {
			ev.Progress = &scanstream.ProgressEvent{Percent: finished * 33, Finished: int64(finished), Total: 3}
		})
	}
	rig.exec.finish(t, id, "completed")
}

func collectFrom(t *testing.T, rig *testRig, id string, fromSeq uint64) []*scanstream.Event {
	t.Helper()
	sub, _, err := rig.mgr.Subscribe(id, fromSeq)
	if err != nil {
		t.Fatalf("Subscribe(from_seq=%d): %v", fromSeq, err)
	}
	defer sub.Close()
	return collect(t, sub, 10*time.Second)
}

func waitStatus(t *testing.T, rig *testRig, id string, want Status, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rig.task(t, id).Snapshot().Status == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("task %s never reached status %s (now %s)", id, want, rig.task(t, id).Snapshot().Status)
}
