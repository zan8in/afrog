package mcp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

// ---------------------------------------------------------------------------
// 测试替身：可控事件流的执行器。
//
// task.* 的语义全部落在控制面任务表上，与「谁在跑扫描」无关。这里用假执行器把任务
// 生命周期交给测试自行推进（何时发事件、何时收尾），从而不拉真子进程也能覆盖
// 状态查询、事件增量拉取与控制动作。
// ---------------------------------------------------------------------------

type fakeScanHandle struct {
	events chan *scanstream.Event
	done   chan struct{}

	mu     sync.Mutex
	closed bool
	paused bool
}

func (h *fakeScanHandle) Events() <-chan *scanstream.Event { return h.events }
func (h *fakeScanHandle) Done() <-chan struct{}            { return h.done }
func (h *fakeScanHandle) Err() error                       { return nil }
func (h *fakeScanHandle) PID() int                         { return 4242 }

func (h *fakeScanHandle) Pause() error {
	h.mu.Lock()
	h.paused = true
	h.mu.Unlock()
	return nil
}

func (h *fakeScanHandle) Resume() error {
	h.mu.Lock()
	h.paused = false
	h.mu.Unlock()
	return nil
}

// Cancel 模拟「子进程被杀 → stdout 读完 → 事件流关闭」：控制面的 run 循环因此结束。
func (h *fakeScanHandle) Cancel() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return executor.ErrAlreadyDone
	}
	h.closed = true
	h.mu.Unlock()
	close(h.events)
	close(h.done)
	return nil
}

func (h *fakeScanHandle) emit(ev *scanstream.Event) { h.events <- ev }

type fakeScanExecutor struct {
	mu      sync.Mutex
	handles map[string]*fakeScanHandle
}

func newFakeScanExecutor() *fakeScanExecutor {
	return &fakeScanExecutor{handles: map[string]*fakeScanHandle{}}
}

func (f *fakeScanExecutor) Start(_ context.Context, taskID string, _ *executor.Spec) (executor.Handle, error) {
	h := &fakeScanHandle{
		events: make(chan *scanstream.Event, 512),
		done:   make(chan struct{}),
	}
	f.mu.Lock()
	f.handles[taskID] = h
	f.mu.Unlock()
	return h, nil
}

// waitHandle 等执行器真正拉起句柄。Start 由控制面在自己的 goroutine 里调用，因此
// 提交返回后句柄不一定就绪。
func (f *fakeScanExecutor) waitHandle(t *testing.T, taskID string) *fakeScanHandle {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		h, ok := f.handles[taskID]
		f.mu.Unlock()
		if ok {
			return h
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("executor never started task %s", taskID)
	return nil
}

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

// newTaskTestServer 装配一个注入了假执行器的工具面：task.* 因此可在无子进程的情况下
// 驱动完整任务生命周期。
func newTaskTestServer(t *testing.T, policyYAML string) (*Server, *fakeScanExecutor) {
	t.Helper()
	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	ex := newFakeScanExecutor()
	return New(Options{Policy: p, Executor: ex}), ex
}

func taskMgrOf(t *testing.T, s *Server) *scantask.Manager {
	t.Helper()
	mgr, err := s.taskManager()
	if err != nil {
		t.Fatalf("task manager: %v", err)
	}
	return mgr
}

// submitFakeTask 直接向控制面提交一次扫描式任务，并等到假执行器把句柄拉起。
func submitFakeTask(t *testing.T, s *Server, ex *fakeScanExecutor) (string, *fakeScanHandle) {
	t.Helper()
	mgr := taskMgrOf(t, s)
	snap, err := mgr.SubmitSpec(&executor.Spec{Targets: []string{"http://127.0.0.1:1/"}}, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return snap.ID, ex.waitHandle(t, snap.ID)
}

// callTaskTool 调用一个工具处理器并取回 map 结果。
func callTaskTool(t *testing.T, s *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	out, err := s.tools[name].Handler(context.Background(), mustJSON(t, args))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("%s: result type = %T, want map", name, out)
	}
	return m
}

// callTaskToolErr 调用一个工具处理器并取回错误（用于断言被拒绝/未找到的路径）。
func callTaskToolErr(t *testing.T, s *Server, name string, args map[string]any) error {
	t.Helper()
	_, err := s.tools[name].Handler(context.Background(), mustJSON(t, args))
	return err
}

func waitTaskStatus(t *testing.T, mgr *scantask.Manager, taskID string, want scantask.Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if t, ok := mgr.Get(taskID); ok && t.Status() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("task %s never reached status %s", taskID, want)
}

func waitTerminalTask(t *testing.T, mgr *scantask.Manager, taskID string) *scantask.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if task, ok := mgr.Get(taskID); ok {
			if snap := task.Snapshot(); snap.Status.Terminal() {
				return snap
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("task %s never reached a terminal status", taskID)
	return nil
}

// waitEventCount 等到任务缓冲里至少有 n 条事件：事件由控制面在别的 goroutine 里吸收，
// 发出后不能立刻假定已入缓冲。
func waitEventCount(t *testing.T, mgr *scantask.Manager, taskID string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if evs, _, err := mgr.Events(taskID, 0); err == nil && len(evs) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("task %s never buffered %d events", taskID, n)
}

// finishFakeTask 让任务正常收尾：先发 done（带汇总），再关闭事件流，等任务到终态。
func finishFakeTask(t *testing.T, mgr *scantask.Manager, taskID string, h *fakeScanHandle) {
	t.Helper()
	h.emit(&scanstream.Event{Type: scanstream.TypeDone, Done: &scanstream.DoneEvent{
		Status:  "completed",
		Summary: &scanstream.Summary{Executed: 3, Found: 1, BySeverity: map[string]int64{"high": 1}},
	}})
	if err := h.Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
		t.Fatalf("finish: %v", err)
	}
	waitTerminalTask(t, mgr, taskID)
}

// ---------------------------------------------------------------------------
// 注册与注解
// ---------------------------------------------------------------------------

// task.* 四个工具必须全部注册；只读的三个要与策略「只读档」口径一致，控制工具不能
// 被标成只读。task.status 的返回结构是稳定契约，需声明 outputSchema。
func TestTaskToolsRegisteredAndAnnotated(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	byName := map[string]map[string]any{}
	for _, e := range s.toolList() {
		byName[e["name"].(string)] = e
	}
	for _, name := range []string{"task.list", "task.status", "task.events", "task.control"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("%s must be registered", name)
		}
	}

	for _, name := range []string{"task.list", "task.status", "task.events"} {
		a, ok := byName[name]["annotations"].(ToolAnnotations)
		if !ok {
			t.Fatalf("%s must carry annotations", name)
		}
		if !a.ReadOnlyHint || !a.IdempotentHint || a.OpenWorldHint || a.DestructiveHint {
			t.Fatalf("%s annotations = %+v, want readOnly+idempotent and neither openWorld nor destructive", name, a)
		}
	}
	if a := byName["task.control"]["annotations"].(ToolAnnotations); a.ReadOnlyHint {
		t.Fatalf("task.control annotations = %+v, want not readOnly", a)
	}

	if byName["task.status"]["outputSchema"] == nil {
		t.Fatal("task.status must declare outputSchema")
	}

	// instructions 要把「长任务转句柄后怎么办」讲清楚，否则模型会把 pending 当失败。
	for _, want := range []string{"task.status", "task.events", "task_id"} {
		if !strings.Contains(Instructions, want) {
			t.Fatalf("instructions must mention %s", want)
		}
	}
}

// scan.start 把长任务转成句柄后，返回体必须仍对 outputSchema 合法，并给出 task_id
// 与 pending 结论——否则调用方会把「还没跑完」读成「无漏洞」。
func TestPendingScanResultShape(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	schema, _ := s.tools["scan.start"].OutputSchema.(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["task_id"]; !ok {
		t.Fatal("scan.start outputSchema must declare task_id")
	}

	got := pendingScanResult("http://target/", "thinkphp", "20260101-00001-abcdef", string(scantask.StatusRunning), 7)
	if got["conclusion"] != "pending" {
		t.Fatalf("conclusion = %v, want pending", got["conclusion"])
	}
	if got["task_id"] != "20260101-00001-abcdef" {
		t.Fatalf("task_id = %v", got["task_id"])
	}
	if got["found"] != false {
		t.Fatalf("found = %v, want false (还没跑完不能宣称命中)", got["found"])
	}
	if items, ok := got["results"].([]map[string]any); !ok || len(items) != 0 {
		t.Fatalf("results = %#v, want an empty array", got["results"])
	}
	if lib, _ := got["library"].(map[string]any); lib["matched_pocs"] != 7 {
		t.Fatalf("library = %#v, want matched_pocs=7", got["library"])
	}
	if g, _ := got["guidance"].(string); !strings.Contains(g, "task.status") {
		t.Fatalf("guidance must point at task.status: %q", g)
	}
}

// ---------------------------------------------------------------------------
// 策略门控
// ---------------------------------------------------------------------------

// 只读档放行 task.list / task.status / task.events（只读任务表），拒绝 task.control
// （它会改变任务状态）；safe 档允许控制。
func TestTaskToolsPolicyGate(t *testing.T) {
	ro := New(Options{Policy: policy.Default()})
	for _, name := range []string{"task.list", "task.status", "task.events"} {
		if err := ro.gate.Take(policy.Action{Name: name}, 0); err != nil {
			t.Fatalf("%s must be allowed under readonly policy: %v", name, err)
		}
	}
	if err := ro.gate.Take(policy.Action{Name: "task.control"}, 0); err == nil {
		t.Fatal("task.control must be denied under readonly policy")
	}

	safe := New(Options{Policy: &policy.Policy{Mode: policy.ModeSafe}})
	if err := safe.gate.Take(policy.Action{Name: "task.control"}, 0); err != nil {
		t.Fatalf("task.control must be allowed under safe policy: %v", err)
	}
}

// 只读档下 task.control 的处理器要如实报策略拒绝，且不扣任何额度。
func TestTaskControlDeniedByReadOnlyPolicy(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")

	err := callTaskToolErr(t, s, "task.control", map[string]any{"task_id": "x", "action": "cancel"})
	if err == nil || !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("err = %v, want a policy denial", err)
	}
	if got := s.gate.Budget().Remaining(); got != policy.DefaultRequests {
		t.Fatalf("budget after denial = %d, want %d", got, policy.DefaultRequests)
	}
}

// ---------------------------------------------------------------------------
// task.list
// ---------------------------------------------------------------------------

// task.list 默认最新在前，支持按状态过滤与条数上限。
func TestTaskListNewestFirstAndFilters(t *testing.T) {
	s, ex := newTaskTestServer(t, "mode: safe\n")
	mgr := taskMgrOf(t, s)

	olderID, olderH := submitFakeTask(t, s, ex)
	waitTaskStatus(t, mgr, olderID, scantask.StatusRunning)
	finishFakeTask(t, mgr, olderID, olderH)

	newerID, _ := submitFakeTask(t, s, ex)
	waitTaskStatus(t, mgr, newerID, scantask.StatusRunning)

	all := callTaskTool(t, s, "task.list", map[string]any{})
	tasks, ok := all["tasks"].([]map[string]any)
	if !ok {
		t.Fatalf("tasks type = %T, want []map", all["tasks"])
	}
	if len(tasks) != 2 || all["count"] != 2 {
		t.Fatalf("list = %#v, want 2 tasks", all)
	}
	if tasks[0]["task_id"] != newerID || tasks[1]["task_id"] != olderID {
		t.Fatalf("list order = [%v %v], want newest-first [%v %v]",
			tasks[0]["task_id"], tasks[1]["task_id"], newerID, olderID)
	}

	completed := callTaskTool(t, s, "task.list", map[string]any{"status": "completed"})
	ct := completed["tasks"].([]map[string]any)
	if len(ct) != 1 || ct[0]["task_id"] != olderID {
		t.Fatalf("status=completed list = %#v, want only %s", ct, olderID)
	}

	running := callTaskTool(t, s, "task.list", map[string]any{"status": "running"})
	rt := running["tasks"].([]map[string]any)
	if len(rt) != 1 || rt[0]["task_id"] != newerID {
		t.Fatalf("status=running list = %#v, want only %s", rt, newerID)
	}

	limited := callTaskTool(t, s, "task.list", map[string]any{"limit": 1})
	lt := limited["tasks"].([]map[string]any)
	if len(lt) != 1 || lt[0]["task_id"] != newerID {
		t.Fatalf("limit=1 list = %#v, want only the newest %s", lt, newerID)
	}

	none := callTaskTool(t, s, "task.list", map[string]any{"status": "no_such_status"})
	if nt := none["tasks"].([]map[string]any); len(nt) != 0 {
		t.Fatalf("unknown status filter = %#v, want empty", nt)
	}
}

// ---------------------------------------------------------------------------
// task.status
// ---------------------------------------------------------------------------

// task.status 缺参报错、任务不存在报错；完成的任务要把状态、命中与收尾汇总如实带出。
func TestTaskStatusTool(t *testing.T) {
	s, ex := newTaskTestServer(t, "mode: safe\n")
	mgr := taskMgrOf(t, s)

	if err := callTaskToolErr(t, s, "task.status", map[string]any{}); err == nil ||
		!strings.Contains(err.Error(), "task_id is required") {
		t.Fatalf("missing task_id err = %v, want a required error", err)
	}
	if err := callTaskToolErr(t, s, "task.status", map[string]any{"task_id": "no-such-task"}); err == nil ||
		!strings.Contains(err.Error(), "task not found") {
		t.Fatalf("unknown task err = %v, want task not found", err)
	}

	id, h := submitFakeTask(t, s, ex)
	waitTaskStatus(t, mgr, id, scantask.StatusRunning)

	h.emit(&scanstream.Event{Type: scanstream.TypeResult, Result: &scanstream.ResultEvent{
		PocID: "poc-x", PocName: "X", Severity: "high", Target: "http://127.0.0.1:1/",
	}})
	finishFakeTask(t, mgr, id, h)

	view := callTaskTool(t, s, "task.status", map[string]any{"task_id": id})
	if view["task_id"] != id || view["status"] != "completed" {
		t.Fatalf("status view = %#v, want id=%s status=completed", view, id)
	}
	if view["hit_total"] != 1 {
		t.Fatalf("hit_total = %v, want 1", view["hit_total"])
	}
	hits, _ := view["hits"].(map[string]int)
	if hits["high"] != 1 {
		t.Fatalf("hits = %#v, want high=1", view["hits"])
	}
	summary, _ := view["summary"].(map[string]any)
	if summary == nil || summary["found"] != int64(1) || summary["executed"] != int64(3) {
		t.Fatalf("summary = %#v, want executed=3 found=1", view["summary"])
	}
	targets, _ := view["targets"].([]string)
	if len(targets) != 1 || targets[0] != "http://127.0.0.1:1/" {
		t.Fatalf("targets = %#v", view["targets"])
	}
}

// ---------------------------------------------------------------------------
// task.events
// ---------------------------------------------------------------------------

// task.events 是拉取式增量：from_seq=0 取全部、带上 last_seq 再取只拿新增；limit 生效
// 时 has_more 为真。
func TestTaskEventsIncrementalPull(t *testing.T) {
	s, ex := newTaskTestServer(t, "mode: safe\n")
	mgr := taskMgrOf(t, s)

	if err := callTaskToolErr(t, s, "task.events", map[string]any{"task_id": "no-such-task"}); err == nil ||
		!strings.Contains(err.Error(), "task not found") {
		t.Fatalf("unknown task err = %v, want task not found", err)
	}

	id, h := submitFakeTask(t, s, ex)
	waitTaskStatus(t, mgr, id, scantask.StatusRunning)
	h.emit(&scanstream.Event{Type: scanstream.TypeProgress, Progress: &scanstream.ProgressEvent{Percent: 10, Finished: 1, Total: 10}})
	waitEventCount(t, mgr, id, 3) // starting + running + progress

	first := callTaskTool(t, s, "task.events", map[string]any{"task_id": id, "from_seq": 0})
	events, ok := first["events"].([]map[string]any)
	if !ok {
		t.Fatalf("events type = %T, want []map", first["events"])
	}
	if first["count"] != len(events) || len(events) < 3 {
		t.Fatalf("events = %#v, want at least 3 and count to match", first)
	}
	if first["done"] != false {
		t.Fatalf("done = %v, want false while running", first["done"])
	}
	if first["status"] != "running" {
		t.Fatalf("status = %v, want running", first["status"])
	}

	// seq 必须从 1 开始且严格递增（控制面按 seq 编号，调用方据此不重不漏）。
	prev := uint64(0)
	for i, ev := range events {
		seq, _ := ev["seq"].(uint64)
		if seq <= prev {
			t.Fatalf("event[%d] seq = %d, want > %d", i, seq, prev)
		}
		prev = seq
	}
	if s0, _ := events[0]["seq"].(uint64); s0 != 1 {
		t.Fatalf("first seq = %d, want 1", s0)
	}
	if last := events[len(events)-1]; last["type"] != "progress" {
		t.Fatalf("last event = %#v, want the progress event", last)
	}

	lastSeq, _ := first["last_seq"].(uint64)
	if lastSeq != prev {
		t.Fatalf("last_seq = %d, want %d", lastSeq, prev)
	}

	// 带上次的 last_seq 再拉：没有新增事件。
	again := callTaskTool(t, s, "task.events", map[string]any{"task_id": id, "from_seq": lastSeq})
	if again["count"] != 0 || again["has_more"] != false {
		t.Fatalf("incremental pull = %#v, want empty", again)
	}
	if again["last_seq"] != lastSeq {
		t.Fatalf("last_seq after empty pull = %v, want %d", again["last_seq"], lastSeq)
	}

	// limit 生效：只返回一条，并标记还有更多。
	limited := callTaskTool(t, s, "task.events", map[string]any{"task_id": id, "from_seq": 0, "limit": 1})
	le, _ := limited["events"].([]map[string]any)
	if len(le) != 1 || limited["has_more"] != true {
		t.Fatalf("limit=1 pull = %#v, want 1 event with has_more", limited)
	}
	if ls, _ := limited["last_seq"].(uint64); ls != 1 {
		t.Fatalf("limit=1 last_seq = %d, want 1", ls)
	}
}

// ---------------------------------------------------------------------------
// task.control
// ---------------------------------------------------------------------------

// task.control 的取消/暂停/恢复，以及入参校验。
func TestTaskControlActions(t *testing.T) {
	s, ex := newTaskTestServer(t, "mode: safe\n")
	mgr := taskMgrOf(t, s)

	if err := callTaskToolErr(t, s, "task.control", map[string]any{"task_id": "x", "action": "explode"}); err == nil ||
		!strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("unknown action err = %v, want unknown action", err)
	}
	if err := callTaskToolErr(t, s, "task.control", map[string]any{"task_id": "no-such-task", "action": "cancel"}); err == nil ||
		!strings.Contains(err.Error(), "task not found") {
		t.Fatalf("unknown task err = %v, want task not found", err)
	}

	id, _ := submitFakeTask(t, s, ex)
	waitTaskStatus(t, mgr, id, scantask.StatusRunning)

	paused := callTaskTool(t, s, "task.control", map[string]any{"task_id": id, "action": "pause"})
	if paused["status"] != "paused" || paused["action"] != "pause" {
		t.Fatalf("pause view = %#v, want status=paused action=pause", paused)
	}

	resumed := callTaskTool(t, s, "task.control", map[string]any{"task_id": id, "action": "resume"})
	if resumed["status"] != "running" || resumed["action"] != "resume" {
		t.Fatalf("resume view = %#v, want status=running action=resume", resumed)
	}

	cancelled := callTaskTool(t, s, "task.control", map[string]any{"task_id": id, "action": "cancel"})
	if cancelled["action"] != "cancel" {
		t.Fatalf("cancel view = %#v, want action=cancel", cancelled)
	}
	if snap := waitTerminalTask(t, mgr, id); snap.Status != scantask.StatusCancelled {
		t.Fatalf("status after cancel = %s, want cancelled", snap.Status)
	}
}
