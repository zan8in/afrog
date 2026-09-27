package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// startHelper 用当前测试二进制作为“afrog 二进制”拉起一个 helper 子进程。
// helper 通过环境变量分流，见 helper_test.go 的 TestMain。
func startHelper(t *testing.T, scenario, taskID string, spec *Spec) Handle {
	t.Helper()
	t.Setenv(helperEnv, "1")
	t.Setenv(scenarioEnv, scenario)
	if spec == nil {
		spec = &Spec{Targets: []string{"http://127.0.0.1:1"}}
	}
	lp := &LocalProcess{BinaryPath: os.Args[0]}
	h, err := lp.Start(context.Background(), taskID, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return h
}

// collectEvents 读完事件通道，超时直接失败。
func collectEvents(t *testing.T, h Handle, timeout time.Duration) []*scanstream.Event {
	t.Helper()
	deadline := time.After(timeout)
	var events []*scanstream.Event
	for {
		select {
		case ev, ok := <-h.Events():
			if !ok {
				return events
			}
			events = append(events, ev)
		case <-deadline:
			t.Fatalf("timeout waiting for events, got %d", len(events))
		}
	}
}

func waitDone(t *testing.T, h Handle, timeout time.Duration) {
	t.Helper()
	select {
	case <-h.Done():
	case <-time.After(timeout):
		t.Fatal("Done() did not close in time")
	}
}

func TestLocalProcess_EventOrderAndDone(t *testing.T) {
	h := startHelper(t, "events", "task-abc", nil)
	if h.PID() <= 0 {
		t.Fatalf("PID = %d, want > 0", h.PID())
	}

	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if err := h.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}

	want := []string{
		scanstream.TypeStatus,
		scanstream.TypeStatus,
		scanstream.TypeResult,
		scanstream.TypeDone,
	}
	if len(events) != len(want) {
		t.Fatalf("got %d events, want %d: %v", len(events), len(want), eventTypes(events))
	}
	for i, ty := range want {
		if events[i].Type != ty {
			t.Fatalf("event %d type = %q, want %q (all: %v)", i, events[i].Type, ty, eventTypes(events))
		}
	}
	if events[3].Done == nil || events[3].Done.Status != "completed" {
		t.Fatalf("done payload mismatch: %+v", events[3].Done)
	}
}

// 超长单行（>200KB）必须能完整解析：用于验证没有踩 bufio.Scanner 的 64KB 上限。
func TestLocalProcess_LongLineIsParsed(t *testing.T) {
	h := startHelper(t, "longline", "task-long", nil)
	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if err := h.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if len(events) != 1 || events[0].Result == nil || events[0].Result.Evidence == nil {
		t.Fatalf("unexpected events: %v", eventTypes(events))
	}
	resp := events[0].Result.Evidence.Exchanges[0].Response
	if len(resp) != 250*1024 {
		t.Fatalf("long line truncated: got %d bytes, want %d", len(resp), 250*1024)
	}
}

// helper 打印非 JSON 行时，既不能失败，也不能影响后续事件的解析。
func TestLocalProcess_NonJSONLinesAreIgnored(t *testing.T) {
	h := startHelper(t, "noise", "task-noise", nil)
	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if err := h.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %v", len(events), eventTypes(events))
	}
	if events[0].Log == nil || events[0].Log.Text != "first" {
		t.Fatalf("first log mismatch: %+v", events[0].Log)
	}
	if events[1].Log == nil || events[1].Log.Text != "second" {
		t.Fatalf("second log mismatch: %+v", events[1].Log)
	}
}

func TestLocalProcess_NonZeroExitSetsErr(t *testing.T) {
	h := startHelper(t, "fail", "task-fail", nil)
	collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	err := h.Err()
	if err == nil {
		t.Fatal("Err = nil, want non-nil for non-zero exit")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Err = %v (%T), want wrapped *exec.ExitError", err, err)
	}

	// 已结束的任务再做控制操作应返回 ErrAlreadyDone。
	if err := h.Cancel(); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Cancel after done = %v, want ErrAlreadyDone", err)
	}
	if err := h.Pause(); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Pause after done = %v, want ErrAlreadyDone", err)
	}
	if err := h.Resume(); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Resume after done = %v, want ErrAlreadyDone", err)
	}
}

func TestLocalProcess_CancelStopsProcess(t *testing.T) {
	h := startHelper(t, "sleep", "task-cancel", nil)
	if h.PID() <= 0 {
		t.Fatalf("PID = %d, want > 0", h.PID())
	}
	if err := h.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	// SIGTERM 应能让 sleep 中的 helper 很快退出。
	waitDone(t, h, 10*time.Second)
}

func TestLocalProcess_PauseResume(t *testing.T) {
	h := startHelper(t, "sleep", "task-pause", nil)
	defer func() { _ = h.Cancel() }()

	if runtime.GOOS == "windows" {
		if err := h.Pause(); !errors.Is(err, ErrPauseUnsupported) {
			t.Fatalf("Pause on windows = %v, want ErrPauseUnsupported", err)
		}
		if err := h.Resume(); !errors.Is(err, ErrPauseUnsupported) {
			t.Fatalf("Resume on windows = %v, want ErrPauseUnsupported", err)
		}
		return
	}

	if err := h.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := h.Resume(); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := h.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	waitDone(t, h, 10*time.Second)
}

// 子进程必须收到 AFROG_TASK_ID，供写 sqlite 时关联父任务。
func TestLocalProcess_InjectsTaskIDEnv(t *testing.T) {
	const taskID = "parent-task-42"
	h := startHelper(t, "taskid", taskID, nil)
	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if err := h.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if len(events) != 1 || events[0].Log == nil {
		t.Fatalf("unexpected events: %v", eventTypes(events))
	}
	if events[0].Log.Text != taskID {
		t.Fatalf("AFROG_TASK_ID = %q, want %q", events[0].Log.Text, taskID)
	}
}

// 子进程必须在独立的临时工作目录里运行，且该目录在进程退出后被删除：
// afrog 会往 CWD 写 HTML 报告与 resume 状态文件，继承控制面进程的 CWD 会在
// 服务器目录里不断堆积垃圾文件。
func TestLocalProcess_ChildRunsInIsolatedWorkDir(t *testing.T) {
	parentWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	h := startHelper(t, "cwd", "task-cwd", nil)
	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if err := h.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if len(events) != 1 || events[0].Log == nil {
		t.Fatalf("unexpected events: %v", eventTypes(events))
	}
	childWD := events[0].Log.Text
	if childWD == "" {
		t.Fatal("child work dir is empty")
	}
	if childWD == parentWD {
		t.Fatalf("child inherited parent CWD %q", parentWD)
	}
	if _, statErr := os.Stat(childWD); !os.IsNotExist(statErr) {
		t.Fatalf("work dir %q should be removed after exit, stat err = %v", childWD, statErr)
	}
}

// WorkDir 显式指定时应原样使用，且不被执行器删除。
func TestLocalProcess_ExplicitWorkDirIsKept(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(helperEnv, "1")
	t.Setenv(scenarioEnv, "cwd")
	lp := &LocalProcess{BinaryPath: os.Args[0], WorkDir: dir}
	h, err := lp.Start(context.Background(), "task-cwd2", &Spec{Targets: []string{"http://127.0.0.1:1"}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events := collectEvents(t, h, 15*time.Second)
	waitDone(t, h, 10*time.Second)

	if len(events) != 1 || events[0].Log == nil {
		t.Fatalf("unexpected events: %v", eventTypes(events))
	}
	// macOS 的 /var 是 /private/var 的符号链接，两边的 Getwd 结果可能不同，用 SameFile 比较。
	if !sameDir(t, events[0].Log.Text, dir) {
		t.Fatalf("child work dir = %q, want %q", events[0].Log.Text, dir)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("explicit work dir must be kept, stat err = %v", statErr)
	}
}

// sameDir 判断两个路径是否指向同一目录（兼容 macOS 符号链接）。
func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

func TestLocalProcess_BinaryNotFound(t *testing.T) {
	lp := &LocalProcess{BinaryPath: filepath.Join(t.TempDir(), "definitely-missing")}
	_, err := lp.Start(context.Background(), "t", &Spec{Targets: []string{"http://a.example"}})
	if !errors.Is(err, ErrBinaryNotFound) {
		t.Fatalf("err = %v, want ErrBinaryNotFound", err)
	}
}

func TestLocalProcess_NoTargets(t *testing.T) {
	lp := &LocalProcess{BinaryPath: os.Args[0]}
	_, err := lp.Start(context.Background(), "t", &Spec{})
	if err == nil {
		t.Fatal("want error for empty targets")
	}
	if errors.Is(err, ErrBinaryNotFound) {
		t.Fatalf("err = %v, should be a spec error, not binary error", err)
	}
}

func eventTypes(events []*scanstream.Event) []string {
	types := make([]string, 0, len(events))
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	return types
}
