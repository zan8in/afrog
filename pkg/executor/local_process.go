package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

const (
	// Events 通道缓冲，避免 stdout 读协程因消费方短暂停顿而被阻塞。
	eventsBuffer = 256
	// Cancel 时 SIGTERM 到 SIGKILL 的默认等待时间。
	defaultKillGrace = 5 * time.Second
	// 子进程据此把写库结果归属到父进程持有的任务，见 pkg/db/db.go。
	taskIDEnvVar = "AFROG_TASK_ID"
)

// LocalProcess 通过拉起自身（或指定二进制）的子进程执行扫描。
type LocalProcess struct {
	// BinaryPath 为 afrog 二进制路径，为空时使用 os.Executable()。
	BinaryPath string
	// ExtraArgs 追加在参数末尾，供测试/调试使用。
	ExtraArgs []string
	// OnStderr 逐行接收子进程 stderr，可为 nil（默认丢弃）。
	OnStderr func(line string)
	// KillGrace 是 Cancel 时 SIGTERM 到 SIGKILL 的等待时间，默认 5s。
	KillGrace time.Duration
	// WorkDir 是子进程的工作目录。为空时每个任务使用独立的临时目录，并在进程
	// 退出后删除：afrog 会往工作目录写 HTML 报告与 resume 状态文件（每 10s 一次），
	// 默认继承控制面进程的 CWD 会在服务器目录里不断堆积垃圾文件。
	WorkDir string
}

// NewLocalProcess 创建本地进程执行器。
func NewLocalProcess() (*LocalProcess, error) {
	if _, err := os.Executable(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBinaryNotFound, err)
	}
	return &LocalProcess{}, nil
}

// resolveBinary 返回要拉起的二进制路径。
func (e *LocalProcess) resolveBinary() (string, error) {
	if e.BinaryPath != "" {
		if _, err := os.Stat(e.BinaryPath); err != nil {
			return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, e.BinaryPath)
		}
		return e.BinaryPath, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBinaryNotFound, err)
	}
	return p, nil
}

// Start 拉起子进程并返回句柄。
func (e *LocalProcess) Start(ctx context.Context, taskID string, spec *Spec) (Handle, error) {
	bin, err := e.resolveBinary()
	if err != nil {
		return nil, err
	}
	args, cleanup, err := buildArgs(taskID, spec)
	if err != nil {
		return nil, err
	}
	args = append(args, e.ExtraArgs...)

	// 子进程的工作目录：默认给每个任务一个独立临时目录，随进程退出一起删除。
	workDir := e.WorkDir
	if workDir == "" {
		prefix := "afrog-work-"
		if s := sanitizeTaskID(taskID); s != "" {
			prefix += s + "-"
		}
		dir, derr := os.MkdirTemp("", prefix+"*")
		if derr != nil {
			cleanup()
			return nil, fmt.Errorf("executor: create work dir: %w", derr)
		}
		workDir = dir
		prevCleanup := cleanup
		cleanup = func() {
			prevCleanup()
			_ = os.RemoveAll(dir)
		}
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = workDir
	// 注入任务 ID，让子进程写 sqlite 时带上父任务 ID（追加到既有环境变量之后）。
	cmd.Env = append(os.Environ(), taskIDEnvVar+"="+taskID)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("executor: open stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("executor: open stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("executor: start %s: %w", bin, err)
	}

	grace := e.KillGrace
	if grace <= 0 {
		grace = defaultKillGrace
	}
	h := &handle{
		cmd:      cmd,
		proc:     cmd.Process,
		pid:      cmd.Process.Pid,
		events:   make(chan *scanstream.Event, eventsBuffer),
		done:     make(chan struct{}),
		abort:    make(chan struct{}),
		onStderr: e.OnStderr,
		grace:    grace,
		cleanup:  cleanup,
	}
	go h.run(stdout, stderr)
	return h, nil
}

// handle 是 LocalProcess 启动的任务句柄，控制方法可并发调用。
type handle struct {
	cmd  *exec.Cmd
	proc *os.Process
	pid  int

	events chan *scanstream.Event
	done   chan struct{}
	abort  chan struct{}

	onStderr func(line string)
	grace    time.Duration
	cleanup  func()

	cancelOnce sync.Once
	mu         sync.Mutex
	finished   bool
	err        error
}

func (h *handle) Events() <-chan *scanstream.Event { return h.events }
func (h *handle) Done() <-chan struct{}            { return h.done }
func (h *handle) PID() int                         { return h.pid }

func (h *handle) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *handle) Pause() error {
	h.mu.Lock()
	finished := h.finished
	h.mu.Unlock()
	if finished {
		return ErrAlreadyDone
	}
	return pauseProcess(h.proc)
}

func (h *handle) Resume() error {
	h.mu.Lock()
	finished := h.finished
	h.mu.Unlock()
	if finished {
		return ErrAlreadyDone
	}
	return resumeProcess(h.proc)
}

func (h *handle) Cancel() error {
	h.mu.Lock()
	finished := h.finished
	h.mu.Unlock()
	if finished {
		return ErrAlreadyDone
	}

	h.cancelOnce.Do(func() {
		// 先 SIGTERM 让子进程有机会收尾；宽限期内未退出再 SIGKILL。
		_ = terminateProcess(h.proc)
		go func() {
			select {
			case <-h.done:
			case <-time.After(h.grace):
				_ = h.proc.Kill()
			}
		}()
		// 关闭 abort 让 stdout 读协程停止向无人消费的通道发送，保证 Done 能及时关闭。
		close(h.abort)
	})
	return nil
}

// run 读取子进程输出并等待退出，最后关闭 Done。
func (h *handle) run(stdout, stderr io.Reader) {
	var stderrWG sync.WaitGroup
	stderrWG.Add(1)
	go func() {
		defer stderrWG.Done()
		h.drainStderr(stderr)
	}()

	h.readStdout(stdout)
	close(h.events)

	// 子进程退出会关闭 stderr 写端，先等 stderr 读完再 Wait，避免 Wait 关闭管道
	// 导致 stderr 尾部日志丢失。
	stderrWG.Wait()

	// 先等 stdout 读完再 Wait，保证 done 事件不会因进程退出而丢失。
	err := h.cmd.Wait()
	if h.cleanup != nil {
		h.cleanup()
	}

	h.mu.Lock()
	h.finished = true
	if err != nil {
		h.err = fmt.Errorf("executor: process exited: %w", err)
	}
	h.mu.Unlock()
	close(h.done)
}

// readStdout 逐行读取并解析事件。
//
// 这里刻意不用 bufio.Scanner：它的默认单行上限是 64KB，超长的请求/响应证据行会触发
// ErrTooLong 而丢事件。bufio.Reader.ReadBytes 按需扩容，可容纳任意长度的单行。
func (h *handle) readStdout(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			h.parseLine(line)
		}
		if err != nil {
			return
		}
		select {
		case <-h.abort:
			return
		default:
		}
	}
}

// parseLine 解析一行 NDJSON；无法解析的行（子进程的诊断输出等）直接丢弃，不影响后续事件。
func (h *handle) parseLine(line []byte) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return
	}
	ev, err := scanstream.Parse(trimmed)
	if err != nil {
		return
	}
	select {
	case h.events <- &ev:
	case <-h.abort:
	}
}

// drainStderr 持续读取 stderr：管道写满会阻塞子进程，必须读干。
func (h *handle) drainStderr(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 && h.onStderr != nil {
			h.onStderr(string(bytes.TrimRight(line, "\r\n")))
		}
		if err != nil {
			return
		}
	}
}
