package scantask

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/gologger"
)

// Manager 是控制面的任务管理器：受理扫描、限制并发、驱动执行器、收尾广播。
//
// 并发模型：m.mu 只保护任务表与排队状态，任务自身的字段由 Task.mu 保护；
// 任何「先持 m.mu 再持 Task.mu」的调用都不存在逆向路径，因此不会死锁。
type Manager struct {
	opts Options
	node string
	// idSuffix 是本进程的任务 ID 后缀，见 nextID。
	idSuffix string

	mu        sync.Mutex
	tasks     map[string]*Task
	order     []string
	running   int
	queue     []string
	seqByDate map[string]int
}

// New 创建任务管理器。
func New(opts Options) (*Manager, error) {
	if opts.Executor == nil {
		return nil, errors.New("scantask: executor is required")
	}
	return &Manager{
		opts:      opts,
		node:      opts.node(),
		idSuffix:  processSuffix(),
		tasks:     make(map[string]*Task),
		seqByDate: make(map[string]int),
	}, nil
}

// Node 返回本控制面的节点名。
func (m *Manager) Node() string { return m.node }

// Submit 受理一次扫描：解析规格、登记任务、取得名额后开始执行。
// 并发已满时任务进入排队，状态为 queued。
func (m *Manager) Submit(req Request) (*Snapshot, error) {
	spec, cleanup, err := BuildSpec(req)
	if err != nil {
		return nil, err
	}

	t := newTask(m.nextID(), m.node, spec, cleanup, m.opts.eventBuffer(), m.opts.now)

	m.mu.Lock()
	m.tasks[t.id] = t
	m.order = append(m.order, t.id)
	m.mu.Unlock()

	m.schedule(t)
	return t.Snapshot(), nil
}

// Get 按 ID 取任务。
func (m *Manager) Get(taskID string) (*Task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[taskID]
	return t, ok
}

// List 按创建顺序返回所有任务的状态快照。
func (m *Manager) List() []*Snapshot {
	m.mu.Lock()
	tasks := make([]*Task, 0, len(m.order))
	for _, id := range m.order {
		if t, ok := m.tasks[id]; ok {
			tasks = append(tasks, t)
		}
	}
	m.mu.Unlock()

	out := make([]*Snapshot, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, t.Snapshot())
	}
	return out
}

// Subscribe 订阅任务事件。fromSeq 是调用方已经收到的最大 seq（0 表示从头取），
// 返回的 Subscription 会先补发窗口内的事件再持续推送。
func (m *Manager) Subscribe(taskID string, fromSeq uint64) (*Subscription, *Snapshot, error) {
	t, ok := m.Get(taskID)
	if !ok {
		return nil, nil, ErrTaskNotFound
	}
	return t.subscribe(fromSeq), t.Snapshot(), nil
}

// Control 对任务执行暂停/继续/取消。
func (m *Manager) Control(taskID string, action Action) error {
	t, ok := m.Get(taskID)
	if !ok {
		return ErrTaskNotFound
	}

	if action == ActionCancel {
		// 排队中的任务还没有进程：直接从队列摘掉并收尾（不占用名额）。
		if m.cancelQueued(t) {
			return nil
		}
	}

	h := t.handleRef()
	if h == nil {
		return ErrNoProcess
	}

	switch action {
	case ActionPause:
		if err := h.Pause(); err != nil {
			return err
		}
		t.setStatus(StatusPaused)
	case ActionResume:
		if err := h.Resume(); err != nil {
			return err
		}
		t.setStatus(StatusRunning)
	case ActionCancel:
		if err := h.Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
			return err
		}
		t.setErr("任务已被取消")
		m.finalize(t, StatusCancelled)
	default:
		return fmt.Errorf("scantask: unknown action %d", action)
	}
	return nil
}

// schedule 取得运行名额并拉起执行；名额不足则排队。
func (m *Manager) schedule(t *Task) {
	m.mu.Lock()
	if m.running >= m.opts.maxRunning() {
		m.queue = append(m.queue, t.id)
		m.mu.Unlock()
		gologger.Debug().Msgf("scan queued: taskId=%s running=%d maxRunning=%d", t.ID(), m.running, m.opts.maxRunning())
		t.setStatus(StatusQueued)
		return
	}
	m.running++
	m.mu.Unlock()

	t.setStatus(StatusStarting)
	go m.run(t)
}

// run 拉起子进程、吸收事件，最后按引擎自报的收尾状态折算任务状态。
func (m *Manager) run(t *Task) {
	h, err := m.opts.Executor.Start(context.Background(), t.ID(), t.spec)
	if err != nil {
		gologger.Warning().Str("taskId", t.ID()).Str("error", err.Error()).Msg("scan failed to start")
		t.setErr(err.Error())
		m.finalize(t, StatusFailed)
		return
	}

	t.setHandle(h)
	t.setStatus(StatusRunning)

	for ev := range h.Events() {
		t.apply(ev)
	}

	doneStatus, errText := t.doneState()
	m.finalize(t, terminalStatus(h.Err(), doneStatus, errText))
}

// cancelQueued 取消一个仍在排队、从未占用运行名额的任务。
// 返回 false 表示它已经被收尾路径取走执行。
//
// 队列的增删一律在 m.mu 下进行，因此「从队列里找到它」就等价于「它还没被执行」。
func (m *Manager) cancelQueued(t *Task) bool {
	m.mu.Lock()
	idx := -1
	for i, id := range m.queue {
		if id == t.ID() {
			idx = i
			break
		}
	}
	if idx < 0 {
		m.mu.Unlock()
		return false
	}
	m.queue = append(m.queue[:idx], m.queue[idx+1:]...)
	m.mu.Unlock()

	if !t.markFinalized() {
		return true
	}
	gologger.Debug().Msgf("scan cancelled while queued: taskId=%s", t.ID())
	t.setStatus(StatusCancelled)
	t.closeSubscribers()
	m.notifyFinished(t)
	return true
}

// finalize 收尾任务：补发终态事件、释放名额并放行队列。只会生效一次。
func (m *Manager) finalize(t *Task, status Status) {
	if !t.markFinalized() {
		return
	}

	// 先补发权威进度与汇总，再发终态 status，最后才关闭订阅通道，
	// 保证订阅者一定能看到收尾数据。
	t.publishFinalState()
	t.setStatus(status)
	if t.cleanup != nil {
		t.cleanup()
	}

	m.mu.Lock()
	if m.running > 0 {
		m.running--
	}
	var next *Task
	for len(m.queue) > 0 {
		id := m.queue[0]
		m.queue = m.queue[1:]
		queued, ok := m.tasks[id]
		if !ok || queued.Status() != StatusQueued {
			continue
		}
		next = queued
		break
	}
	m.mu.Unlock()

	gologger.Debug().Msgf("scan finished: taskId=%s status=%s", t.ID(), status)
	t.closeSubscribers()
	m.notifyFinished(t)

	if next != nil {
		m.schedule(next)
	}
}

func (m *Manager) notifyFinished(t *Task) {
	if m.opts.OnTaskFinished != nil {
		m.opts.OnTaskFinished(t.Snapshot())
	}
}

// nextID 生成「日期-五位序号-进程后缀」形式的任务 ID。
//
// 后缀不能省：序号是进程内计数器，重启后会从 1 重新开始，只靠「日期-序号」会让
// 同一天里先后来起的进程（多次启动的 Web / 控制面）生成同一个 ID，而 sqlite 里的
// 命中是按 task_id 关联的——旧任务的命中会被算到新任务头上。
func (m *Manager) nextID() string {
	if m.opts.IDGenerator != nil {
		return m.opts.IDGenerator()
	}
	day := m.opts.now().Format(defaultIDTimeFormat)

	m.mu.Lock()
	m.seqByDate[day]++
	n := m.seqByDate[day]
	m.mu.Unlock()

	return fmt.Sprintf("%s-%05d-%s", day, n, m.idSuffix)
}

// processSuffix 生成本进程专属的 6 位十六进制后缀。
func processSuffix() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%06x", uint32(time.Now().UnixNano())&0xffffff)
	}
	return hex.EncodeToString(b)
}

// terminalStatus 把引擎自报的收尾状态与子进程退出码折算成任务状态。
//
// cmd/afrog 在 runner 报错时是先发 error 事件再正常 return（退出码 0），
// 所以只要收到过 error 事件就判为失败——即使之后还收到一个 completed 的 done。
// 只有「被终止」优先于失败：终止路径本身也会带来错误信息。
func terminalStatus(exitErr error, doneStatus, errText string) Status {
	if doneStatus == "stopped" {
		return StatusCancelled
	}
	if exitErr != nil || errText != "" {
		return StatusFailed
	}
	return StatusCompleted
}
