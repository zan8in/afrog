package scantask

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// Task 是一个扫描任务。所有可变字段都由 mu 保护，对外只通过 Snapshot 暴露，
// 避免调用方读到撕裂的状态。
type Task struct {
	id       string
	node     string
	spec     *executor.Spec
	targets  []string
	cleanup  func()
	now      func() time.Time
	bufLimit int

	mu         sync.Mutex
	status     Status
	createdAt  time.Time
	startedAt  time.Time
	endedAt    time.Time
	handle     executor.Handle
	seq        uint64
	buf        []*scanstream.Event
	dropped    int
	subs       map[*Subscription]struct{}
	progress   *scanstream.ProgressEvent
	scanInfo   *scanstream.ScanInfoEvent
	summary    *scanstream.Summary
	doneStatus string
	hits       map[string]int
	errText    string

	// finalized 保证 finalize 只生效一次。它是原子量而不是受 mu 保护的字段：
	// 「取消排队任务」与「收尾放行队列」会在不同的锁路径上竞争同一个任务。
	finalized atomic.Bool
}

func newTask(id, node string, spec *executor.Spec, cleanup func(), bufLimit int, now func() time.Time) *Task {
	return &Task{
		id:        id,
		node:      node,
		spec:      spec,
		targets:   append([]string(nil), spec.Targets...),
		cleanup:   cleanup,
		now:       now,
		bufLimit:  bufLimit,
		status:    StatusStarting,
		createdAt: now(),
		subs:      make(map[*Subscription]struct{}),
		hits:      make(map[string]int),
	}
}

// ID 返回任务 ID。
func (t *Task) ID() string { return t.id }

// Node 返回执行该任务的节点名。
func (t *Task) Node() string { return t.node }

// Spec 返回任务规格（只读）。
func (t *Task) Spec() *executor.Spec { return t.spec }

// Status 返回当前状态。
func (t *Task) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// markFinalized 返回 true 表示本次调用是第一个到达收尾的路径。
func (t *Task) markFinalized() bool {
	return t.finalized.CompareAndSwap(false, true)
}

// setHandle 记录子进程句柄，供暂停/继续/取消使用。
func (t *Task) setHandle(h executor.Handle) {
	t.mu.Lock()
	t.handle = h
	t.mu.Unlock()
}

// handle 返回子进程句柄，未拉起时为 nil。
func (t *Task) handleRef() executor.Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handle
}

// setErr 记录失败原因（首次写入生效）。
func (t *Task) setErr(msg string) {
	if msg == "" {
		return
	}
	t.mu.Lock()
	if t.errText == "" {
		t.errText = msg
	}
	t.mu.Unlock()
}

// doneState 返回引擎自报的收尾状态与错误信息。
func (t *Task) doneState() (string, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.doneStatus, t.errText
}

// setStatus 更新状态并广播 status 事件。控制面是状态的唯一真源。
func (t *Task) setStatus(next Status) {
	t.mu.Lock()
	t.status = next
	if t.startedAt.IsZero() && (next == StatusStarting || next == StatusRunning) {
		t.startedAt = t.now()
	}
	if next.Terminal() {
		t.endedAt = t.now()
	}
	t.mu.Unlock()

	t.publish(scanstream.TypeStatus, func(ev *scanstream.Event) {
		ev.Status = &scanstream.StatusEvent{Status: string(next)}
	})
}

// apply 吸收执行器上报的事件：先更新任务状态，再按控制面的编号广播。
//
// status 事件被刻意丢弃：排队、暂停、收尾这些状态由控制面自己决定，子进程的
// starting/running 重复广播只会让订阅者看到互相矛盾的状态。
func (t *Task) apply(ev *scanstream.Event) {
	switch ev.Type {
	case scanstream.TypeStatus:
		return
	case scanstream.TypeProgress:
		if ev.Progress == nil {
			return
		}
		t.mu.Lock()
		t.progress = ev.Progress
		t.mu.Unlock()
	case scanstream.TypeScanInfo:
		if ev.ScanInfo == nil {
			return
		}
		t.mu.Lock()
		t.scanInfo = ev.ScanInfo
		t.mu.Unlock()
	case scanstream.TypeResult:
		if ev.Result == nil {
			return
		}
		t.mu.Lock()
		if t.hits == nil {
			t.hits = make(map[string]int)
		}
		t.hits[strings.ToLower(ev.Result.Severity)]++
		t.mu.Unlock()
	case scanstream.TypeDone:
		if ev.Done == nil {
			return
		}
		t.mu.Lock()
		t.doneStatus = ev.Done.Status
		if ev.Done.Summary != nil {
			t.summary = ev.Done.Summary
		}
		t.mu.Unlock()
	case scanstream.TypeError:
		if ev.Error == nil {
			return
		}
		t.setErr(ev.Error.Message)
	}
	t.relay(ev)
}

// publish 产生一条控制面自有的事件。
func (t *Task) publish(typ string, fill func(*scanstream.Event)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ev := t.nextEnvelopeLocked(typ)
	if fill != nil {
		fill(ev)
	}
	t.broadcastLocked(ev)
}

// relay 把执行器的事件换成控制面的信封后广播（载荷原样保留）。
func (t *Task) relay(src *scanstream.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ev := *src
	ev.V = scanstream.Version
	ev.Node = t.node
	ev.Task = t.id
	ev.Seq = t.nextSeqLocked()
	ev.TsMs = t.now().UnixMilli()
	t.broadcastLocked(&ev)
}

// nextEnvelopeLocked 生成信封并占用下一个 seq。调用方必须持有 t.mu。
func (t *Task) nextEnvelopeLocked(typ string) *scanstream.Event {
	return &scanstream.Event{
		V:    scanstream.Version,
		Node: t.node,
		Task: t.id,
		Seq:  t.nextSeqLocked(),
		TsMs: t.now().UnixMilli(),
		Type: typ,
	}
}

func (t *Task) nextSeqLocked() uint64 {
	t.seq++
	return t.seq
}

// broadcastLocked 写入事件缓冲并分发给订阅者。调用方必须持有 t.mu。
func (t *Task) broadcastLocked(ev *scanstream.Event) {
	t.recordLocked(ev)
	for s := range t.subs {
		if !s.offer(ev) {
			// 订阅者消费不过来：断开它，让它带上 last_seq 重连补发（协议 §5.1）。
			delete(t.subs, s)
			s.close(ErrSlowSubscriber)
		}
	}
}

// recordLocked 维护「最近 bufLimit 条事件」的窗口。调用方必须持有 t.mu。
func (t *Task) recordLocked(ev *scanstream.Event) {
	t.buf = append(t.buf, ev)
	over := len(t.buf) - t.bufLimit
	if over <= 0 {
		return
	}
	copy(t.buf, t.buf[over:])
	t.buf = t.buf[:len(t.buf)-over]
	t.dropped += over
}

// snapshotLocked 组装状态快照。调用方必须持有 t.mu。
func (t *Task) snapshotLocked() *Snapshot {
	snap := &Snapshot{
		ID:        t.id,
		Name:      t.spec.TaskName,
		Node:      t.node,
		Status:    t.status,
		Targets:   append([]string(nil), t.targets...),
		CreatedAt: t.createdAt,
		StartedAt: t.startedAt,
		EndedAt:   t.endedAt,
		Hits:      make(map[string]int, len(t.hits)),
		LastSeq:   t.seq,
		Truncated: t.dropped > 0,
		Pausable:  t.pausableLocked(),
		Error:     t.errText,
	}
	for k, v := range t.hits {
		snap.Hits[k] = v
		snap.HitTotal += v
	}
	if len(t.buf) > 0 {
		snap.BufferedFrom = t.buf[0].Seq
	}
	if t.scanInfo != nil {
		snap.ScanInfo = ScanInfo{
			TotalTargets: t.scanInfo.TotalTargets,
			TotalPocs:    t.scanInfo.TotalPocs,
			TotalScans:   t.scanInfo.TotalScans,
			OOBEnabled:   t.scanInfo.OOBEnabled,
			OOBStatus:    t.scanInfo.OOBStatus,
		}
	}
	if t.summary != nil {
		dist := make(map[string]int64, len(t.summary.BySeverity))
		for k, v := range t.summary.BySeverity {
			dist[k] = v
		}
		snap.Summary = &Summary{
			Executed:   t.summary.Executed,
			Found:      t.summary.Found,
			BySeverity: dist,
			ElapsedMs:  t.summary.ElapsedMs,
		}
	}
	snap.Progress = t.progressLocked()
	return snap
}

// Snapshot 返回任务当前状态。
func (t *Task) Snapshot() *Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

// progressLocked 汇总进度口径（协议文档 §5.2）。调用方必须持有 t.mu。
func (t *Task) progressLocked() Progress {
	p := Progress{}
	if t.progress != nil {
		p.Percent = t.progress.Percent
		p.Finished = t.progress.Finished
		p.Total = t.progress.Total
		p.ElapsedMs = t.progress.ElapsedMs
	}
	// 前置阶段（主机发现/端口扫描/Web 探测）里引擎还没算出任务总数，
	// 这期间的 progress 事件带 total=0，scan_info 里的才是权威总数。
	if t.scanInfo != nil && t.scanInfo.TotalScans > 0 {
		p.Total = int64(t.scanInfo.TotalScans)
	}
	if t.summary != nil {
		p.Finished = t.summary.Executed
		if t.summary.ElapsedMs > 0 {
			p.ElapsedMs = t.summary.ElapsedMs
		}
	}
	if p.ElapsedMs <= 0 && !t.startedAt.IsZero() {
		p.ElapsedMs = t.now().Sub(t.startedAt).Milliseconds()
	}
	if secs := p.ElapsedMs / 1000; secs > 0 {
		p.Rate = int(p.Finished / secs)
	}
	if t.status == StatusCompleted {
		// 引擎只在整轮扫描跑完时才让百分数到 100，整数取整会停在 99。
		p.Percent = 100
	}
	return p
}

// pausableLocked 如实反映「现在能不能暂停/继续」。调用方必须持有 t.mu。
// Windows 不支持进程暂停，排队中（还没有进程）与已结束的任务也无从下手。
func (t *Task) pausableLocked() bool {
	if !executor.PauseSupported {
		return false
	}
	if t.handle == nil {
		return false
	}
	switch t.status {
	case StatusRunning, StatusPaused:
		return true
	}
	return false
}

// publishFinalState 在收尾前补发一次权威进度与汇总，避免订阅者停在最后一次
// 1 秒采样上；调用必须在 setStatus(终态) 之前完成。
func (t *Task) publishFinalState() {
	snap := t.Snapshot()
	if t.hasProgress() {
		t.publish(scanstream.TypeProgress, func(ev *scanstream.Event) {
			ev.Progress = &scanstream.ProgressEvent{
				Percent:   snap.Progress.Percent,
				Finished:  snap.Progress.Finished,
				Total:     snap.Progress.Total,
				Rate:      snap.Progress.Rate,
				ElapsedMs: snap.Progress.ElapsedMs,
			}
		})
	}
	if t.hasScanInfo() {
		t.publish(scanstream.TypeScanInfo, func(ev *scanstream.Event) {
			ev.ScanInfo = &scanstream.ScanInfoEvent{
				TotalTargets: snap.ScanInfo.TotalTargets,
				TotalPocs:    snap.ScanInfo.TotalPocs,
				TotalScans:   snap.ScanInfo.TotalScans,
				OOBEnabled:   snap.ScanInfo.OOBEnabled,
				OOBStatus:    snap.ScanInfo.OOBStatus,
			}
		})
	}
}

func (t *Task) hasProgress() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.progress != nil || t.summary != nil
}

func (t *Task) hasScanInfo() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.scanInfo != nil
}

// subscribe 订阅任务事件：先补发窗口内 seq > fromSeq 的事件，再持续推送新事件。
//
// 任务已经结束时，补发完就关闭通道——不会再有新事件了。
func (t *Task) subscribe(fromSeq uint64) *Subscription {
	t.mu.Lock()
	defer t.mu.Unlock()

	s := &Subscription{ch: make(chan *scanstream.Event, t.bufLimit+subChannelSlack), task: t}

	// 请求的位置早于缓冲窗口：中间那段已经拿不到了，如实告知（seq=0 的通知不参与去重）。
	if len(t.buf) > 0 && fromSeq > 0 && fromSeq+1 < t.buf[0].Seq {
		s.ch <- &scanstream.Event{
			V:    scanstream.Version,
			Node: t.node,
			Task: t.id,
			Type: scanstream.TypeError,
			Error: &scanstream.ErrorEvent{
				Code:    "events_truncated",
				Message: "更早的事件已超出保留窗口，不再补发，请用 GetStatus / GetResults 获取汇总",
			},
		}
	}
	for _, ev := range t.buf {
		if ev.Seq <= fromSeq {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// 补发量本身就超过了通道容量（窗口被调大过），让客户端重试。
			s.close(ErrSlowSubscriber)
			return s
		}
	}

	if t.status.Terminal() {
		s.close(nil)
		return s
	}
	t.subs[s] = struct{}{}
	return s
}

// unsubscribe 移除订阅者并关闭其通道。
func (t *Task) unsubscribe(s *Subscription) {
	t.mu.Lock()
	delete(t.subs, s)
	t.mu.Unlock()
	s.close(nil)
}

// closeSubscribers 在任务收尾后关闭所有订阅通道（必须在终态事件发出之后调用）。
func (t *Task) closeSubscribers() {
	t.mu.Lock()
	subs := make([]*Subscription, 0, len(t.subs))
	for s := range t.subs {
		subs = append(subs, s)
	}
	t.subs = make(map[*Subscription]struct{})
	t.mu.Unlock()

	for _, s := range subs {
		s.close(nil)
	}
}

// Subscription 是任务事件的订阅句柄。
//
// 消费方必须持续读取 Events()：来不及消费会被判定为 ErrSlowSubscriber 并断开，
// 由客户端带上 last_seq 重连补发。
type Subscription struct {
	task *Task
	ch   chan *scanstream.Event

	once sync.Once
	mu   sync.Mutex
	err  error
}

// Events 返回事件通道，任务结束或订阅被断开时关闭。
func (s *Subscription) Events() <-chan *scanstream.Event { return s.ch }

// Err 返回订阅被断开的原因；正常结束（任务收尾）为 nil。
func (s *Subscription) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close 主动结束订阅，可重复调用。
func (s *Subscription) Close() { s.task.unsubscribe(s) }

func (s *Subscription) close(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.ch)
	})
}

// offer 尝试投递一条事件；返回 false 表示订阅者太慢、通道已满。
// 调用方（持有 task.mu）负责把它移出订阅表并关闭。
func (s *Subscription) offer(ev *scanstream.Event) bool {
	select {
	case s.ch <- ev:
		return true
	default:
		return false
	}
}
