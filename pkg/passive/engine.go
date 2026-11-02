package passive

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// EngineOptions 是调度层的配置。
type EngineOptions struct {
	// Detectors 是参与检测的检测器集合，按注册顺序串行执行。
	Detectors []Detector
	// Prober 是注入给检测器的受控重放器。
	Prober Prober
	// OnFinding 在发现通过门控与去重后回调，用于对接台账/事件流。
	OnFinding func(Finding)
	// OnError 在检测器内部异常时回调，便于观测。
	OnError func(detector string, err error)
	// OnTraffic 在单个事务判定完成后回调，用于界面展示「为什么没检测」。
	OnTraffic func(TrafficEvent)
	// Workers 是并发处理事务的 worker 数。
	Workers int
	// QueueSize 是待处理事务队列长度，队列满时新事务直接丢弃。
	QueueSize int
}

// maxSeenEntries 限制去重表规模。被动扫描可能长时间运行，去重表必须封顶，
// 否则会成为新的内存泄漏点。超过上限时整体清空——去重退化为"窗口内去重"，
// 对去重效果的影响远小于内存无限增长的风险。
const maxSeenEntries = 100000

// Stats 是调度层的运行计数。
type Stats struct {
	Submitted uint64 `json:"submitted"`
	Dropped   uint64 `json:"dropped"`
	// Inspected 是真正跑过检测器的事务数——「捕获很多但检测不动」时，
	// 对比 Submitted 与 Inspected 就能立刻定位卡在哪一层。
	Inspected  uint64 `json:"inspected"`
	Detected   uint64 `json:"detected"`
	Filtered   uint64 `json:"filtered"`
	Duplicated uint64 `json:"duplicated"`
	Reported   uint64 `json:"reported"`
	Errors     uint64 `json:"errors"`
}

// Engine 是被动检测的调度层：接收代理事务、分发给检测器、执行置信度门控与去重。
//
// 它是零误报原则的最后一道闸：即使某个检测器错误地给出了低置信度结论，
// 也会在这里被 Filtered 拦下，永远进不了台账。
type Engine struct {
	opts   EngineOptions
	prober Prober
	tasks  chan *CapturedTransaction
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	seen       map[string]struct{}
	submitted  uint64
	dropped    uint64
	inspected  uint64
	detected   uint64
	filtered   uint64
	duplicated uint64
	reported   uint64
	errs       uint64
}

// NewEngine 创建调度层。未设置的 Prober 会退化为保守默认值。
func NewEngine(opts EngineOptions) *Engine {
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 256
	}
	prober := opts.Prober
	if prober == nil {
		prober = NewHTTPProber(DefaultProberOptions())
	}
	return &Engine{
		opts:   opts,
		prober: prober,
		tasks:  make(chan *CapturedTransaction, opts.QueueSize),
		seen:   make(map[string]struct{}),
	}
}

// Start 启动 worker。ctx 取消时所有 worker 退出，之后到达的事务会被丢弃。
func (e *Engine) Start(ctx context.Context) {
	if e.cancel != nil {
		return
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	for i := 0; i < e.opts.Workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
}

// Submit 投递一条事务。返回 false 表示队列已满而被丢弃。
//
// 采用非阻塞投递是有意为之：被动扫描绝不能因为检测能力跟不上而反压用户
// 真实业务流量，宁可丢弃待检流量。
func (e *Engine) Submit(tx *CapturedTransaction) bool {
	if tx == nil {
		return false
	}
	atomic.AddUint64(&e.submitted, 1)
	if e.cancel == nil {
		atomic.AddUint64(&e.dropped, 1)
		e.emitTraffic(tx, VerdictDropped, "被动扫描未启动，事务被丢弃", 0, nil, nil)
		return false
	}
	select {
	case e.tasks <- tx:
		return true
	case <-e.ctx.Done():
		atomic.AddUint64(&e.dropped, 1)
		e.emitTraffic(tx, VerdictDropped, "被动扫描正在停止，事务被丢弃", 0, nil, nil)
		return false
	default:
		atomic.AddUint64(&e.dropped, 1)
		e.emitTraffic(tx, VerdictDropped, "待检队列已满，为避免反压真实流量已丢弃", 0, nil, nil)
		return false
	}
}

// Close 停止接收并等待在途事务处理完成。
func (e *Engine) Close() {
	if e.cancel == nil {
		return
	}
	e.cancel()
	e.wg.Wait()
}

// Stats 返回当前计数快照。
func (e *Engine) Stats() Stats {
	return Stats{
		Submitted:  atomic.LoadUint64(&e.submitted),
		Dropped:    atomic.LoadUint64(&e.dropped),
		Inspected:  atomic.LoadUint64(&e.inspected),
		Detected:   atomic.LoadUint64(&e.detected),
		Filtered:   atomic.LoadUint64(&e.filtered),
		Duplicated: atomic.LoadUint64(&e.duplicated),
		Reported:   atomic.LoadUint64(&e.reported),
		Errors:     atomic.LoadUint64(&e.errs),
	}
}

func (e *Engine) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case tx, ok := <-e.tasks:
			if !ok {
				return
			}
			e.handle(tx)
		}
	}
}

func (e *Engine) handle(tx *CapturedTransaction) {
	ran := make([]string, 0, len(e.opts.Detectors))
	reasons := make([]string, 0, len(e.opts.Detectors))
	var firstErr error
	reported := 0

	for _, d := range e.opts.Detectors {
		if d == nil {
			continue
		}
		if !d.Interest(tx) {
			reasons = append(reasons, interestReason(d, tx))
			continue
		}
		ran = append(ran, d.Name())
		findings, err := e.safeDetect(d, tx)
		if err != nil {
			atomic.AddUint64(&e.errs, 1)
			if firstErr == nil {
				firstErr = err
			}
			if e.opts.OnError != nil {
				e.opts.OnError(d.Name(), err)
			}
			continue
		}
		for _, f := range findings {
			atomic.AddUint64(&e.detected, 1)
			// 零误报门控：非 Certain 一律拦下。
			if f.Confidence < ConfidenceCertain {
				atomic.AddUint64(&e.filtered, 1)
				continue
			}
			if !e.markSeen(f) {
				atomic.AddUint64(&e.duplicated, 1)
				continue
			}
			atomic.AddUint64(&e.reported, 1)
			reported++
			if e.opts.OnFinding != nil {
				e.opts.OnFinding(f)
			}
		}
	}

	e.emitTraffic(tx, verdictOf(ran, reported, firstErr), joinReasons(reasons), reported, firstErr, ran)
	if len(ran) > 0 {
		atomic.AddUint64(&e.inspected, 1)
	}
}

// verdictOf 把「跑了哪些检测器 / 是否出错 / 是否命中」归纳成一句结论。
func verdictOf(ran []string, reported int, err error) TrafficVerdict {
	if reported > 0 {
		return VerdictFinding
	}
	if err != nil {
		return VerdictError
	}
	if len(ran) == 0 {
		return VerdictNoInterest
	}
	return VerdictNoFinding
}

func joinReasons(reasons []string) string {
	out := ""
	for _, r := range reasons {
		if r == "" {
			continue
		}
		if out == "" {
			out = r
		} else {
			out += "；" + r
		}
	}
	return out
}

// interestReason 取检测器给出的具体原因；未实现扩展接口时退回通用文案。
func interestReason(d Detector, tx *CapturedTransaction) string {
	if r, ok := d.(InterestReasoner); ok {
		if s := r.InterestReason(tx); s != "" {
			return d.Name() + "：" + s
		}
	}
	return d.Name() + "：不满足检测条件"
}

func (e *Engine) emitTraffic(tx *CapturedTransaction, verdict TrafficVerdict, reason string, findings int, err error, ran []string) {
	if e.opts.OnTraffic == nil || tx == nil {
		return
	}
	ev := TrafficEvent{
		ID:        tx.ID,
		Time:      tx.StartAt,
		Verdict:   verdict,
		Reason:    reason,
		Findings:  findings,
		Detectors: ran,
	}
	if tx.Request != nil {
		ev.Method = tx.Request.Method
		if tx.Request.URL != nil {
			ev.URL = tx.Request.URL.String()
		}
	}
	if tx.Response != nil {
		ev.Status = tx.Response.Status
		ev.Bytes = len(tx.Response.Body)
		ev.Duration = tx.Response.Duration
		ev.DurationMs = tx.Response.Duration.Milliseconds()
	}
	if err != nil {
		ev.Error = err.Error()
	}
	e.opts.OnTraffic(ev)
}

// safeDetect 隔离单个检测器的 panic，避免一个检测器的缺陷拖垮整个被动链路。
func (e *Engine) safeDetect(d Detector, tx *CapturedTransaction) (findings []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("detector %s panic: %v", d.Name(), r)
		}
	}()
	return d.Detect(e.ctx, tx, e.prober)
}

func (e *Engine) markSeen(f Finding) bool {
	key := f.Detector + "|" + f.VulnType + "|" + f.Target + "|" + f.Location

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.seen[key]; ok {
		return false
	}
	if len(e.seen) >= maxSeenEntries {
		e.seen = make(map[string]struct{}, maxSeenEntries/4)
	}
	e.seen[key] = struct{}{}
	return true
}
