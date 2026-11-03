package passive

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
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
	// Workers 是**门控池**的 worker 数，<=0 用 defaultWorkers。
	//
	// 门控池只做「这条请求要不要检测」的筛选：便宜、极快，几乎不会成为瓶颈。
	// 它同时也是检测入口的守门人，因此它的并发决定了「入口能吞下多快的流量」。
	Workers int
	// DetectWorkers 是**检测池**的 worker 数，<=0 时跟随 Workers。
	//
	// 与门控池分开的意义：检测又慢又不可控（一个慢接口能让单次检测耗到分钟级），
	// 如果和门控共用 worker，一条慢检测就会把整个调度层连同入口一起堵死。
	// 拆开之后，检测池再慢也只影响检测队列，门控入口照常消化流量。
	DetectWorkers int
	// QueueSize 是门控入口队列长度，<=0 用 defaultQueueSize；队列满时新事务直接丢弃。
	QueueSize int
	// DetectQueueSize 是检测队列长度，<=0 时跟随 QueueSize。
	//
	// 它只装「已确认需要检测」的事务，量级远小于入口队列；但一旦放不下就意味着漏报，
	// 所以排空它比排空入口队列更重要。
	DetectQueueSize int
}

// maxSeenEntries 限制去重表规模。被动扫描可能长时间运行，去重表必须封顶，
// 否则会成为新的内存泄漏点。超过上限时整体清空——去重退化为"窗口内去重"，
// 对去重效果的影响远小于内存无限增长的风险。
const maxSeenEntries = 100000

// maxHitPoints 限制「已确认命中的注入点」表规模，理由同上。
const maxHitPoints = 20000

// maxMissPoints 限制「已判定无注入的注入点」表规模，理由同 maxHitPoints。
const maxMissPoints = 20000

// missPointTTL 是「已判定无注入」这一结论的有效期。
//
// 未命中的结论必须带有效期，不能像命中那样在整个运行期内永久短路：站点可能在会话
// 中途改配置、上线新版本或换了数据库，参数由「不能注入」变成「能注入」。给一个足够
// 短的有效期，既省下绝大多数的重复重放，又保证同一注入点会在有效期内被重新复测。
//
// 未命中的代价远高于命中的代价：漏掉一个真漏洞不可挽回，而多重测一次只是多花流量，
// 因此这个值刻意取得偏小。
const missPointTTL = 30 * time.Minute

// defaultWorkers / defaultQueueSize 是未显式配置时的调度层默认值。
//
// worker 数等于**实际重放并发度**——检测器在一个事务内串行发请求，所以同时在飞的
// 重放请求数就是检测池的 worker 数。取 8 是让它不低于 Prober 的单目标并发上限（4），
// 否则会出现「Prober 允许 4 并发、只给 2 个 worker」的额度闲置，吞吐白白腰斩。
// 对目标的真实压力由 Prober 的速率与并发闸门兜底，调大 worker 不等于加大攻击面。
const (
	defaultWorkers   = 8
	defaultQueueSize = 256
)

// Stats 是调度层的运行计数。
type Stats struct {
	Submitted uint64 `json:"submitted"`
	Dropped   uint64 `json:"dropped"`
	// Inspected 是真正跑过检测器的事务数——「捕获很多但检测不动」时，
	// 对比 Submitted 与 Inspected 就能立刻定位卡在哪一层。
	Inspected uint64 `json:"inspected"`
	// Handled 是**门控池**取出并处理完的事务总数，含「没有检测器感兴趣」的那些。
	//
	// 与 Inspected 的区别正是判断队列是否排空的关键：Inspected 只统计真正跑过检测器
	// 的事务，未通过门控的不计入，因此用 Submitted-Dropped 与 Inspected 比较永远对不上。
	// 队列排空要看 Handled（以及四个积压/在途指标）——见 Engine.Drained。
	Handled uint64 `json:"handled"`
	// Forwarded 是被门控判定「需要检测」并转交检测池的事务数。
	Forwarded uint64 `json:"forwarded"`
	// SkippedKnown 是被门控判定「注入点已确认命中」或「短期内已判定无注入」而跳过
	// 复测的事务数。它衡量的是这套短期记忆省下了多少昂贵重放。
	SkippedKnown uint64 `json:"skipped_known"`
	// SkippedInFlight 是被门控判定「该注入点已有事务在检测队列中或检测中」而跳过的
	// 事务数。它衡量的是「在途指纹短路」省下的并发重复重放。
	//
	// 与 SkippedKnown 分开：后者是结论已落定后的短路，这里结论还没产生，被跳过的那份
	// 不会补测。单独计数才能让这条口径的取舍显式可见。
	SkippedInFlight uint64 `json:"skipped_in_flight"`
	// DroppedDetect 是已确认需要检测、却因检测队列满而未能进入检测的事务数。
	// 它与 Dropped 分开统计：这一项直接对应漏报风险。
	DroppedDetect uint64 `json:"dropped_detect"`
	// QueueDepth 是门控入口队列的积压深度（瞬时值）。
	QueueDepth int `json:"queue_depth"`
	// InFlight 是门控池正在处理的事务数（瞬时值）。
	InFlight uint64 `json:"in_flight"`
	// DetectQueueDepth 是检测队列的积压深度（瞬时值）。
	DetectQueueDepth int `json:"detect_queue_depth"`
	// DetectInFlight 是检测池正在检测的事务数（瞬时值）。
	// 它长期等于检测池 worker 数，说明检测能力已打满。
	DetectInFlight uint64 `json:"detect_in_flight"`
	Detected       uint64 `json:"detected"`
	Filtered       uint64 `json:"filtered"`
	Duplicated     uint64 `json:"duplicated"`
	Reported       uint64 `json:"reported"`
	Errors         uint64 `json:"errors"`
}

// Engine 是被动检测的调度层：接收代理事务、分发给检测器、执行置信度门控与去重。
//
// 它是零误报原则的最后一道闸：即使某个检测器错误地给出了低置信度结论，
// 也会在这里被 Filtered 拦下，永远进不了台账。
//
// 内部是**两阶段流水线**：门控池先判定「要不要检测」（便宜、快），需要检测的才转交
// 给检测池（昂贵、慢且耗时不可控）。这么拆是为了不让一条病态慢的检测堵住整个入口。
type Engine struct {
	opts       EngineOptions
	prober     Prober
	tasks      chan *CapturedTransaction
	detectJobs chan *detectJob
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// activeMu / active 登记「已进入检测流水线但尚未完成」的事务，用于回答
	// 「检测积压 / 检测在途」背后的具体请求。规模受检测队列与 worker 数约束。
	activeMu sync.Mutex
	active   map[string]*activeEntry

	mu   sync.Mutex
	seen map[string]struct{}
	// hitPoints 记录本次运行内「已确认命中的注入点身份」，用于让重复流量短路，
	// 不再重复重放。身份不含参数值，因为同一注入点换值后结论不变；也不含同名参数的
	// 序号，?id=1&id=2 视为同一注入点族。跨运行不复用——重启即清空，保证复测价值。
	hitPoints map[string]struct{}
	// missPoints 记录「已判定无注入的注入点身份」及其判定时刻，带 missPointTTL 有效期。
	//
	// 这是被动扫描最大的一块可省流量：动态站点上同一条 URL 会以不同参数值反复出现，
	// 每个注入点都要付约 35 次重放。没有它，结论「干净」的注入点会被无限次重测。
	missPoints map[string]time.Time
	// inFlightPoints 记录「已在检测队列中或检测中」的注入点身份**引用计数**。
	//
	// 事后短路（hitPoints/missPoints）只有在检测跑完、结论落定后才生效，而一条全量
	// 检测要数十秒——这个窗口内到达的相同请求会全部通过门控，被成倍并行重放
	// （同一 URL 并发数条各自跑一遍）。它补的就是这个窗口。
	//
	// 用引用计数而非集合：同一点可能被多个不同事务同时覆盖，检测完成顺序不定，
	// 集合会在第一个完成时误清空，把后面仍在检测的事务漏出计数。
	inFlightPoints  map[string]int
	submitted       uint64
	dropped         uint64
	droppedDetect   uint64
	inspected       uint64
	handled         uint64
	forwarded       uint64
	skippedKnown    uint64
	skippedInFlight uint64
	inFlight        uint64
	detectInFlight  uint64
	detected        uint64
	filtered        uint64
	duplicated      uint64
	reported        uint64
	errs            uint64
}

// detectJob 是一条已通过门控、等待检测池处理的事务。
//
// 把「哪些检测器感兴趣」与「注入点身份」一并带过来，避免检测池重复计算——
// 门控阶段已经解析过一遍了。
type detectJob struct {
	tx        *CapturedTransaction
	detectors []Detector
	points    []string
}

// NewEngine 创建调度层。未设置的 Prober 会退化为保守默认值。
func NewEngine(opts EngineOptions) *Engine {
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.DetectWorkers <= 0 {
		opts.DetectWorkers = opts.Workers
	}
	if opts.DetectQueueSize <= 0 {
		opts.DetectQueueSize = opts.QueueSize
	}
	prober := opts.Prober
	if prober == nil {
		prober = NewHTTPProber(DefaultProberOptions())
	}
	return &Engine{
		opts:           opts,
		prober:         prober,
		tasks:          make(chan *CapturedTransaction, opts.QueueSize),
		detectJobs:     make(chan *detectJob, opts.DetectQueueSize),
		seen:           make(map[string]struct{}),
		hitPoints:      make(map[string]struct{}),
		missPoints:     make(map[string]time.Time),
		inFlightPoints: make(map[string]int),
	}
}

// Start 启动两段流水线的 worker。ctx 取消时所有 worker 退出，之后到达的事务会被丢弃。
func (e *Engine) Start(ctx context.Context) {
	if e.cancel != nil {
		return
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	for i := 0; i < e.opts.Workers; i++ {
		e.wg.Add(1)
		go e.gateWorker()
	}
	for i := 0; i < e.opts.DetectWorkers; i++ {
		e.wg.Add(1)
		go e.detectWorker()
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
		e.emitTraffic(tx, VerdictDropped, "被动扫描未启动，事务被丢弃", 0, 0, nil, nil)
		return false
	}
	select {
	case e.tasks <- tx:
		return true
	case <-e.ctx.Done():
		atomic.AddUint64(&e.dropped, 1)
		e.emitTraffic(tx, VerdictDropped, "被动扫描正在停止，事务被丢弃", 0, 0, nil, nil)
		return false
	default:
		atomic.AddUint64(&e.dropped, 1)
		e.emitTraffic(tx, VerdictDropped, "待检队列已满，为避免反压真实流量已丢弃", 0, 0, nil, nil)
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
		Submitted:        atomic.LoadUint64(&e.submitted),
		Dropped:          atomic.LoadUint64(&e.dropped),
		Inspected:        atomic.LoadUint64(&e.inspected),
		Handled:          atomic.LoadUint64(&e.handled),
		Forwarded:        atomic.LoadUint64(&e.forwarded),
		SkippedKnown:     atomic.LoadUint64(&e.skippedKnown),
		SkippedInFlight:  atomic.LoadUint64(&e.skippedInFlight),
		DroppedDetect:    atomic.LoadUint64(&e.droppedDetect),
		QueueDepth:       len(e.tasks),
		InFlight:         atomic.LoadUint64(&e.inFlight),
		DetectQueueDepth: len(e.detectJobs),
		DetectInFlight:   atomic.LoadUint64(&e.detectInFlight),
		Detected:         atomic.LoadUint64(&e.detected),
		Filtered:         atomic.LoadUint64(&e.filtered),
		Duplicated:       atomic.LoadUint64(&e.duplicated),
		Reported:         atomic.LoadUint64(&e.reported),
		Errors:           atomic.LoadUint64(&e.errs),
	}
}

// Drained 报告「进入调度的事务是否已全部处理完」。
//
// 两段流水线都必须停稳才算排空：门控队列/在途 + 检测队列/在途 全为 0，
// 且成功入队数（Submitted-Dropped）已全部被门控池处理（Handled）。
//
// 不能用 Inspected 来判：它只统计真正跑过检测器的事务，没有检测器感兴趣的事务
// 虽然已处理完却不计入，会让队列明明空了却被判成「还在处理」。
//
// 注意它只描述调度层。此刻可能仍有检测器在重放请求——但那属于检测池处理中的
// 一部分，会被计入 DetectInFlight，因此不会出现「Drained 为真却还在检测」的情况。
func (e *Engine) Drained() bool {
	if len(e.tasks) != 0 || len(e.detectJobs) != 0 {
		return false
	}
	if atomic.LoadUint64(&e.inFlight) != 0 || atomic.LoadUint64(&e.detectInFlight) != 0 {
		return false
	}
	enqueued := atomic.LoadUint64(&e.submitted) - atomic.LoadUint64(&e.dropped)
	return atomic.LoadUint64(&e.handled) >= enqueued
}

// gateWorker 跑门控池：只做「要不要检测」的筛选，不做任何重放。
func (e *Engine) gateWorker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case tx, ok := <-e.tasks:
			if !ok {
				return
			}
			e.gate(tx)
		}
	}
}

// detectWorker 跑检测池：执行真正昂贵、耗时不可控的重放与判定。
func (e *Engine) detectWorker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case job, ok := <-e.detectJobs:
			if !ok {
				return
			}
			e.detect(job)
		}
	}
}

// gate 是流水线的第一段：判定这条事务要不要检测。
//
// 它只做三件事——命中短路、逐检测器 Interest、把需要检测的转交出去。全部是纯本地
// 计算，不产生任何网络请求，因此这段永远快。把昂贵的检测隔离在另一段之后，
// 是「一条慢检测不再堵死整个入口」的关键。
func (e *Engine) gate(tx *CapturedTransaction) {
	// 计数与在途标记都放在最前：Handled 不设任何门控，才能代表「队列里的事务已取完」，
	// 这是 Drained 用来判断排空的依据。
	atomic.AddUint64(&e.handled, 1)
	atomic.AddUint64(&e.inFlight, 1)
	defer atomic.AddUint64(&e.inFlight, ^uint64(0)) // 原子减 1（-1 的补码）

	// 注入点记忆短路：本次运行内该请求的注入点结论已经明确，再跑一遍只会重复消耗
	// 重放流量（含最贵的 WAF 绕过分支），结论不可能变。分两种情况给不同结论：
	// 已确认命中的标 duplicate，已判定干净的标 known-clean——两者省下的流量一样，
	// 但含义相反，混在一起会让使用者以为某处被检出过。
	//
	// 只对「全部注入点都已有明确结论」的事务短路——只要还有一个未确认的注入点，
	// 就必须整体重测：检测器是按事务而非按注入点调用的，无法只重测其中一部分。
	// 这条约束同时保证了「结论不明的请求永远照常重测」，短路不会引入漏报。
	points := injectionPointIDs(tx.Request)
	if len(points) > 0 {
		allHit, allSettled := e.pointsStatus(points)
		switch {
		case allHit:
			atomic.AddUint64(&e.duplicated, 1)
			atomic.AddUint64(&e.skippedKnown, 1)
			e.emitTraffic(tx, VerdictDuplicate, "该请求的注入点在本次运行内均已确认命中，跳过重复重放", 0, 1, nil, nil)
			return
		case allSettled:
			atomic.AddUint64(&e.skippedKnown, 1)
			e.emitTraffic(tx, VerdictKnownClean, "该请求的注入点在有效期内已判定无注入，跳过重复重放", 0, 0, nil, nil)
			return
		case e.allPointsInFlight(points):
			// 结论还没落定，但同注入点已有事务在检测队列中/检测中。此刻再投递只会
			// 让同一条 URL 被并行重放一遍（全量档一条要数十秒）。跳过并显式标注，
			// 它既不是「已确认命中」也不是「已判定干净」，必须自成一类。
			atomic.AddUint64(&e.skippedInFlight, 1)
			e.emitTraffic(tx, VerdictInFlightDup, "该请求的注入点已有事务正在检测中，跳过并发重复投递", 0, 0, nil, nil)
			return
		}
	}

	interested := make([]Detector, 0, len(e.opts.Detectors))
	reasons := make([]string, 0, len(e.opts.Detectors))
	for _, d := range e.opts.Detectors {
		if d == nil {
			continue
		}
		if !d.Interest(tx) {
			reasons = append(reasons, interestReason(d, tx))
			continue
		}
		interested = append(interested, d)
	}
	if len(interested) == 0 {
		e.emitTraffic(tx, VerdictNoInterest, joinReasons(reasons), 0, 0, nil, nil)
		return
	}

	// 转交检测池。非阻塞投递同样是有意为之：门控池绝不能为了等检测池腾出空位而被
	// 卡住——那等于把慢检测重新传染回入口。放不下就丢弃并明确标注，让「检测能力饱和」
	// 这件事显式可见，而不是变成一次无声的漏报。
	job := &detectJob{tx: tx, detectors: interested, points: points}
	// 先登记再投递：检测池可能在投递后立刻跑完并注销，顺序反了会留下僵尸记录。
	// 在途指纹同样要在投递前占用，否则并发到达的相同请求会在计数生效前一起挤进来。
	e.registerActive(job)
	e.retainInFlightPoints(points)
	select {
	case e.detectJobs <- job:
		atomic.AddUint64(&e.forwarded, 1)
	default:
		// 投递失败必须把在途计数还回去，否则这些注入点会被永久判成「在途」而不再复测。
		e.releaseInFlightPoints(points)
		e.unregisterActive(tx.ID)
		atomic.AddUint64(&e.droppedDetect, 1)
		e.emitTraffic(tx, VerdictDroppedDetect,
			"检测队列已满：该请求已确认需要检测，但检测能力饱和，未能检测（存在漏报风险）", 0, 0, nil, nil)
	}
}

// detect 是流水线的第二段：对已确认需要检测的事务执行检测器。
func (e *Engine) detect(job *detectJob) {
	atomic.AddUint64(&e.detectInFlight, 1)
	defer atomic.AddUint64(&e.detectInFlight, ^uint64(0))
	// 同步在途登记：让「检测在途」能被点开看到具体是哪条请求。
	if job != nil && job.tx != nil {
		e.markActiveDetecting(job.tx.ID)
		defer e.unregisterActive(job.tx.ID)
	}
	// 检测结束才归还在途占用。defer 在函数体之后执行，因此它必然晚于
	// rememberHitPoints / rememberMissPoints——保证「在途」与「已落定」之间无缝衔接，
	// 不会出现两者都没覆盖的窗口让重复流量钻空子。
	defer e.releaseInFlightPoints(job.points)

	tx := job.tx
	ran := make([]string, 0, len(job.detectors))
	var firstErr error
	reported := 0
	duplicated := 0
	// detectedHere 是本次事务里检测器报出的发现总数（未经过零误报门控）。
	// 它是「干净结论」的判据：一条发现都没报出来，才算真的干净。
	detectedHere := 0

	for _, d := range job.detectors {
		if d == nil {
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
			detectedHere++
			// 零误报门控：非 Certain 一律拦下。
			if f.Confidence < ConfidenceCertain {
				atomic.AddUint64(&e.filtered, 1)
				continue
			}
			if !e.markSeen(f) {
				atomic.AddUint64(&e.duplicated, 1)
				duplicated++
				continue
			}
			atomic.AddUint64(&e.reported, 1)
			reported++
			if e.opts.OnFinding != nil {
				e.opts.OnFinding(f)
			}
		}
	}

	e.emitTraffic(tx, verdictOf(ran, reported, duplicated, firstErr), "", reported, duplicated, firstErr, ran)
	atomic.AddUint64(&e.inspected, 1)

	// 只有「真正上报了命中」才把注入点记为已确认：被低置信度拦下的不算命中，
	// 必须留待下次重新检测，否则一次误判就会把该注入点永久短路掉。
	//
	// 反过来，「干净结论」也只在真正干净时才记：必须一条发现都没报出来，且没有任何
	// 检测器出错。有发现却被门控拦下，说明结论本身是「可疑」而非「干净」；检测器出错
	// 说明这一轮没跑完整——把这两种情况记成干净，会在有效期内一直屏蔽掉真实漏洞。
	switch {
	case reported > 0:
		e.rememberHitPoints(job.points)
	case detectedHere == 0 && firstErr == nil:
		e.rememberMissPoints(job.points)
	}
}

// injectionPointIDs 返回一次事务中所有注入点的稳定身份（详见 Engine.hitPoints 的说明）。
//
// 身份 = 方法 + 站点 + 路径 + 位置:参数名，刻意不含参数值与同名序号。
func injectionPointIDs(req *CapturedRequest) []string {
	if req == nil || req.URL == nil {
		return nil
	}
	points := ParseInjectionPoints(req)
	if len(points) == 0 {
		return nil
	}
	base := req.Method + " " + req.URL.Scheme + "://" + req.URL.Host + req.URL.EscapedPath()
	ids := make([]string, 0, len(points))
	for _, p := range points {
		ids = append(ids, base+"|"+string(p.Location)+":"+p.Name)
	}
	return ids
}

// pointsStatus 报告给定注入点的结论状态。
//
// allHit 为真表示全部已确认命中；allSettled 为真表示全部已有明确结论——要么命中，
// 要么在 missPointTTL 内被判定为干净。两者都足以整天短路，但结论相反，调用方据此
// 给出不同 verdict，不能合并成一个布尔。
//
// 只对「全部已有结论」返回真：只要还有一个未确认的注入点，就必须整体重测，因为
// 检测器是按事务调用的，无法只补测其中一部分。这同时保证了结论不明的请求永远照常重测。
func (e *Engine) pointsStatus(ids []string) (allHit, allSettled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	allHit = true
	allSettled = true
	for _, id := range ids {
		if _, ok := e.hitPoints[id]; ok {
			continue
		}
		allHit = false
		if at, ok := e.missPoints[id]; ok && now.Sub(at) < missPointTTL {
			continue
		}
		allSettled = false
	}
	return allHit, allSettled
}

// allPointsInFlight 报告这些注入点是否**全部**已被在途事务覆盖。
//
// 与 pointsStatus 一样要求「全部」，原因相同：检测器按事务调用，只要有任一注入点
// 没有在途覆盖，就必须整体检测，不能只补测其中一部分。因此只要有一个点是新的，
// 这条请求就照常进入检测。
func (e *Engine) allPointsInFlight(ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range ids {
		if e.inFlightPoints[id] <= 0 {
			return false
		}
	}
	return true
}

// retainInFlightPoints 为一批注入点占用在途计数，必须在投递检测队列前调用。
func (e *Engine) retainInFlightPoints(ids []string) {
	if len(ids) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range ids {
		e.inFlightPoints[id]++
	}
}

// releaseInFlightPoints 释放在途计数，在检测结束后调用（含投递失败的回滚）。
//
// 归零即删除键，让 map 规模始终等于「当前真正在途的注入点数」，不会随运行时间增长。
func (e *Engine) releaseInFlightPoints(ids []string) {
	if len(ids) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range ids {
		if n := e.inFlightPoints[id]; n > 1 {
			e.inFlightPoints[id] = n - 1
			continue
		}
		delete(e.inFlightPoints, id)
	}
}

// rememberHitPoints 记录已确认命中的注入点，供后续重复流量短路。
func (e *Engine) rememberHitPoints(ids []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range ids {
		if len(e.hitPoints) >= maxHitPoints {
			// 整体清空，退化为"窗口内短路"。清空只会让后续请求重新被检测，
			// 是偏安全的一侧；表无限增长则是实打实的内存风险。
			e.hitPoints = make(map[string]struct{}, maxHitPoints/4)
		}
		e.hitPoints[id] = struct{}{}
	}
}

// rememberMissPoints 记录「已判定无注入」的注入点身份与时刻，供 TTL 内短路。
//
// 与 rememberHitPoints 的关键差别是它带有效期：干净结论可能因站点改配置/上线新版本
// 而失效，过期后必须重新复测，否则会永久屏蔽掉此后才出现的漏洞。
func (e *Engine) rememberMissPoints(ids []string) {
	if len(ids) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for _, id := range ids {
		if len(e.missPoints) >= maxMissPoints {
			// 整体清空，退化为"窗口内记忆"。清空只会让后续请求重新被检测，
			// 是偏安全的一侧；表无限增长则是实打实的内存风险。
			e.missPoints = make(map[string]time.Time, maxMissPoints/4)
		}
		e.missPoints[id] = now
	}
}

// verdictOf 把「跑了哪些检测器 / 是否出错 / 是否命中 / 是否被去重」归纳成一句结论。
//
// 去重必须单独成一类：它代表「确实检出了」，只是此前已上报过。若并入 no-finding，
// 界面会显示「检测无结论」，等于抹掉了真实发现。
func verdictOf(ran []string, reported, duplicated int, err error) TrafficVerdict {
	if reported > 0 {
		return VerdictFinding
	}
	if duplicated > 0 {
		return VerdictDuplicate
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

func (e *Engine) emitTraffic(tx *CapturedTransaction, verdict TrafficVerdict, reason string, findings, duplicated int, err error, ran []string) {
	if e.opts.OnTraffic == nil || tx == nil {
		return
	}
	ev := TrafficEvent{
		ID:         tx.ID,
		Time:       tx.StartAt,
		Verdict:    verdict,
		Reason:     reason,
		Findings:   findings,
		Duplicated: duplicated,
		Detectors:  ran,
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

// markSeen 标记一次命中，返回「本次运行内是否首次见到该指纹」。
//
// 去重只作用于「单次运行」：同一进程内重复命中会记为 duplicated（实时流量显示
// 「重复命中」），避免同一条流量被反复落库。跨运行的聚合不在这里做——那由存储层
// 按 (project_id, fingerprint) 的 upsert 负责：重启后同一处漏洞会命中已有记录、
// 累加次数并刷新 last_seen，而不是被永久当成「重复」而丢掉。
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
