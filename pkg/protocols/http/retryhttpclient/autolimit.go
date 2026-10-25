package retryhttpclient

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// 自适应单目标限速（-auto-req-limit）的判定参数。窗口、水位、因子刻意与端口扫描的
// AIMD 保持同一套口径，便于对照理解。
const (
	// autoReqLimitWindow 是判定窗口：太短会被单次抖动带偏，太长则降速不够及时。
	autoReqLimitWindow = 2 * time.Second
	// autoReqLimitWarmup 让扫描先跑起来再判定，避免起步阶段的样本带偏。
	autoReqLimitWarmup = 3 * time.Second
	// autoReqLimitMinSamples 是窗口内参与判定的最少请求数上限：样本太少时比率噪声极大。
	// 实际门槛按「本窗口在当前速率下最多能产生多少样本」折算（见 effectiveMinSamples），
	// 否则低于 10 req/s 时窗口内凑不齐 20 个样本，判定会永久失效、降速后再也升不回来。
	autoReqLimitMinSamples = 20
	// 失败率高低水位：过半请求拿不到响应才算目标劣化，回到 5% 以下才算恢复。
	autoReqLimitFailHigh = 0.5
	autoReqLimitFailLow  = 0.05
	// 响应时延相对空载基线的倍率阈值。
	autoReqLimitLatencyHigh = 3.0
	autoReqLimitLatencyLow  = 1.5
	// autoReqLimitDecrease 是乘性降因子，autoReqLimitIncreaseDiv 是加性升的分母（每次 +1/5）。
	autoReqLimitDecrease    = 0.7
	autoReqLimitIncreaseDiv = 5
	// autoReqLimitQueueWaitMs 是「限速器确实在排队」的判定线：低于它说明瓶颈不在我们的
	// 限速器上，提额度没有意义。
	autoReqLimitQueueWaitMs = 250
	// autoReqLimitBaselineFloorMs 给基线时延兜底：本机/局域网时延极低时，一点点抖动
	// 就能算出很高的倍率，会误触发降速。
	autoReqLimitBaselineFloorMs = 50
	// autoReqLimitWarnInterval 是持续降速时的最小重复告警间隔，避免长时间劣化完全静默。
	autoReqLimitWarnInterval = 30 * time.Second
)

var (
	httpAttemptTotal   int64
	httpAttemptFailure int64
	httpLatencyNs      int64
)

// observeHTTPAttempt 记录一次真实网络往返的时延与成败。被上层取消的请求（用户中断、
// 任务硬超时）既不代表目标慢，也不代表目标不可达，不参与判定。
func observeHTTPAttempt(req *http.Request, resp *http.Response, latency time.Duration) {
	if requestCanceled(req) {
		return
	}
	atomic.AddInt64(&httpAttemptTotal, 1)
	if resp == nil {
		atomic.AddInt64(&httpAttemptFailure, 1)
	}
	if latency > 0 {
		atomic.AddInt64(&httpLatencyNs, latency.Nanoseconds())
	}
}

// AutoReqLimitEvent 描述一次限速调整，供调用方渲染告警。
type AutoReqLimitEvent struct {
	OldRate   int
	NewRate   int
	FailPct   int
	Latency   time.Duration
	Baseline  time.Duration
	QueueWait time.Duration
	Reason    string
	Recovered bool
}

var (
	autoReqLimitReporterMu sync.Mutex
	autoReqLimitReporterFn func(AutoReqLimitEvent)
)

// SetAutoReqLimitReporter 注册限速调整回调。本包不直接输出日志，展示口径由上层决定
// （CLI 只在 -debug 下打一行，SDK 可以静默）。
func SetAutoReqLimitReporter(fn func(AutoReqLimitEvent)) {
	autoReqLimitReporterMu.Lock()
	autoReqLimitReporterFn = fn
	autoReqLimitReporterMu.Unlock()
}

func reportAutoReqLimit(ev AutoReqLimitEvent) {
	autoReqLimitReporterMu.Lock()
	fn := autoReqLimitReporterFn
	autoReqLimitReporterMu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

// autoReqLimitController 用 AIMD（乘性降、加性升）在运行时调整单目标请求速率上限。
//
// 为什么需要它：单目标限速值是个静态猜值——同一个数字对响应 20ms 的站点是浪费，对
// 已经在超时的站点又太激进。既然观测得到目标状态，就让它动态收敛：
//
//   - 窗口内过半请求拿不到响应，或平均响应时延相对空载基线抬升 3 倍 → 乘性降速，
//     先把压力让出去；恢复干净后（失败率 < 5% 且时延回落）再逐步加回来。
//   - 只有「限速器确实在排队」时才加性升：排队说明瓶颈在我们的限速器上，而不是在
//     目标那边，此时提额度才有意义。
//
// 判定只看两件本地可测的事实：真实网络往返的失败率与平均时延。被熔断跳过的请求不做
// 任何网络往返，因此不会进入这两个信号。
type autoReqLimitController struct {
	limiter  *hostPortLimiter
	minRate  int
	maxRate  int
	baseline time.Duration

	prev     LiveMetrics
	lastDir  int // -1 降 / 0 未调整 / +1 升，只在方向翻转时告警
	lastWarn time.Time
}

// StartAutoReqLimit 启动双向自适应单目标限速。minRate/maxRate 是速率钳制区间。
func StartAutoReqLimit(stop <-chan struct{}, minRate int, maxRate int) {
	if reqLimiter == nil {
		return
	}
	if minRate <= 0 {
		minRate = 1
	}
	if maxRate < minRate {
		maxRate = minRate
	}
	c := &autoReqLimitController{limiter: reqLimiter, minRate: minRate, maxRate: maxRate}
	go c.run(stop)
}

func (c *autoReqLimitController) run(stop <-chan struct{}) {
	timer := time.NewTimer(autoReqLimitWarmup)
	defer timer.Stop()
	select {
	case <-stop:
		return
	case <-timer.C:
	}

	c.prev = GetLiveMetrics()

	ticker := time.NewTicker(autoReqLimitWindow)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			c.tick()
		}
	}
}

func (c *autoReqLimitController) tick() {
	cur := GetLiveMetrics()
	dAttempts := cur.HTTPAttempts - c.prev.HTTPAttempts
	dFailures := cur.HTTPFailures - c.prev.HTTPFailures
	dLatencyNs := cur.HTTPLatencyNs - c.prev.HTTPLatencyNs
	dWaitCount := cur.ReqLimitWaitCount - c.prev.ReqLimitWaitCount
	dWaitNs := cur.ReqLimitWaitNs - c.prev.ReqLimitWaitNs
	c.prev = cur

	current := GetReqLimitPerTarget()
	if current <= 0 {
		return
	}
	// 判定门槛随当前速率折算：2s 窗口在速率 r 下最多产生约 2r 个样本。固定门槛 20 等价于
	// 要求 ≥10 req/s，低速时永远凑不齐，降速后就会卡死无法回升。
	minSamples := effectiveMinSamples(current)

	failRate := 0.0
	failPct := 0
	avgLatency := time.Duration(0)
	avgWait := time.Duration(0)
	if dAttempts > 0 {
		failRate = float64(dFailures) / float64(dAttempts)
		failPct = int(failRate * 100)
		avgLatency = time.Duration(dLatencyNs / dAttempts)
	}
	if dWaitCount > 0 {
		avgWait = time.Duration(dWaitNs / dWaitCount)
	}

	c.observeBaseline(avgLatency)
	latencyRatio := 0.0
	if c.baseline > 0 {
		latencyRatio = float64(avgLatency) / float64(c.baseline)
	}

	// 降速信号：要么大面积拿不到响应，要么响应时延明显高于空载基线。
	reason := ""
	if dAttempts >= minSamples {
		if failRate >= autoReqLimitFailHigh {
			reason = "no-response"
		} else if latencyRatio >= autoReqLimitLatencyHigh {
			reason = "latency"
		}
	}
	if reason != "" {
		next := int(float64(current) * autoReqLimitDecrease)
		if next < c.minRate {
			next = c.minRate
		}
		if next < current {
			c.limiter.SetRate(next)
			first := c.lastDir != -1
			c.lastDir = -1
			if first || time.Since(c.lastWarn) >= autoReqLimitWarnInterval {
				c.lastWarn = time.Now()
				reportAutoReqLimit(AutoReqLimitEvent{
					OldRate: current, NewRate: next, FailPct: failPct,
					Latency: avgLatency, Baseline: c.baseline, QueueWait: avgWait, Reason: reason,
				})
			}
		}
		return
	}

	if current >= c.maxRate {
		c.lastDir = 0
		return
	}
	// 只有目标健康、且限速器确实在排队时才提额度。
	if dAttempts < minSamples || failRate >= autoReqLimitFailLow || latencyRatio >= autoReqLimitLatencyLow {
		return
	}
	if avgWait < autoReqLimitQueueWaitMs*time.Millisecond {
		return
	}
	step := current / autoReqLimitIncreaseDiv
	if step < 1 {
		step = 1
	}
	next := current + step
	if next > c.maxRate {
		next = c.maxRate
	}
	if next <= current {
		return
	}
	c.limiter.SetRate(next)
	if c.lastDir < 0 {
		reportAutoReqLimit(AutoReqLimitEvent{
			OldRate: current, NewRate: next, FailPct: failPct,
			Latency: avgLatency, Baseline: c.baseline, QueueWait: avgWait, Recovered: true,
		})
	}
	c.lastDir = 1
}

// effectiveMinSamples 按当前速率折算窗口内的最少样本数：2s 窗口在速率 r 下最多产生约
// 2r 个样本，取它与固定上限 20 的较小值，并保证至少 1。这样低速时也能凑齐判定门槛。
func effectiveMinSamples(rate int) int64 {
	if rate <= 0 {
		return autoReqLimitMinSamples
	}
	n := int(float64(rate) * autoReqLimitWindow.Seconds())
	if n > autoReqLimitMinSamples {
		n = autoReqLimitMinSamples
	}
	if n < 1 {
		n = 1
	}
	return int64(n)
}

// observeBaseline 维护「空载基线时延」：取观测到的最小平均时延，并给一个下限。
// 目标是衰减那个最优值，任何相对它的显著抬升都说明目标开始吃力。
func (c *autoReqLimitController) observeBaseline(avgLatency time.Duration) {
	if avgLatency <= 0 {
		return
	}
	floor := autoReqLimitBaselineFloorMs * time.Millisecond
	if c.baseline == 0 || avgLatency < c.baseline {
		c.baseline = avgLatency
		if c.baseline < floor {
			c.baseline = floor
		}
	}
}
