package portscan

import (
	"context"
	"time"
)

const (
	// congestionWindow 是统计窗口：太短会被单次抖动带偏，太长则降速不够及时。
	congestionWindow = 2 * time.Second
	// congestionWarmup 让扫描先跑起来再开始判定，避免刚起步的几百个探测就触发降速。
	congestionWarmup = 3 * time.Second
	// congestionDecrease 是乘性降因子，congestionIncreaseStep 是加性升的比例。
	congestionDecrease     = 0.7
	congestionIncreaseStep = 8
	// 网关 RTT 相对空载基线的倍率阈值。
	congestionLinkHigh = 3.0
	congestionLinkLow  = 1.5
	// congestionLinkLossStreak 是判定「本机出口已经不通」所需的、连续收不到网关回包的
	// 窗口数。一个窗口只有一次网关采样，单次超时可能只是抖动；连续失败才是硬故障。
	// 窗口 2s，3 个窗口 ≈ 6s 完全收不到网关回音。
	congestionLinkLossStreak = 3
	// 持续降速时的最小重复告警间隔，避免长时间劣化在终端上完全静默。
	congestionWarnInterval = 30 * time.Second
)

// congestionEvent 描述一次速率调整，供调用方渲染告警。
type congestionEvent struct {
	OldRate    int
	NewRate    int
	LinkRTT    time.Duration
	BaselineRT time.Duration
	// Reason 为 link-rtt（网关 RTT 抬升）或 link-loss（网关连续无回包）。
	Reason string
	// LinkLossStreak 是触发 link-loss 时的连续失败窗口数，仅用于展示。
	LinkLossStreak int
	Recovered      bool
}

// congestionController 用 AIMD（乘性降、加性升）在运行时调整全局连接速率上限。
//
// 为什么需要它：CPS 天花板是个静态猜值。同一台机器扫外网和扫内网是两个量级的压力，
// 而出口设备的会话表容量、网关的转发能力都不可预知。既然观测得到链路状态，就让它
// 动态收敛：链路吃紧时乘性降速，恢复干净后再逐步加回来，上限不超过用户配置值。
//
// 判定只认本机可测的两个信号，都由 linkProbe 提供：到默认网关的 RTT 相对空载基线的
// 倍率，以及到网关的连续无回包次数。
//
// 为什么不看「探测丢了几个」：目标不回包有两种相反的原因——本机链路堵了，或目标 /
// 中间设备按策略静默过滤。后者在扫公网时是常态（一个全过滤的目标，探测丢包率恒为
// 100%），而本机链路可以完全健康。拿它当拥塞信号，等于对每个被过滤的公网目标误报
// 一次降速，还会让速率长期涨不回去。网关就在本机一跳之外，它的 RTT 抬升与无回包
// 只可能来自本机出口或网关被压满，是唯一干净的本地信号（详见 linkprobe.go）。
type congestionController struct {
	limiter *rateLimiter
	link    *linkProbe

	maxRate int // 天花板（用户配置值），<= 0 表示不限速、控制器不启用
	minRate int // 地板：降到底也要保住可用性
	ctx     context.Context

	// lastDir 记录上一次的调整方向（-1 降 / 0 未调整 / +1 升），用来只在方向翻转时告警。
	lastDir  int
	lastWarn time.Time

	onChange func(congestionEvent)

	stop chan struct{}
	done chan struct{}
}

// newCongestionController 在限速器存在且用户设了非零上限时才创建。
// 上限为 0 表示用户显式要求不限速（-pcps 0 / -aggressive），不做任何干预。
func newCongestionController(ctx context.Context, limiter *rateLimiter, link *linkProbe, maxRate int, onChange func(congestionEvent)) *congestionController {
	if limiter == nil || maxRate <= 0 {
		return nil
	}
	floor := maxRate / 4
	if floor < 100 {
		floor = 100
	}
	if floor > maxRate {
		floor = maxRate
	}
	return &congestionController{
		limiter:  limiter,
		link:     link,
		maxRate:  maxRate,
		minRate:  floor,
		ctx:      ctx,
		lastDir:  0,
		onChange: onChange,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (c *congestionController) start() {
	if c == nil {
		return
	}
	go func() {
		defer close(c.done)
		timer := time.NewTimer(congestionWarmup)
		defer timer.Stop()
		select {
		case <-c.stop:
			return
		case <-c.ctx.Done():
			return
		case <-timer.C:
		}
		ticker := time.NewTicker(congestionWindow)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.tick()
			}
		}
	}()
}

func (c *congestionController) close() {
	if c == nil {
		return
	}
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	<-c.done
}

func (c *congestionController) tick() {
	c.link.sample(c.ctx)
	linkRatio, linkRTT, baseline := c.link.ratio()
	linkLoss := c.link.gatewayLossStreak()

	cur := c.limiter.ratePerSec()
	if cur <= 0 {
		return
	}

	reason := ""
	switch {
	case linkRatio >= congestionLinkHigh:
		reason = "link-rtt"
	case linkLoss >= congestionLinkLossStreak:
		reason = "link-loss"
	}

	if reason != "" {
		next := int(float64(cur) * congestionDecrease)
		if next < c.minRate {
			next = c.minRate
		}
		if next < cur {
			c.limiter.setRate(next)
			first := c.lastDir != -1
			c.lastDir = -1
			if first || time.Since(c.lastWarn) >= congestionWarnInterval {
				c.lastWarn = time.Now()
				c.onChange(congestionEvent{
					OldRate: cur, NewRate: next,
					LinkRTT: linkRTT, BaselineRT: baseline,
					Reason: reason, LinkLossStreak: linkLoss,
				})
			}
		}
		return
	}

	if cur >= c.maxRate {
		c.lastDir = 0
		return
	}
	// 恢复的门槛比降速低：网关回包正常（没有连续失败，RTT 也没有明显抬升）才敢加回来，
	// 避免刚恢复就把压力重新拉满。
	if linkLoss > 0 || linkRatio >= congestionLinkLow {
		return
	}
	next := cur + cur/congestionIncreaseStep
	if step := c.maxRate / congestionIncreaseStep; next < cur+step {
		next = cur + step
	}
	if next > c.maxRate {
		next = c.maxRate
	}
	if next <= cur {
		return
	}
	c.limiter.setRate(next)
	if c.lastDir < 0 {
		c.onChange(congestionEvent{
			OldRate: cur, NewRate: next,
			LinkRTT: linkRTT, BaselineRT: baseline, Recovered: true,
		})
	}
	c.lastDir = 1
}
