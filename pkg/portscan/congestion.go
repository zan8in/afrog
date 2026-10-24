package portscan

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// congestionWindow 是统计窗口：太短会被单次抖动带偏，太长则降速不够及时。
	congestionWindow = 2 * time.Second
	// congestionWarmup 让扫描先跑起来再开始判定，避免刚起步的几百个探测就触发降速。
	congestionWarmup = 3 * time.Second
	// congestionMinSamples 是窗口内参与判定的最少探测数：样本太少时丢包率的噪声极大。
	congestionMinSamples = 50
	// 丢包率高低水位：过半探测没回音才算拥塞，恢复到 5% 以下才认为链路干净。
	congestionLossHigh = 0.5
	congestionLossLow  = 0.05
	// congestionDecrease 是乘性降因子，congestionIncreaseStep 是加性升的比例。
	congestionDecrease     = 0.7
	congestionIncreaseStep = 8
	// 网关 RTT 相对空载基线的倍率阈值。
	congestionLinkHigh = 3.0
	congestionLinkLow  = 1.5
	// 持续降速时的最小重复告警间隔，避免长时间劣化在终端上完全静默。
	congestionWarnInterval = 30 * time.Second
)

// congestionEvent 描述一次速率调整，供调用方渲染告警。
type congestionEvent struct {
	OldRate    int
	NewRate    int
	LossPct    int
	LinkRTT    time.Duration
	BaselineRT time.Duration
	Reason     string
	Recovered  bool
}

// congestionController 用 AIMD（乘性降、加性升）在运行时调整全局连接速率上限。
//
// 为什么需要它：CPS 天花板是个静态猜值。同一台机器扫外网和扫内网是两个量级的压力，
// 而出口设备的会话表容量、网关的转发能力都不可预知。既然观测得到链路状态，就让它
// 动态收敛：一旦探测大面积不回包、或网关 RTT 相对空载基线明显抬升，就乘性降速；
// 链路恢复干净后再逐步加回来，上限不超过用户配置值。
//
// 判定只看两件事，都是本地可测的：窗口内的丢包率、网关 RTT 相对基线的倍率。
type congestionController struct {
	limiter *rateLimiter
	link    *linkProbe

	maxRate int // 天花板（用户配置值），<= 0 表示不限速、控制器不启用
	minRate int // 地板：降到底也要保住可用性
	ctx     context.Context

	total atomic.Uint64
	loss  atomic.Uint64

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

// observe 记录一个探测结果。ok 为 false 表示这次探测没有任何回音（超时或本地网络
// 错误）。fd 耗尽不属于链路信号，调用方不会传进来。
func (c *congestionController) observe(ok bool) {
	if c == nil {
		return
	}
	c.total.Add(1)
	if !ok {
		c.loss.Add(1)
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
		// 预热期内的样本不参与第一轮判定，先清空。
		c.total.Store(0)
		c.loss.Store(0)

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
	total := c.total.Swap(0)
	loss := c.loss.Swap(0)

	c.link.sample(c.ctx)
	linkRatio, linkRTT, baseline := c.link.ratio()

	lossRate := 0.0
	if total > 0 {
		lossRate = float64(loss) / float64(total)
	}
	lossPct := int(lossRate * 100)

	cur := c.limiter.ratePerSec()
	if cur <= 0 {
		return
	}

	reason := ""
	if linkRatio >= congestionLinkHigh {
		reason = "link-rtt"
	} else if total >= congestionMinSamples && lossRate >= congestionLossHigh {
		reason = "no-reply"
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
					OldRate: cur, NewRate: next, LossPct: lossPct,
					LinkRTT: linkRTT, BaselineRT: baseline, Reason: reason,
				})
			}
		}
		return
	}

	if cur >= c.maxRate {
		c.lastDir = 0
		return
	}
	if total < congestionMinSamples || lossRate >= congestionLossLow || linkRatio >= congestionLinkLow {
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
			OldRate: cur, NewRate: next, LossPct: lossPct,
			LinkRTT: linkRTT, BaselineRT: baseline, Recovered: true,
		})
	}
	c.lastDir = 1
}
