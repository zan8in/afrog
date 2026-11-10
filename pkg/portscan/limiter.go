package portscan

import (
	"context"
	"sync"
	"time"
)

// rateLimiter 限制「每秒新发起多少个探测」，与 ants 池的在飞并发上限正交。
// 只限并发挡不住内网：500 并发配 1ms RTT 的上限是 50 万连接/秒，出口设备的
// NAT/conntrack 会话表会被打满，同网段其他人的新建连接跟着失败。CPS 才是控制
// 「每秒往会话表里塞多少条表项」的那把闸。
//
// 实现是带小突发的令牌桶。高 CPS 下（内网全端口扫描会到 500~4000/s）如果每个
// 探测都 new 一个 timer 再睡几十微秒，定时器分配与调度开销本身就会成为瓶颈；
// 允许一次消耗少量攒下的令牌，可以把「逐个睡」摊平成「攒够一小批再睡一次」，
// 平均速率仍然严格受 rate 约束。突发量按 rate/100 取，最多 64 个探测。
type rateLimiter struct {
	mu     sync.Mutex
	rate   int // tokens per second, <= 0 = unlimited
	tokens float64
	burst  float64
	last   time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	l := &rateLimiter{rate: rate, last: time.Now()}
	l.burst = float64(l.rate / 100)
	if l.burst < 1 {
		l.burst = 1
	}
	if l.burst > 64 {
		l.burst = 64
	}
	l.tokens = l.burst
	return l
}

// setRate 供拥塞控制器在运行时调整速率；调低立即生效（已预约的时刻不回退）。
func (l *rateLimiter) setRate(rate int) {
	l.mu.Lock()
	l.rate = rate
	burst := float64(rate / 100)
	if burst < 1 {
		burst = 1
	}
	if burst > 64 {
		burst = 64
	}
	l.burst = burst
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.mu.Unlock()
}

func (l *rateLimiter) ratePerSec() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// wait 阻塞到可以再发起一个探测；ctx 结束则返回其错误。调用方是单线程的提交循环，
// 所以这里的阻塞睡眠本身就是限速手段，不会拖慢别的提交流。
func (l *rateLimiter) wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		l.mu.Lock()
		rate := l.rate
		if rate <= 0 {
			l.mu.Unlock()
			return ctx.Err()
		}
		now := time.Now()
		if l.last.IsZero() {
			l.last = now
		}
		if now.After(l.last) {
			l.tokens += now.Sub(l.last).Seconds() * float64(rate)
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		deficit := (1 - l.tokens) / float64(rate)
		l.mu.Unlock()

		if deficit <= 0 {
			continue
		}
		timer := time.NewTimer(time.Duration(deficit * float64(time.Second)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// hostLimiter 是按目标分桶的连接速率限制器。单个目标限速必须存在：全局闸门再严，
// 一个目标也足以独自把出口设备的会话表塞满，而内网扫描往往就是一个目标。
// 只有提交循环（单 goroutine）会访问它，所以不需要额外的锁。
type hostLimiter struct {
	rate    int
	perHost map[string]*rateLimiter
}

func newHostLimiter(rate int) *hostLimiter {
	if rate <= 0 {
		return nil
	}
	return &hostLimiter{rate: rate, perHost: make(map[string]*rateLimiter)}
}

func (h *hostLimiter) wait(ctx context.Context, host string) error {
	if h == nil {
		return ctx.Err()
	}
	l, ok := h.perHost[host]
	if !ok {
		l = newRateLimiter(h.rate)
		h.perHost[host] = l
	}
	return l.wait(ctx)
}
