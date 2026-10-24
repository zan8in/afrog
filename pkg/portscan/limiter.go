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
// 这里用的是最朴素的 GCRA（令牌间隔固定、突发量为 1）：每次取号把 next 往后推
// 1/rate，取号人睡到自己的号。突发量为 1 意味着探测均匀铺开，正是限速想要的形状；
// 池容量本来就能提供突发。rate <= 0 表示不限速。
type rateLimiter struct {
	mu   sync.Mutex
	rate int // tokens per second, <= 0 = unlimited
	next time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	return &rateLimiter{rate: rate}
}

// setRate 供拥塞控制器在运行时调整速率；调低立即生效（已预约的时刻不回退）。
func (l *rateLimiter) setRate(rate int) {
	l.mu.Lock()
	l.rate = rate
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
	l.mu.Lock()
	rate := l.rate
	if rate <= 0 {
		l.mu.Unlock()
		return ctx.Err()
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	now := time.Now()
	// next 落后于当前时刻说明闲置了一段时间，重置为 now，不给后续探测累积突发额度。
	if l.next.Before(now) {
		l.next = now
	}
	target := l.next
	l.next = l.next.Add(interval)
	l.mu.Unlock()

	d := time.Until(target)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
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
