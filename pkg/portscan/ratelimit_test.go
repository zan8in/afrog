package portscan

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterUnlimitedWhenNonPositive(t *testing.T) {
	l := newRateLimiter(0)
	start := time.Now()
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("unlimited limiter blocked for %v", elapsed)
	}
}

// 限速器必须真的把取号人按 1/rate 的间隔摊开，否则「保护 NAT 会话表」只是一句口号。
func TestRateLimiterPacesTakers(t *testing.T) {
	l := newRateLimiter(100) // 10ms 间隔
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.wait(context.Background()); err != nil {
			t.Fatalf("wait #%d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	// 第一个号立即放行，其后 4 次各等一个间隔。
	if elapsed < 30*time.Millisecond {
		t.Fatalf("5 次取号仅耗时 %v，限速未生效", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("5 次取号耗时 %v，限速过慢", elapsed)
	}
}

func TestRateLimiterSetRate(t *testing.T) {
	l := newRateLimiter(10)
	l.setRate(500)
	if got := l.ratePerSec(); got != 500 {
		t.Fatalf("ratePerSec = %d, want 500", got)
	}
}

// 扫描被取消时，等号的协程必须立刻醒过来，不能把退出拖到限速间隔之后。
func TestRateLimiterStopsOnCancel(t *testing.T) {
	l := newRateLimiter(1) // 1s 间隔
	ctx, cancel := context.WithCancel(context.Background())
	if err := l.wait(ctx); err != nil { // 占掉第一个号（立即放行）
		t.Fatalf("first wait: %v", err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := l.wait(ctx); err == nil {
		t.Fatal("wait should return the context error")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("wait ignored cancelling for %v", elapsed)
	}
}

func TestHostLimiterDisabledWhenNonPositive(t *testing.T) {
	h := newHostLimiter(0)
	if h != nil {
		t.Fatal("rate <= 0 should disable the per-host limiter")
	}
	if err := h.wait(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("nil hostLimiter should be a no-op, got %v", err)
	}
}

// 单目标限速是按目标分桶的，不能退化成「所有目标共用一个号」。
func TestHostLimiterKeepsHostsIndependent(t *testing.T) {
	h := newHostLimiter(100) // 每目标 10ms
	start := time.Now()
	for _, host := range []string{"a", "b", "c"} {
		if err := h.wait(context.Background(), host); err != nil {
			t.Fatalf("wait(%s): %v", host, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("不同目标互相阻塞，耗时 %v", elapsed)
	}
	if got := len(h.perHost); got != 3 {
		t.Fatalf("perHost buckets = %d, want 3", got)
	}
}

func TestHostLimiterPacesSameHost(t *testing.T) {
	h := newHostLimiter(100)
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := h.wait(context.Background(), "10.0.0.1"); err != nil {
			t.Fatalf("wait #%d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("同一目标的 4 次取号仅耗时 %v，单目标限速未生效", elapsed)
	}
}

func TestLinkProbeRatioNeutralWithoutSignal(t *testing.T) {
	var nilProbe *linkProbe
	if ratio, _, _ := nilProbe.ratio(); ratio != 1 {
		t.Fatalf("nil linkProbe ratio = %v, want 1", ratio)
	}
	// 没有基线（网关不可达）时必须返回中性值，不能让缺失的信号触发降速。
	noBaseline := &linkProbe{}
	if ratio, _, _ := noBaseline.ratio(); ratio != 1 {
		t.Fatalf("baseline-less ratio = %v, want 1", ratio)
	}
	noSamples := &linkProbe{baseline: 10 * time.Millisecond}
	if ratio, _, _ := noSamples.ratio(); ratio != 1 {
		t.Fatalf("sample-less ratio = %v, want 1", ratio)
	}
}

func TestLinkProbeRatioUsesMedian(t *testing.T) {
	p := &linkProbe{
		baseline: 10 * time.Millisecond,
		recent: []time.Duration{
			50 * time.Millisecond,
			10 * time.Millisecond,
			20 * time.Millisecond,
		},
	}
	ratio, rtt, baseline := p.ratio()
	if rtt != 20*time.Millisecond {
		t.Fatalf("median RTT = %v, want 20ms", rtt)
	}
	if baseline != 10*time.Millisecond {
		t.Fatalf("baseline = %v, want 10ms", baseline)
	}
	if ratio < 1.9 || ratio > 2.1 {
		t.Fatalf("ratio = %v, want ~2", ratio)
	}
}

func TestCongestionControllerSkippedWithoutCap(t *testing.T) {
	if c := newCongestionController(context.Background(), newRateLimiter(100), nil, 0, nil); c != nil {
		t.Fatal("maxRate 0 (不限速) should disable the controller")
	}
	if c := newCongestionController(context.Background(), nil, nil, 100, nil); c != nil {
		t.Fatal("nil limiter should disable the controller")
	}
}

// 网关 RTT 相对空载基线抬升到 3 倍以上，说明本机出口链路吃紧：必须乘性降速。
func TestCongestionControllerEasesOffOnLinkRTT(t *testing.T) {
	l := newRateLimiter(1000)
	link := &linkProbe{baseline: 10 * time.Millisecond, recent: []time.Duration{40 * time.Millisecond}}
	var events []congestionEvent
	c := newCongestionController(context.Background(), l, link, 1000, func(ev congestionEvent) {
		events = append(events, ev)
	})
	c.tick()

	if got := l.ratePerSec(); got != 700 {
		t.Fatalf("rate = %d, want 700 after one multiplicative decrease", got)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one easing-off warning", events)
	}
	if events[0].Reason != "link-rtt" || events[0].Recovered {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

// 网关连续多个窗口无回包才算链路故障，判定门槛之前不能动速率。
func TestCongestionControllerLinkLossThreshold(t *testing.T) {
	l := newRateLimiter(1000)
	link := &linkProbe{baseline: 10 * time.Millisecond, streak: congestionLinkLossStreak - 1}
	c := newCongestionController(context.Background(), l, link, 1000, func(congestionEvent) {})

	c.tick()
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want unchanged 1000 below the streak threshold", got)
	}

	link.streak = congestionLinkLossStreak
	c.tick()
	if got := l.ratePerSec(); got != 700 {
		t.Fatalf("rate = %d, want 700 at the streak threshold", got)
	}
}

// 目标是死的（探测全超时）不该动全局速率：被防火墙静默过滤的公网目标丢包率恒为
// 100%，只有网关信号才能证明是本机链路的问题。控制器已不看探测结果，这里用一个
// 没有网关的探针（nil）代表「没有本地信号」的场景，速率必须纹丝不动。
func TestCongestionControllerIgnoresTargetNonReplies(t *testing.T) {
	l := newRateLimiter(1000)
	c := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	for i := 0; i < 50; i++ {
		c.tick()
	}
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want a calm 1000 with no link signal", got)
	}
}

func TestCongestionControllerRecovers(t *testing.T) {
	l := newRateLimiter(1000)
	link := &linkProbe{baseline: 10 * time.Millisecond, recent: []time.Duration{40 * time.Millisecond}}
	var events []congestionEvent
	c := newCongestionController(context.Background(), l, link, 1000, func(ev congestionEvent) {
		events = append(events, ev)
	})

	c.tick() // 网关 RTT 抬升 -> 700
	if got := l.ratePerSec(); got != 700 {
		t.Fatalf("rate = %d, want 700 after easing off", got)
	}
	events = nil

	// 网关回包恢复正常（无 RTT 样本、无连续失败）后，速率应逐步加回来并提示一次恢复。
	link.recent = nil
	c.tick()
	got := l.ratePerSec()
	if got <= 700 || got > 1000 {
		t.Fatalf("rate = %d, want (700, 1000] after additive increase", got)
	}
	if len(events) != 1 || !events[0].Recovered {
		t.Fatalf("events = %+v, want one recovered warning", events)
	}
}

func TestCongestionControllerRecoversUpToCap(t *testing.T) {
	l := newRateLimiter(300)
	c := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	for i := 0; i < 50; i++ {
		c.tick()
	}
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want the cap 1000", got)
	}
}

func TestCongestionControllerStopsAtFloor(t *testing.T) {
	l := newRateLimiter(1000)
	link := &linkProbe{baseline: 10 * time.Millisecond, recent: []time.Duration{40 * time.Millisecond}}
	c := newCongestionController(context.Background(), l, link, 1000, func(congestionEvent) {})
	for i := 0; i < 20; i++ {
		c.tick()
	}
	// floor = maxRate/4，降到底也要保住可用性。
	if got := l.ratePerSec(); got != 250 {
		t.Fatalf("rate = %d, want the floor 250", got)
	}
}

func TestCongestionControllerNilSafe(t *testing.T) {
	var c *congestionController
	c.start()
	c.close()

	// 探针缺失（nil link）时 tick 也不能崩，且不产生任何调整。
	l := newRateLimiter(1000)
	nilLink := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	nilLink.tick()
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want an untouched 1000", got)
	}
	var p *linkProbe
	if s := p.gatewayLossStreak(); s != 0 {
		t.Fatalf("nil linkProbe streak = %d, want 0", s)
	}
	p.sample(context.Background())
}
