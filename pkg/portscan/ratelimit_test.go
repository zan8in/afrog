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

func TestCongestionControllerEasesOffOnLoss(t *testing.T) {
	l := newRateLimiter(1000)
	var events []congestionEvent
	c := newCongestionController(context.Background(), l, nil, 1000, func(ev congestionEvent) {
		events = append(events, ev)
	})

	for i := 0; i < 100; i++ {
		c.observe(false)
	}
	c.tick()

	if got := l.ratePerSec(); got != 700 {
		t.Fatalf("rate = %d, want 700 after one multiplicative decrease", got)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one easing-off warning", events)
	}
	if events[0].Reason != "no-reply" || events[0].Recovered || events[0].LossPct != 100 {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestCongestionControllerIgnoresThinSamples(t *testing.T) {
	l := newRateLimiter(1000)
	c := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	// 样本不足 congestionMinSamples 时不判定：几百个探测里有几十个不回包是常态。
	for i := 0; i < 10; i++ {
		c.observe(false)
	}
	c.tick()
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want an unchanged 1000", got)
	}
}

func TestCongestionControllerRecovers(t *testing.T) {
	l := newRateLimiter(1000)
	var events []congestionEvent
	c := newCongestionController(context.Background(), l, nil, 1000, func(ev congestionEvent) {
		events = append(events, ev)
	})

	for i := 0; i < 100; i++ {
		c.observe(false)
	}
	c.tick() // -> 700
	events = nil

	for i := 0; i < 100; i++ {
		c.observe(true)
	}
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
	l := newRateLimiter(1000)
	c := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	for i := 0; i < 10; i++ {
		for j := 0; j < 100; j++ {
			c.observe(true)
		}
		c.tick()
	}
	if got := l.ratePerSec(); got != 1000 {
		t.Fatalf("rate = %d, want the cap 1000", got)
	}
}

func TestCongestionControllerStopsAtFloor(t *testing.T) {
	l := newRateLimiter(1000)
	c := newCongestionController(context.Background(), l, nil, 1000, func(congestionEvent) {})
	for i := 0; i < 20; i++ {
		for j := 0; j < 100; j++ {
			c.observe(false)
		}
		c.tick()
	}
	// floor = maxRate/4，降到底也要保住可用性。
	if got := l.ratePerSec(); got != 250 {
		t.Fatalf("rate = %d, want the floor 250", got)
	}
}

func TestCongestionControllerNilSafe(t *testing.T) {
	var c *congestionController
	c.observe(true)
	c.start()
	c.close()
}
