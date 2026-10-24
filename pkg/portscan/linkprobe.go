package portscan

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// linkProbeTimeout 是单次链路探针的超时。链路探针只关心「回包多快」，不需要给慢
// 网关留长预算：超时即视为无样本，不参与判定，以免把探针自身的耗时算进 RTT。
const linkProbeTimeout = 300 * time.Millisecond

// linkProbe 周期性测量到默认网关的 RTT，用来把「链路堵了」和「目标本来就不回包」
// 区分开。没有这个信号时，只能看丢包率，而一个被防火墙 drop 的目标丢包率恒为
// 100%，会被误判成拥塞；网关就在本机这一跳，它的 RTT 抬升只可能来自本机出口链路
// 或网关本体被压满，是干净的本地信号。
//
// 探针不打 ICMP（raw socket 需要特权，普通用户拿不到），改为对网关做 TCP connect：
// 连通或收到 RST 都算一次有效 RTT 样本，只有超时才算无样本。
type linkProbe struct {
	gateway string

	mu       sync.Mutex
	baseline time.Duration
	recent   []time.Duration
}

// newLinkProbe 探测默认网关；发现不到（或平台不支持）时返回 nil，调用方据此禁用
// 链路信号，拥塞控制退化为只依赖探测结果。
func newLinkProbe() *linkProbe {
	gw := defaultGateway()
	if gw == "" {
		return nil
	}
	return &linkProbe{gateway: gw}
}

// measure 采样一次网关 RTT。
func (p *linkProbe) measure(ctx context.Context) (time.Duration, bool) {
	if p == nil || p.gateway == "" {
		return 0, false
	}
	// 网关不一定开着管理端口，80/443 任一有响应就够；两个都超时才算没有样本。
	for _, port := range []int{80, 443} {
		d := net.Dialer{Timeout: linkProbeTimeout}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.gateway, strconv.Itoa(port)))
		elapsed := time.Since(start)
		if err == nil {
			conn.Close()
			return elapsed, true
		}
		// RST 也是一次完整的往返：网关活着并且回了话（只是端口没开）。
		if isConnRefused(err) {
			return elapsed, true
		}
	}
	return 0, false
}

// takeBaseline 在扫描开始前取基线。此时还没有本机产生的负载，测到的是这条链路的
// 空载 RTT；取多次的最小值，避开偶发抖动。
func (p *linkProbe) takeBaseline(ctx context.Context) {
	if p == nil {
		return
	}
	best := time.Duration(0)
	for i := 0; i < 3; i++ {
		if rtt, ok := p.measure(ctx); ok && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	if best <= 0 {
		return
	}
	p.mu.Lock()
	p.baseline = best
	p.mu.Unlock()
}

// sample 记录一次负载期间的网关 RTT。
func (p *linkProbe) sample(ctx context.Context) {
	if p == nil {
		return
	}
	rtt, ok := p.measure(ctx)
	if !ok {
		return
	}
	p.mu.Lock()
	p.recent = append(p.recent, rtt)
	if len(p.recent) > 4 {
		p.recent = p.recent[len(p.recent)-4:]
	}
	p.mu.Unlock()
}

// ratio 返回「当前 RTT / 空载 RTT」。没有基线或没有样本时返回 1（中性，不触发任何
// 判定），避免拿缺失的信号去做降速决策。
func (p *linkProbe) ratio() (float64, time.Duration, time.Duration) {
	if p == nil {
		return 1, 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.baseline <= 0 || len(p.recent) == 0 {
		return 1, 0, 0
	}
	sorted := make([]time.Duration, len(p.recent))
	copy(sorted, p.recent)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	median := sorted[len(sorted)/2]
	return float64(median) / float64(p.baseline), median, p.baseline
}
