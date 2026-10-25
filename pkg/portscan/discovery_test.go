package portscan

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// 存活主机结果行与 port-scan / web-probe 同一语法：序号 + [alive] + 目标 + 方括号属性。
func TestFormatAliveHost(t *testing.T) {
	strip := func(s string) string { return ansiRe.ReplaceAllString(s, "") }

	cases := []struct {
		seq   int
		host  string
		proto string
		want  string
	}{
		{1, "127.0.0.1", "icmp", "001 [alive] 127.0.0.1 [icmp]"},
		{12, "example.com", "tcp", "012 [alive] example.com [tcp]"},
		{3, "10.0.0.9", "", "003 [alive] 10.0.0.9"},
		{0, "10.0.0.9", "ping", "[alive] 10.0.0.9 [ping]"}, // n<=0 退化为不带序号的普通结果行
	}
	for _, tc := range cases {
		if got := strip(formatAliveHost(tc.seq, tc.host, tc.proto)); got != tc.want {
			t.Fatalf("formatAliveHost(%d,%q,%q)=%q，期望 %q", tc.seq, tc.host, tc.proto, got, tc.want)
		}
	}
}

// 存活行是「结果」而非过程日志：门控关闭时既不出行，也不该占用序号。
func TestPrintAliveHostGatedOff(t *testing.T) {
	opts := DefaultOptions()
	opts.Quiet = true
	opts.LogDiscoveredHosts = false
	opts.Debug = false

	printAliveHost("10.0.0.1", "icmp", opts)

	if got := atomic.LoadUint64(&opts.aliveSeq); got != 0 {
		t.Fatalf("被门控关闭时不该占用序号，实际 %d", got)
	}
}

func TestScanWithTCPDiscoveryTreatsConnRefusedAsAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	opts := DefaultOptions()
	opts.Targets = []string{"127.0.0.1", "127.0.0.2"}
	opts.Ports = portStr
	opts.Timeout = 200 * time.Millisecond
	opts.Retries = 0
	opts.RateLimit = 100
	opts.SkipDiscovery = false
	opts.DiscoveryMethod = "tcp"
	opts.Quiet = true
	opts.LogDiscoveredHosts = false

	found := make(chan struct{}, 1)
	opts.OnResult = func(r *ScanResult) {
		if r.Host == "127.0.0.1" && r.Port == port {
			select {
			case found <- struct{}{}:
			default:
			}
		}
	}

	sc, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sc.Scan(ctx); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	select {
	case <-found:
	default:
		t.Fatalf("expected open port result for 127.0.0.1:%d", port)
	}
}

func TestVerifyPortHTTPOnRandomPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()

	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	sc.options.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, info := sc.verifyPort(ctx, "127.0.0.1", port)
	if !ok {
		t.Fatalf("expected verify ok")
	}
	if info.Banner == "" {
		t.Fatalf("expected banner")
	}

	<-done
}

// ICMP 回包只带源 IP，必须反查回用户输入的主机名，否则主机名目标在整个 ICMP 阶段
// 永远匹配不上（NewHostIterator 对主机名是原样透传的）。
func TestBuildICMPTargetsMapsReplyIPBackToHostname(t *testing.T) {
	byIP, targets := buildICMPTargets([]string{"localhost", "127.0.0.1"})

	if len(targets) != 1 {
		t.Fatalf("同一 IP 的重复目标应去重，实际 %d 个", len(targets))
	}
	if got := byIP["127.0.0.1"]; got != "localhost" {
		t.Fatalf("byIP[127.0.0.1]=%q，期望保留先出现的主机名 localhost", got)
	}
	if targets[0].host != "localhost" {
		t.Fatalf("targets[0].host=%q，期望 localhost", targets[0].host)
	}
}

// 无法解析的目标不参与探测，也不该让整轮发现失败。
func TestBuildICMPTargetsSkipsUnresolvable(t *testing.T) {
	byIP, targets := buildICMPTargets([]string{"host.invalid.", "127.0.0.1"})
	if len(targets) != 1 || targets[0].host != "127.0.0.1" {
		t.Fatalf("targets=%v，期望只保留 127.0.0.1", targets)
	}
	if len(byIP) != 1 {
		t.Fatalf("byIP 大小=%d，期望 1", len(byIP))
	}
}

// 原生 ICMP 的等待时间跟随 -timeout，并收敛到 [6s, 10s]：地板必须够宽，否则 ICMP
// 被限速的主机会被误判为 down。
func TestICMPProbeTimeoutFollowsUserBudget(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, 6 * time.Second},
		{300 * time.Millisecond, 6 * time.Second},
		{time.Second, 6 * time.Second},
		{2 * time.Second, 6 * time.Second},
		{5 * time.Second, 10 * time.Second},
		{30 * time.Second, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := icmpProbeTimeout(&Options{Timeout: tc.in}); got != tc.want {
			t.Fatalf("icmpProbeTimeout(%s)=%s，期望 %s", tc.in, got, tc.want)
		}
	}
}

// 发现阶段的套接字闸门同样受 fd 预算约束，并保留地板。
func TestTCPDiscoverySocketLimitRespectsFDBudget(t *testing.T) {
	opts := DefaultOptions()
	opts.RateLimit = 1 << 20
	got := tcpDiscoverySocketLimit(opts)

	if budget := fdScanBudget(); budget > 0 && budget >= tcpDiscoveryMinSockets && got > budget {
		t.Fatalf("limit=%d 越过 fd 预算 %d", got, budget)
	}
	if got < tcpDiscoveryMinSockets {
		t.Fatalf("limit=%d 低于地板 %d", got, tcpDiscoveryMinSockets)
	}
}

// 探测预算按端口数折算：每个探测端口都要拿到完整机会，总耗时随之有界。
// 用 RFC 5737 文档网段（192.0.2.0/24）作为不会响应的目标。
func TestTCPDiscoveryBudgetBoundedPerHost(t *testing.T) {
	opts := DefaultOptions()
	opts.Timeout = 300 * time.Millisecond
	opts.RateLimit = 64
	opts.Quiet = true
	opts.LogDiscoveredHosts = false

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	alive := runTCPDiscovery(ctx, opts, []string{"192.0.2.1"}, nil)
	elapsed := time.Since(start)

	if len(alive) != 0 {
		t.Fatalf("文档网段不该被判存活，实际 %v", alive)
	}
	// primary + fallback 两个预算，单个预算 = ceil(端口数/fanout)+1 轮；60 个顺序超时
	// 折算后是 8 轮，留足调度余量取 10 轮。
	if limit := 10 * opts.Timeout; elapsed > limit {
		t.Fatalf("单主机探测耗时 %s，超出预算上限 %s", elapsed, limit)
	}
}

// 已取消的上下文应立即返回，不再发起新探测。
func TestProbePortsStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if probePorts(ctx, "127.0.0.1", []int{1, 2, 3, 4}, make(chan struct{}, 4), 200*time.Millisecond) {
		t.Fatalf("已取消的上下文不该判定存活")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("已取消的上下文应立即返回，实际耗时 %s", elapsed)
	}
}

// 回归测试：探测列表末尾的端口也必须拿到探测机会。
//
// 之前的实现把整机预算压成一个 opt.Timeout，1 秒内只轮询得到前 tcpDiscoveryFanout 个
// 端口，列表深处的开放端口被永久漏掉——真实案例是探测列表第 34 位的 5000 端口上跑着
// Web 服务，主机却因为探不到它被判死。
func TestTCPDiscoveryReachesPortsBeyondFirstFanout(t *testing.T) {
	ports := make([]int, 0, 40)
	for i := 1; i <= 40; i++ {
		ports = append(ports, 40000+i)
	}
	target := ports[len(ports)-1] // 列表最末一个端口，远超第一轮 fanout 覆盖范围

	orig := discoveryDial
	discoveryDial = func(ctx context.Context, host string, port int) bool {
		if port == target {
			return true
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
		return false
	}
	t.Cleanup(func() { discoveryDial = orig })

	opts := DefaultOptions()
	opts.Timeout = 200 * time.Millisecond
	opts.RateLimit = 64
	opts.Quiet = true
	opts.LogDiscoveredHosts = false
	opts.DiscoveryPorts = ports
	opts.DiscoveryFallbackPorts = ports

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alive := runTCPDiscovery(ctx, opts, []string{"10.11.12.13"}, nil)
	if len(alive) != 1 {
		t.Fatalf("末尾端口 %d 开放的主机应被判存活，实际 %v", target, alive)
	}
}

// 黑洞目标（连得上却不回包）的探测次数正好等于探测列表全量：预算按端口数折算的意义
// 就是「列表里每个端口都被探到一次」。既不能漏（漏 = 准确率损失，见
// TestTCPDiscoveryReachesPortsBeyondFirstFanout），也不该重复（重复 = 白白冲击 NAT 表）。
func TestTCPDiscoveryProbesEveryPortOnce(t *testing.T) {
	orig := discoveryDial
	var calls int32
	discoveryDial = func(ctx context.Context, host string, port int) bool {
		atomic.AddInt32(&calls, 1)
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
		return false
	}
	t.Cleanup(func() { discoveryDial = orig })

	opts := DefaultOptions()
	opts.Timeout = 300 * time.Millisecond
	opts.RateLimit = 64
	opts.Quiet = true
	opts.LogDiscoveredHosts = false

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	alive := runTCPDiscovery(ctx, opts, []string{"10.11.12.13"}, nil)
	elapsed := time.Since(start)

	if len(alive) != 0 {
		t.Fatalf("黑洞目标不该被判存活，实际 %v", alive)
	}
	// primary(40) + fallback(20) 各折算一次预算：ceil(40/16)+1=4 轮、ceil(20/16)+1=3 轮，
	// 合计 7 轮；逐端口串行则是 60 次串行超时。留足调度余量取 10 轮。
	if limit := 10 * opts.Timeout; elapsed > limit {
		t.Fatalf("单台 filtered 主机耗时 %s，超出 %s（预算未按端口数折算）", elapsed, limit)
	}
	want := int32(len(defaultDiscoveryPrimaryPorts()) + len(defaultDiscoveryFallbackPorts()))
	if calls != want {
		t.Fatalf("探测次数 %d，期望 %d（每个端口恰好一次）", calls, want)
	}
}

// 显式点名的目标不因探测沉默被剔除：探测只能证明「活着」，不能证明「死了」——目标往往只是
// 挡掉了 ICMP 与探测端口。用户手写的目标一律保留（与 web-probe 同口径），只有 CIDR/range
// 展开出来的地址才接受探测结论的剔除。否则像「10 个手写目标、探测只认下 6 台」的场景会
// 平白丢掉 4 台资产。
func TestExplicitTargetsSurviveDiscoveryFiltering(t *testing.T) {
	// 显式目标 127.0.0.1 与网段 127.0.0.0/28 展开出的地址重叠：显式点名的必须留下，
	// 只在展开里出现的必须按探测结论剔除。监听该端口是为了证明显式目标确实进了扫描。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	// 所有探测一律判死，模拟目标挡掉全部探测包。
	orig := discoveryDial
	discoveryDial = func(ctx context.Context, host string, port int) bool { return false }
	t.Cleanup(func() { discoveryDial = orig })

	opts := DefaultOptions()
	opts.Targets = []string{"127.0.0.1", "127.0.0.0/28"} // 显式 1 个 + 展开 14 个
	opts.Ports = portStr
	opts.Timeout = 200 * time.Millisecond
	opts.Retries = 0
	opts.RateLimit = 64
	opts.SkipDiscovery = false
	opts.DiscoveryMethod = "tcp"
	opts.Quiet = true
	opts.LogDiscoveredHosts = false

	var mu sync.Mutex
	scanned := make(map[string]struct{})
	opts.OnResult = func(r *ScanResult) {
		mu.Lock()
		scanned[r.Host] = struct{}{}
		mu.Unlock()
	}
	// portscan 阶段的 total = 扫描主机数 × 端口数，是「目标是否被剔除」的直接证据。
	var portTotal atomic.Int32
	opts.OnProgress = func(phase, status string, finished, total, percent int) {
		if phase == "portscan" && total > 0 {
			portTotal.Store(int32(total))
		}
	}

	sc, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sc.Scan(ctx); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	mu.Lock()
	_, keptExplicit := scanned["127.0.0.1"]
	mu.Unlock()
	if !keptExplicit {
		t.Fatalf("显式目标 127.0.0.1 不该被剔除，实际扫描到 %v", scanned)
	}
	if got := portTotal.Load(); got != 1 {
		t.Fatalf("端口扫描 total=%d，期望 1（1 个显式目标 × 1 个端口：展开出来的 14 个地址应被剔除）", got)
	}
}

// ExplicitHosts 只认「未经展开」的目标：CIDR/range 与它们展开出的地址都不算显式。
func TestHostIteratorExplicitHosts(t *testing.T) {
	hi := NewHostIterator([]string{"127.0.0.20", "example.com", "10.0.0.0/30", "10.1.1.1-10.1.1.3"})
	explicit := hi.ExplicitHosts()

	for _, want := range []string{"127.0.0.20", "example.com"} {
		if _, ok := explicit[want]; !ok {
			t.Fatalf("显式目标 %q 应被记录，实际 %v", want, explicit)
		}
	}
	for _, unwanted := range []string{"10.0.0.0/30", "10.1.1.1-10.1.1.3", "10.0.0.1", "10.1.1.2"} {
		if _, ok := explicit[unwanted]; ok {
			t.Fatalf("%q 不是显式目标，不该被记录，实际 %v", unwanted, explicit)
		}
	}
}
