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

// listenPort 起一个只用于「能否连上」判定的监听器，返回其端口；测试结束自动关闭。
func listenPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return listenerPort(t, ln)
}

// closedPort 返回一个刚被关闭、因此确定不会接受的端口。
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listenerPort(t, ln)
	_ = ln.Close()
	return port
}

func listenerPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	return p
}

// 哨兵预探测：对「全端口都回 SYN-ACK」的设备（WAF/高防/端口转发）必须提前剔除，避免为
// 一批假开放白跑数小时；命中数不足阈值的正常主机必须原样保留，不能被误剔。
func TestDropSpoofingHosts(t *testing.T) {
	orig := sentinelPorts
	t.Cleanup(func() { sentinelPorts = orig })

	openA := listenPort(t)
	openB := listenPort(t)
	closedA := closedPort(t)
	closedB := closedPort(t)

	newScanner := func(t *testing.T) *Scanner {
		t.Helper()
		sc, err := NewScanner(DefaultOptions())
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		return sc
	}

	t.Run("two-open-sentinels-dropped", func(t *testing.T) {
		sentinelPorts = func() []int { return []int{openA, openB, closedA} }
		sc := newScanner(t)
		kept := sc.dropSpoofingHosts(context.Background(), []string{"127.0.0.1"})
		if len(kept) != 0 {
			t.Fatalf("2/3 哨兵开放应判定为代答并剔除，实际保留 %v", kept)
		}
		if !sc.isHostSuspicious("127.0.0.1") {
			t.Fatalf("被剔除的主机应标记为 suspicious，避免后续再探")
		}
	})

	t.Run("one-open-sentinel-kept", func(t *testing.T) {
		sentinelPorts = func() []int { return []int{openA, closedA, closedB} }
		sc := newScanner(t)
		kept := sc.dropSpoofingHosts(context.Background(), []string{"127.0.0.1"})
		if len(kept) != 1 || kept[0] != "127.0.0.1" {
			t.Fatalf("仅 1/3 哨兵开放的正常主机不该被剔除，实际 %v", kept)
		}
		if sc.isHostSuspicious("127.0.0.1") {
			t.Fatalf("正常主机不该被标记为 suspicious")
		}
	})
}

// 代答识别只在大端口集扫描时开启，并可由 -ps-no-spoof-check 关闭。
func TestSpoofDetectionEnabled(t *testing.T) {
	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if sc.spoofDetectionEnabled() {
		t.Fatalf("小端口集扫描不该启用代答识别")
	}
	atomic.StoreUint64(&sc.scanPortTotal, heuristicsMinPorts)
	if !sc.spoofDetectionEnabled() {
		t.Fatalf("大端口集扫描应启用代答识别")
	}
	sc.options.SkipSpoofCheck = true
	if sc.spoofDetectionEnabled() {
		t.Fatalf("-ps-no-spoof-check 应关闭代答识别")
	}
}

// addPortRun 是 O(1) 的连续段统计：无论按什么顺序并入，都应给出所在整段的长度，且重复
// 并入同一个端口不影响结果（探测是并发的，端口可能被重复发现）。
func TestAddPortRun(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		runLen := make(map[int]int)
		for i, port := range []int{100, 101, 102, 103} {
			if got := addPortRun(runLen, port); got != i+1 {
				t.Fatalf("顺序并入 %d 后段长=%d，期望 %d", port, got, i+1)
			}
		}
	})

	t.Run("merge-two-runs", func(t *testing.T) {
		runLen := make(map[int]int)
		// 先造 [100,101] 与 [103,104] 两段，再用 102 把它们缝起来。
		addPortRun(runLen, 100)
		addPortRun(runLen, 101)
		addPortRun(runLen, 103)
		addPortRun(runLen, 104)
		if got := addPortRun(runLen, 102); got != 5 {
			t.Fatalf("并入桥接端口后段长=%d，期望 5", got)
		}
		// 段两端都要能查回整段长度。
		if got := runLen[100]; got != 5 {
			t.Fatalf("段左端记录的段长=%d，期望 5", got)
		}
		if got := runLen[104]; got != 5 {
			t.Fatalf("段右端记录的段长=%d，期望 5", got)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		runLen := make(map[int]int)
		addPortRun(runLen, 200)
		addPortRun(runLen, 201)
		if got := addPortRun(runLen, 200); got != 2 {
			t.Fatalf("重复并入已存在的端口段长=%d，期望 2", got)
		}
	})
}

// noteBanner 只统计「足够长、逐字节相同」的响应：短响应在正常主机上也会大量重复，计入
// 统计没有区分度；指纹种类数达到上限后不再接受新指纹，避免无界增长。
func TestNoteBanner(t *testing.T) {
	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	st := newHostScanStat()
	short := "HTTP/1.1 400"
	if got := sc.noteBanner(st, short); got != 0 {
		t.Fatalf("过短响应不该计入统计，实际 %d", got)
	}
	long := "HTTP/1.1 200 OK\r\nServer: CW\r\nContent-Length: 0\r\n\r\n" +
		"padding-padding-padding-padding"
	var last int
	for i := 0; i < spoofBannerMinRepeats; i++ {
		last = sc.noteBanner(st, long)
	}
	if last != spoofBannerMinRepeats {
		t.Fatalf("第 %d 次相同响应应计为 %d，实际 %d", spoofBannerMinRepeats, spoofBannerMinRepeats, last)
	}
	// 独立响应各自计数为 1，互不影响。
	if got := sc.noteBanner(st, long+"-x"); got != 1 {
		t.Fatalf("不同响应应单独计数为 1，实际 %d", got)
	}
}

// 指纹种类数达到上限后，新指纹不再纳入统计（返回 0），已跟踪的指纹仍继续累加。
func TestNoteBannerTrackLimit(t *testing.T) {
	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	st := newHostScanStat()
	base := "HTTP/1.1 200 OK\r\nServer: CW\r\nContent-Length: 0\r\n\r\npadding-padding-padding"
	for i := 0; i < spoofBannerTrackLimit; i++ {
		banner := base + strconv.Itoa(i)
		if got := sc.noteBanner(st, banner); got != 1 {
			t.Fatalf("第 %d 个指纹应计为 1，实际 %d", i, got)
		}
	}
	if got := sc.noteBanner(st, base+"overflow"); got != 0 {
		t.Fatalf("超出跟踪上限的新指纹应返回 0，实际 %d", got)
	}
	if got := sc.noteBanner(st, base+"0"); got != 2 {
		t.Fatalf("已跟踪指纹应继续累加为 2，实际 %d", got)
	}
}

// markSuspicious 负责把主机原子地转入 suspicious 并丢弃未决缓冲；状态转换只应发生一次。
func TestMarkSuspicious(t *testing.T) {
	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	st := newHostScanStat()
	st.pending = []*ScanResult{{Host: "192.0.2.1", Port: 80}}

	if !sc.markSuspicious(st) {
		t.Fatalf("首次转入 suspicious 应返回 true")
	}
	if got := atomic.LoadUint32(&st.mode); got != hostModeSuspicious {
		t.Fatalf("mode=%d，期望 hostModeSuspicious", got)
	}
	if len(st.pending) != 0 {
		t.Fatalf("转入 suspicious 应丢弃未决缓冲，实际残留 %d 条", len(st.pending))
	}
	if sc.markSuspicious(st) {
		t.Fatalf("已是 suspicious 时不该再次发生状态转换")
	}
}

// suspectedVerifyOnly 是成段开放 / banner 雷同命中后的统一入口：转入 suspicious 并异步复核。
// 用不可达地址 + 立即取消的 ctx，保证后台复核不会真的发起连接。
func TestSuspectedVerifyOnly(t *testing.T) {
	sc, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	st := newHostScanStat()
	st.pending = []*ScanResult{{Host: "192.0.2.1", Port: 80}}

	ctx, cancel := context.WithCancel(context.Background())
	sc.suspectedVerifyOnly(ctx, "192.0.2.1", st, "segmented-open", "run=64")
	cancel()

	if got := atomic.LoadUint32(&st.mode); got != hostModeSuspicious {
		t.Fatalf("命中启发式后应转入 suspicious，实际 mode=%d", got)
	}
	if len(st.pending) != 0 {
		t.Fatalf("转入 suspicious 应丢弃未决缓冲，实际残留 %d 条", len(st.pending))
	}
}
