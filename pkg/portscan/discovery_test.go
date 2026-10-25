package portscan

import (
	"context"
	"net"
	"regexp"
	"strconv"
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

// 原生 ICMP 的等待时间跟随 -timeout，并收敛到 [2s, 6s]。
func TestICMPProbeTimeoutFollowsUserBudget(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, 2 * time.Second},
		{300 * time.Millisecond, 2 * time.Second},
		{time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{5 * time.Second, 6 * time.Second},
		{30 * time.Second, 6 * time.Second},
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

// 探测预算按「主机」而非「端口」计：一台不回包的主机不该耗掉几十个超时。
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
	// primary + fallback 各一个预算，留足调度余量；原来的逐端口串行会是 60 倍预算。
	if limit := 10 * opts.Timeout; elapsed > limit {
		t.Fatalf("单主机探测耗时 %s，超出预算上限 %s", elapsed, limit)
	}
}

// 已取消的上下文应立即返回，不再发起新探测。
func TestProbePortsStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if probePorts(ctx, "127.0.0.1", []int{1, 2, 3, 4}, make(chan struct{}, 4)) {
		t.Fatalf("已取消的上下文不该判定存活")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("已取消的上下文应立即返回，实际耗时 %s", elapsed)
	}
}

// 核心不变量：一台「连得上却不回包」的 filtered 主机只该吃掉一个主机预算（primary +
// fallback 各一次），而不是 40+20 个端口各自的超时。用注入的阻塞式探测模拟黑洞目标。
func TestTCPDiscoveryFilteredHostCostsOneBudget(t *testing.T) {
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
	if limit := 4 * opts.Timeout; elapsed > limit {
		t.Fatalf("单台 filtered 主机耗时 %s，超出 %s（预算未按主机计）", elapsed, limit)
	}
	// 每个阶段最多 fanout 个 worker 各卡在一次探测上，两阶段合计不超过 2×fanout。
	if max := int32(2 * tcpDiscoveryFanout); calls > max {
		t.Fatalf("发起了 %d 次探测，超出上限 %d（在逐端口串行尝试）", calls, max)
	}
}
