package portscan

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/gologger"
	"golang.org/x/net/icmp"
)

type phaseProgress struct {
	opt         *Options
	phase       string
	total       uint64
	start       time.Time
	done        uint64
	alive       uint64
	lastPercent int32
	stop        chan struct{}
	printMu     sync.Mutex
}

func newPhaseProgress(opt *Options, phase string, total int) *phaseProgress {
	if total < 0 {
		total = 0
	}
	return &phaseProgress{
		opt:         opt,
		phase:       phase,
		total:       uint64(total),
		lastPercent: -1,
		stop:        make(chan struct{}),
	}
}

func (p *phaseProgress) enabled() bool {
	return p != nil && p.opt != nil && p.total > 0 && (p.opt.OnProgress != nil || (!p.opt.Quiet && p.opt.Debug))
}

func (p *phaseProgress) startRender(ctx context.Context) {
	if !p.enabled() {
		return
	}
	p.start = time.Now()
	p.render(false)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stop:
				return
			case <-ticker.C:
				p.render(false)
			}
		}
	}()
}

func (p *phaseProgress) stopRender() {
	if p == nil {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	p.render(true)
	if p.opt != nil && !p.opt.Quiet && p.opt.Debug && p.total > 0 {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
}

func (p *phaseProgress) attempt() {
	if p == nil {
		return
	}
	atomic.AddUint64(&p.done, 1)
}

func (p *phaseProgress) markAlive(host, proto string) {
	if p == nil || p.opt == nil {
		return
	}
	atomic.AddUint64(&p.alive, 1)
	if p.opt.OnDiscoveredHost != nil && strings.TrimSpace(host) != "" {
		p.opt.OnDiscoveredHost(host)
	}
	printAliveHost(host, proto, p.opt)
}

// formatAliveHost 渲染一条存活主机结果行：`序号 [alive] host [proto]`，与 port-scan /
// web-probe 的结果行同一语法（序号 + 徽标 + 目标 + 方括号属性）。proto 是判定依据
// （icmp / ping / tcp），排障时能看出这台机器是怎么被认出来的。
func formatAliveHost(seq int, host, proto string) string {
	attrs := make([]string, 0, 1)
	if p := strings.TrimSpace(proto); p != "" {
		attrs = append(attrs, log.Dim(p))
	}
	return log.ResNum(seq, log.KindBadge("alive"), host, attrs...)
}

// printAliveHost 输出一条存活主机结果行。存活列表是「结果」而非过程日志，默认可见；
// 序号按本次扫描递增，靠 [alive] 徽标与端口 [open] / Web [web] 消歧。
func printAliveHost(host, proto string, opt *Options) {
	if opt == nil || strings.TrimSpace(host) == "" {
		return
	}
	if !opt.LogDiscoveredHosts && !opt.Debug {
		return
	}
	seq := int(atomic.AddUint64(&opt.aliveSeq, 1))
	// 发现阶段的进度条与结果行同走 stderr，先清行再打印，否则两者会拼在同一行上。
	if !opt.Quiet {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
	gologger.Print().Msgf("%s", formatAliveHost(seq, host, proto))
}

func (p *phaseProgress) render(final bool) {
	if p == nil || p.opt == nil {
		return
	}
	p.printMu.Lock()
	defer p.printMu.Unlock()

	done := atomic.LoadUint64(&p.done)
	total := p.total
	if total == 0 {
		return
	}
	if done > total {
		done = total
	}
	percent := int(done * 100 / total)
	if final {
		percent = 100
	}
	if p.opt.OnProgress != nil {
		status := "running"
		if final {
			status = "completed"
		}
		p.opt.OnProgress("host_discovery", status, int(done), int(total), percent)
	}
	printEnabled := !p.opt.Quiet && p.opt.Debug && total > 0
	if !printEnabled {
		return
	}
	if !final && int32(percent) == atomic.LoadInt32(&p.lastPercent) {
		return
	}
	atomic.StoreInt32(&p.lastPercent, int32(percent))

	elapsed := strings.Split(time.Since(p.start).String(), ".")[0] + "s"
	suffix := ""
	fmt.Fprint(os.Stderr, "\r\033[2K")
	fmt.Fprintf(os.Stderr, "\r[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(percent, 0), percent, done, total, elapsed, suffix)
}

func DiscoverAliveHosts(ctx context.Context, opt *Options, hosts []string) ([]string, error) {
	if opt.SkipDiscovery || len(hosts) <= 1 {
		return hosts, nil
	}
	method := strings.ToLower(strings.TrimSpace(opt.DiscoveryMethod))
	if method == "" || method == "auto" {
		var alive []string
		var err error
		pending := hosts
		conn, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if e == nil {
			defer conn.Close()
			pp := newPhaseProgress(opt, "icmp", len(pending))
			pp.startRender(ctx)
			alive, err = runICMPListen(ctx, pending, conn, opt, pp)
			pp.stopRender()
			if err == nil && len(alive) > 0 && len(alive) < len(pending) {
				pending = diffHosts(pending, alive)
			}
		}
		if len(pending) > 0 {
			c2, e2 := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
			if e2 == nil {
				c2.Close()
				pp := newPhaseProgress(opt, "icmp", len(pending))
				pp.startRender(ctx)
				add2, _ := runICMPNoListen(ctx, pending, opt, pp)
				pp.stopRender()
				alive = mergeUnique(alive, add2)
				pending = diffHosts(pending, add2)
			}
		}
		if len(pending) > 0 {
			pp := newPhaseProgress(opt, "ping", len(pending))
			pp.startRender(ctx)
			add3 := runPing(ctx, pending, opt, pp)
			pp.stopRender()
			alive = mergeUnique(alive, add3)
			pending = diffHosts(pending, add3)
		}
		if len(pending) > 0 && opt.DiscoveryRetries > 0 {
			for i := 0; i < opt.DiscoveryRetries && len(pending) > 0; i++ {
				pp := newPhaseProgress(opt, "ping", len(pending))
				pp.startRender(ctx)
				addp := runPing(ctx, pending, opt, pp)
				pp.stopRender()
				alive = mergeUnique(alive, addp)
				pending = diffHosts(pending, addp)
			}
		}
		if len(pending) > 0 {
			pp := newPhaseProgress(opt, "tcp", len(pending))
			pp.startRender(ctx)
			add4 := runTCPDiscovery(ctx, opt, pending, pp)
			pp.stopRender()
			alive = mergeUnique(alive, add4)
		}
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "icmp" {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			defer conn.Close()
			pp := newPhaseProgress(opt, "icmp", len(hosts))
			pp.startRender(ctx)
			alive, _ := runICMPListen(ctx, hosts, conn, opt, pp)
			pp.stopRender()
			logAliveStats(alive, opt)
			return alive, nil
		}
		pp := newPhaseProgress(opt, "icmp", len(hosts))
		pp.startRender(ctx)
		alive, _ := runICMPNoListen(ctx, hosts, opt, pp)
		pp.stopRender()
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "ping" {
		pp := newPhaseProgress(opt, "ping", len(hosts))
		pp.startRender(ctx)
		res := runPing(ctx, hosts, opt, pp)
		pp.stopRender()
		logAliveStats(res, opt)
		return res, nil
	}
	pp := newPhaseProgress(opt, "tcp", len(hosts))
	pp.startRender(ctx)
	res := runTCPDiscovery(ctx, opt, hosts, pp)
	pp.stopRender()
	logAliveStats(res, opt)
	return res, nil
}

// icmpTarget 是一台待探测的主机。host 保持用户输入的原样（可能是主机名），dst 是实际
// 发包用的解析结果。
type icmpTarget struct {
	host string
	dst  *net.IPAddr
}

// buildICMPTargets 解析候选主机，并返回「应答源 IP -> 用户输入主机名」的反查表。
//
// ICMP 回包只带源 IP。原实现直接拿源 IP 与用户输入做字符串比对，目标是主机名时永远
// 匹配不上（NewHostIterator 对主机名原样透传），整个 ICMP 阶段白跑；即便凑巧是 IP，
// 存活列表里也会丢掉用户书写的形式。先解析再反查，两个问题一起解决。
func buildICMPTargets(hosts []string) (map[string]string, []icmpTarget) {
	byIP := make(map[string]string, len(hosts))
	targets := make([]icmpTarget, 0, len(hosts))
	for _, h := range hosts {
		dst, err := net.ResolveIPAddr("ip", h)
		if err != nil || dst == nil {
			continue
		}
		ip := dst.String()
		if _, dup := byIP[ip]; dup {
			continue
		}
		byIP[ip] = h
		targets = append(targets, icmpTarget{host: h, dst: dst})
	}
	return byIP, targets
}

func runICMPListen(ctx context.Context, hosts []string, conn *icmp.PacketConn, opt *Options, pp *phaseProgress) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	byIP, targets := buildICMPTargets(hosts)
	if len(targets) == 0 {
		return nil, nil
	}
	shuffled := append([]icmpTarget(nil), targets...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	var (
		alive []string
		seen  = make(map[string]struct{})
		mu    sync.Mutex
	)
	// end 被接收 goroutine 与发送/等待循环同时读写，必须是原子类型：这里用普通 bool
	// 是实打实的数据竞争。done 用于收尾时唤醒 ctx 监听 goroutine，避免它一直挂到 ctx 结束。
	var end atomic.Bool
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			end.Store(true)
		case <-done:
		}
	}()

	aliveCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(alive)
	}

	go func() {
		buf := make([]byte, 128)
		for !end.Load() {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, src, err := conn.ReadFrom(buf)
			if err != nil || src == nil {
				continue
			}
			host, ok := byIP[src.String()]
			if !ok {
				continue
			}
			mu.Lock()
			if _, dup := seen[host]; !dup {
				seen[host] = struct{}{}
				if pp != nil {
					pp.markAlive(host, "icmp-listen")
				} else {
					logHostAlive(host, "icmp-listen", opt)
				}
				alive = append(alive, host)
			}
			mu.Unlock()
		}
	}()

	for _, t := range shuffled {
		if ctx.Err() != nil || end.Load() {
			break
		}
		if pp != nil {
			pp.attempt()
		}
		conn.WriteTo(makeICMPEcho(t.host), t.dst)
	}

	start := time.Now()
	goal := len(byIP)
	for aliveCount() < goal {
		wait := 6 * time.Second
		if len(targets) <= 256 {
			wait = 3 * time.Second
		}
		if time.Since(start) > wait || ctx.Err() != nil || end.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	end.Store(true)
	return alive, nil
}

func runICMPNoListen(ctx context.Context, hosts []string, opt *Options, pp *phaseProgress) ([]string, error) {
	num := opt.IcmpConcurrency
	if num <= 0 {
		num = 1000
	}
	// 原生 ICMP 是「一台主机一个裸套接字」，同样吃本机 fd。发现阶段跑在正式扫描之前，
	// 必须和端口扫描一样按 fd 预算收敛，否则低配机器会在还没开始扫时先耗尽句柄。
	if fdBudget := fdScanBudget(); fdBudget > 0 && num > fdBudget {
		num = fdBudget
	}
	if len(hosts) < num {
		num = len(hosts)
	}
	budget := icmpProbeTimeout(opt)
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if icmpAlive(host, budget) {
				mu.Lock()
				if pp != nil {
					pp.markAlive(host, "icmp")
				} else {
					logHostAlive(host, "icmp", opt)
				}
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	close(limiter)
	return alive, nil
}

func runPing(ctx context.Context, hosts []string, opt *Options, pp *phaseProgress) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := opt.PingConcurrency
	if limit <= 0 {
		limit = 50
	}
	limiter := make(chan struct{}, limit)
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if execPing(host) {
				mu.Lock()
				if pp != nil {
					pp.markAlive(host, "ping")
				} else {
					logHostAlive(host, "ping", opt)
				}
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return alive
}

// defaultDiscoveryPrimaryPorts is the built-in TCP probe list used when the
// caller has not specified discovery ports. Beyond the classic web/remote-admin
// ports it covers common database and middleware ports so that hosts exposing
// only a business port (e.g. MySQL 3306) are not treated as dead.
func defaultDiscoveryPrimaryPorts() []int {
	return []int{
		80, 443, 22, 3389, 445, 135, 139, 8080, 8443, 8000,
		3306, 5432, 6379, 1433, 1521, 27017, 9200, 11211, 5672, 2181,
		23, 21, 25, 110, 143, 993, 995, 389, 636, 873,
		5900, 2375, 2379, 5000, 7001, 8888, 9090, 10000, 15672, 3128,
	}
}

// defaultDiscoveryFallbackPorts is the secondary probe list used when the
// primary probes yield no response.
func defaultDiscoveryFallbackPorts() []int {
	return []int{
		81, 102, 123, 161, 502, 2049, 3000, 4444, 5555, 8001,
		8081, 8880, 9000, 9443, 10050, 10051, 27018, 50000, 6379, 3307,
	}
}

// shuffledInts returns a shuffled copy of in so that discovery probes do not
// hit the target in a fixed order.
func shuffledInts(in []int) []int {
	out := append([]int(nil), in...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

const (
	// tcpDiscoveryFanout 是单台主机在发现阶段同时打开的探测连接数。给一点并发是为了让
	// 「目标只开一个非顶层端口」能在一个预算内被找到，同时不至于让一台主机吃掉整个额度。
	tcpDiscoveryFanout = 8
	// tcpDiscoveryMinSockets 是发现阶段套接字闸门的地板，保证预算被压得极低时仍能推进。
	tcpDiscoveryMinSockets = 16
)

// tcpDiscoverySocketLimit 收敛发现阶段的在飞套接字数：既尊重用户/档位配置，也不越过
// 本机 fd 预算。发现阶段跑在正式扫描之前，同样占用套接字，不能只让端口扫描去守预算。
func tcpDiscoverySocketLimit(opt *Options) int {
	limit := opt.RateLimit
	if limit <= 0 {
		limit = 100
	}
	if budget := fdScanBudget(); budget > 0 && limit > budget {
		limit = budget
	}
	if limit < tcpDiscoveryMinSockets {
		limit = tcpDiscoveryMinSockets
	}
	return limit
}

// discoveryDial 是发现阶段实际使用的连接探测函数。抽成变量是为了让测试能注入「连得上
// 却不回包」的 filtered 主机，验证预算按主机计的这条不变量；生产路径固定为 dialProvesAlive。
var discoveryDial = dialProvesAlive

// dialProvesAlive 判断一次 TCP 连接尝试是否足以证明主机在线：连上（开放端口）或收到
// RST（连接被拒绝）都说明对端协议栈在工作；只有超时、无路由这类沉默结果才不算证据。
func dialProvesAlive(ctx context.Context, host string, port int) bool {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		c.Close()
		return true
	}
	return isConnRefused(err)
}

// probePorts 用最多 tcpDiscoveryFanout 个 worker 并发探测 ports，任一探测证明主机在线
// 就立即取消其余探测返回 true。所有连接都从 sem 取额度，保证全局在飞套接字不超预算。
func probePorts(ctx context.Context, host string, ports []int, sem chan struct{}) bool {
	if len(ports) == 0 {
		return false
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var alive atomic.Bool
	work := make(chan int)
	// 投喂 goroutine 不加入 wg：worker 提前退出时它靠 pctx.Done 解阻塞，如果把它算进
	// wg，就会出现「worker 等 wg、wg 等投喂」的互等。
	go func() {
		defer close(work)
		for _, p := range ports {
			select {
			case work <- p:
			case <-pctx.Done():
				return
			}
		}
	}()

	workers := tcpDiscoveryFanout
	if len(ports) < workers {
		workers = len(ports)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				select {
				case sem <- struct{}{}:
				case <-pctx.Done():
					return
				}
				proved := discoveryDial(pctx, host, p)
				<-sem
				if proved {
					alive.Store(true)
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()
	return alive.Load()
}

// tcpHostAlive 在一个 opt.Timeout 的预算内判断主机是否在线：先试 primary 端口，仍有
// 余量且开启回退时再试 fallback 端口。
//
// 预算按「主机」而非「端口」计。原实现对每台主机顺序试 40 个 primary + 20 个 fallback
// 端口，每个都用完整 opt.Timeout，一台不回包的主机就要耗掉几十秒——既让发现阶段漫长得
// 不可接受，也把出口设备的 NAT/conntrack 表当成了压力测试靶。
func tcpHostAlive(ctx context.Context, host string, primary, fallback []int, opt *Options, sem chan struct{}) bool {
	hctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if probePorts(hctx, host, primary, sem) {
		return true
	}
	if !opt.DiscoveryFallback || hctx.Err() != nil {
		return false
	}
	return probePorts(hctx, host, fallback, sem)
}

func runTCPDiscovery(ctx context.Context, opt *Options, hosts []string, pp *phaseProgress) []string {
	if len(hosts) == 0 {
		return nil
	}
	primary := opt.DiscoveryPorts
	if len(primary) == 0 {
		primary = shuffledInts(defaultDiscoveryPrimaryPorts())
	}
	fallback := opt.DiscoveryFallbackPorts
	if len(fallback) == 0 {
		fallback = shuffledInts(defaultDiscoveryFallbackPorts())
	}

	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	// 闸门一：在飞套接字总数（worker 每拨一个连接取一次额度）。
	sem := make(chan struct{}, tcpDiscoverySocketLimit(opt))
	// 闸门二：同时在飞的主机数，按 fanout 折算，保证「主机数 × fanout」不越过闸门一。
	hostLimit := cap(sem) / tcpDiscoveryFanout
	if hostLimit < 1 {
		hostLimit = 1
	}
	hostGate := make(chan struct{}, hostLimit)
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		hostGate <- struct{}{}
		go func(h string) {
			defer func() {
				<-hostGate
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if tcpHostAlive(ctx, h, primary, fallback, opt, sem) {
				mu.Lock()
				if pp != nil {
					pp.markAlive(h, "tcp")
				} else {
					logHostAlive(h, "tcp", opt)
				}
				alive = append(alive, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	return alive
}

// icmpProbeTimeout 把原生 ICMP 的等待时间对齐到用户的 -timeout：ICMP 比 TCP connect
// 更容易被限速丢弃，给 2 倍余量，并把结果收敛到 [2s, 6s]。原来的固定 6s 与用户配置
// 无关，在大网段上是白等。
func icmpProbeTimeout(opt *Options) time.Duration {
	base := opt.Timeout
	if base <= 0 {
		base = time.Second
	}
	d := base * 2
	if d < 2*time.Second {
		d = 2 * time.Second
	}
	if d > 6*time.Second {
		d = 6 * time.Second
	}
	return d
}

// icmpAlive 用一个原生 ICMP socket 探测主机，budget 是本次探测的总预算。
func icmpAlive(host string, budget time.Duration) bool {
	start := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, budget)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(start.Add(budget))
	msg := makeICMPEcho(host)
	if _, err = conn.Write(msg); err != nil {
		return false
	}
	recv := make([]byte, 64)
	if _, err = conn.Read(recv); err != nil {
		return false
	}
	return true
}

func logAliveStats(alive []string, opt *Options) {
	if opt == nil || opt.Quiet || !opt.Debug {
		return
	}
	top := opt.DiscoveryTop
	if top <= 0 {
		top = 10
	}
	if len(alive) > 1000 {
		at, al := countTop(alive, top, true)
		for i := 0; i < len(at); i++ {
			gologger.Debug().Msgf("Alive /16: %s => %d", at[i], al[i])
		}
	}
	if len(alive) > 256 {
		at, al := countTop(alive, top, false)
		for i := 0; i < len(at); i++ {
			gologger.Debug().Msgf("Alive /24: %s => %d", at[i], al[i])
		}
	}
}
func countTop(list []string, top int, bSegment bool) (keys []string, vals []int) {
	m := make(map[string]int)
	for _, ip := range list {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue
		}
		var key string
		if bSegment {
			key = parts[0] + "." + parts[1]
		} else {
			key = parts[0] + "." + parts[1] + "." + parts[2]
		}
		m[key]++
	}
	for i := 0; i < top && len(m) > 0; i++ {
		mk := ""
		mv := 0
		for k, v := range m {
			if v > mv {
				mv = v
				mk = k
			}
		}
		if mk == "" {
			break
		}
		keys = append(keys, mk)
		vals = append(vals, mv)
		delete(m, mk)
	}
	return
}
func logHostAlive(host, proto string, opt *Options) {
	printAliveHost(host, proto, opt)
}
func execPing(ip string) bool {
	for _, c := range []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"} {
		if strings.Contains(ip, c) {
			return false
		}
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "ping -n 2 -w 1000 "+ip+" && echo true || echo false")
	case "darwin":
		// macOS -W is a per-reply wait in milliseconds.
		cmd = exec.Command("/bin/bash", "-c", "ping -c 2 -W 1000 "+ip+" && echo true || echo false")
	default:
		cmd = exec.Command("/bin/bash", "-c", "ping -c 2 -W 2 -w 5 "+ip+" && echo true || echo false")
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return false
	}
	if err := cmd.Wait(); err != nil {
		return false
	}
	s := out.String()
	return strings.Contains(s, "true")
}

func makeICMPEcho(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := ident(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = seq(1)
	chk := csum(msg[0:40])
	msg[2] = byte(chk >> 8)
	msg[3] = byte(chk & 255)
	return msg
}

func csum(b []byte) uint16 {
	s := 0
	n := len(b)
	for i := 0; i < n-1; i += 2 {
		s += int(b[i])*256 + int(b[i+1])
	}
	if n%2 == 1 {
		s += int(b[n-1]) * 256
	}
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	return uint16(^s)
}

func seq(v int16) (byte, byte) {
	return byte(v >> 8), byte(v & 255)
}

func ident(host string) (byte, byte) {
	if len(host) >= 2 {
		return host[0], host[1]
	}
	if len(host) == 1 {
		return host[0], 0
	}
	return 0, 0
}

func mergeUnique(a, b []string) []string {
	m := make(map[string]struct{})
	for _, v := range a {
		m[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := m[v]; !ok {
			a = append(a, v)
			m[v] = struct{}{}
		}
	}
	return a
}

func diffHosts(all, found []string) []string {
	m := make(map[string]struct{})
	for _, v := range found {
		m[v] = struct{}{}
	}
	var res []string
	for _, v := range all {
		if _, ok := m[v]; !ok {
			res = append(res, v)
		}
	}
	return res
}
