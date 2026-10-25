package portscan

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// Scanner is the main entry point for port scanning
type Scanner struct {
	options           *Options
	pool              *ants.PoolWithFunc
	mu                sync.Mutex
	consecutiveErrors int32
	// fdErrors 统计因本机 fd/句柄耗尽而失败的探测数，fdWarned 记录是否已就此告警过。
	// 这类失败不是目标行为（既非端口关闭也非丢包），必须与目标侧信号分开处理，
	// 否则会把丢包率、filtered 判定与自适应惩罚一起带偏。详见 handleFDExhausted。
	fdErrors        uint64
	fdWarned        uint32
	currentProgress uint64
	resultsCount    uint64
	adaptiveDelay   int32 // Current delay in milliseconds
	hostStats       sync.Map
	hostSems        sync.Map // host -> chan struct{} (per-target concurrency gate)
	scanPortTotal   uint64

	fingerprinter *Fingerprinter
	grabber       *Grabber
	verifyGrabber *Grabber

	// limiter / hostLimit 限制每秒新发起的探测数（全局与单目标），保护路径上的
	// NAT/conntrack 会话表；congestion 在运行时按观测到的丢包与网关 RTT 动态调整
	// 全局速率。三者都在 Scan 内按本次配置装配，语义见 options.go 与 congestion.go。
	limiter    *rateLimiter
	hostLimit  *hostLimiter
	congestion *congestionController
}

// NewScanner creates a new scanner instance
func NewScanner(opt *Options) (*Scanner, error) {
	if opt == nil {
		opt = DefaultOptions()
	}

	fp, err := NewFingerprinter(opt.FingerprintDir)
	if err != nil {
		if opt.FingerprintDir == "" {
			return nil, err
		}
		// 外置指纹目录不可用时回退到内置指纹集，避免用户自定义文件写错就中断扫描。
		gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan, "fingerprint", fmt.Sprintf("%v", err), "falling back to built-in"))
		if fp, err = NewFingerprinter(""); err != nil {
			return nil, err
		}
	}

	scanner := &Scanner{
		options:       opt,
		fingerprinter: fp,
		grabber:       NewGrabber(fp, opt.Timeout, opt.ServiceProbes),
		// 复核可疑主机时必须拿到证据，因此强制开启主动探针。
		verifyGrabber: NewGrabber(fp, opt.Timeout, true),
	}

	return scanner, nil
}

// Scan starts the scanning process
func (s *Scanner) Scan(ctx context.Context) error {
	normalizedPorts := strings.ToLower(strings.TrimSpace(s.options.Ports))
	stageMajor := normalizedPorts == "full" || normalizedPorts == "all"

	type stagePlan struct {
		label     string
		ports     []int
		s4Chunk   int
		s4Chunks  int
		isS4Chunk bool
	}

	var (
		portIter    *PortIterator
		stagePlans  []stagePlan
		portTotal   int
		stageCursor atomic.Value
	)

	if stageMajor {
		s1, s2, s3Parts, s4 := buildStagePortsWithS3Parts(nil)
		stagePlans = append(stagePlans, stagePlan{label: "S1", ports: s1})
		stagePlans = append(stagePlans, stagePlan{label: "S2", ports: s2})
		for i, part := range s3Parts {
			stagePlans = append(stagePlans, stagePlan{label: fmt.Sprintf("S3-%d", i+1), ports: part})
		}

		s4Chunks := ChunkPorts(s4, s.options.S4ChunkSize)
		for i, chunk := range s4Chunks {
			stagePlans = append(stagePlans, stagePlan{
				label:     "S4",
				ports:     chunk,
				s4Chunk:   i + 1,
				s4Chunks:  len(s4Chunks),
				isS4Chunk: true,
			})
		}
		s3Total := 0
		for _, p := range s3Parts {
			s3Total += len(p)
		}
		portTotal = len(s1) + len(s2) + s3Total + len(s4)
	} else {
		// Parse ports
		var err error
		portIter, err = NewPortIterator(s.options.Ports)
		if err != nil {
			return err
		}
		portTotal = portIter.Total()
	}
	atomic.StoreUint64(&s.scanPortTotal, uint64(portTotal))

	// 阶段边界行默认静默，只有显式打开 StageLog（CLI 的 -debug）时才打印，
	// 常规输出只保留结果行与统一进度条。
	stageLog := s.options.StageLog || s.options.Debug

	// 以下三件事保护的不是本机（那是 fd 预算的事），而是路径：出口设备的
	// NAT/conntrack 会话表和网关的转发能力。并发上限约束不了速率——500 并发在
	// 1ms RTT 的内网里上限是 50 万连接/秒，足以把一台只有几千条表项的路由器打满，
	// 让同网段所有人的新建连接一起失败。
	//
	// 1) 连接速率限制：全局 + 单目标两道闸，按「每秒新发起的探测数」计。
	// 2) 链路探针：扫描前先量一次网关空载 RTT 作基线，扫描期间周期复测。
	// 3) 拥塞控制器：丢包或网关 RTT 抬升时乘性降速，链路恢复后加性升回。
	// 上限为 0（-pcps 0 / -aggressive）表示用户显式要求不限速，不装配任何一环。
	var link *linkProbe
	if s.options.LinkProbe && s.options.ConnectRateLimit > 0 {
		if link = newLinkProbe(); link != nil {
			link.takeBaseline(ctx)
		}
	}
	s.limiter = newRateLimiter(s.options.ConnectRateLimit)
	s.hostLimit = newHostLimiter(s.options.ConnectRateLimitPerHost)
	s.congestion = newCongestionController(ctx, s.limiter, link, s.options.ConnectRateLimit, s.reportCongestion)
	s.congestion.start()
	defer s.congestion.close()

	// Parse hosts (placeholder for now, assuming options.Targets are just IPs)
	hostIter := NewHostIterator(s.options.Targets)

	// Pre-scan Host Discovery. Discovery is only worthwhile for larger target
	// sets (CIDR blocks, big ranges). A small explicit host/IP list is treated as
	// alive (nmap -Pn semantics) so that live hosts whose ICMP/TCP discovery
	// probes are filtered are never dropped. -Pn forces skipping discovery even
	// for large target sets.
	if hostIter.Total() > discoveryMinHosts && !s.options.SkipDiscovery {
		origHosts := hostIter.GetHosts()
		explicit := hostIter.ExplicitHosts()
		discCtx, discStop := signal.NotifyContext(ctx, os.Interrupt)
		discStart := time.Now()
		if stageLog && !s.options.Quiet {
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageHostDiscovery,
				"started",
				fmt.Sprintf("targets=%d", len(origHosts)),
				fmt.Sprintf("method=%s", s.options.DiscoveryMethod),
			))
		}
		aliveHosts, derr := DiscoverAliveHosts(discCtx, s.options, origHosts)
		if derr != nil {
			return derr
		}
		if discCtx.Err() != nil {
			if !s.options.Quiet {
				gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StageHostDiscovery,
					"interrupted", fmt.Sprintf("alive=%d", len(aliveHosts))))
			}
		}
		discStop()

		// 显式点名的目标不因探测沉默被剔除：探测只能证明「活着」，不能证明「死了」——
		// 目标往往只是挡掉了 ICMP 与探测端口。web-probe 对所有原始目标都发探针、从不按
		// 存活结论裁剪，端口扫描这里对齐同一口径；只有 CIDR/range 展开出来的地址才按探测
		// 结论剔除（大网段里沉默地址太多，全量保留会把扫描时间拖成天文数字）。
		kept := make([]string, 0, len(aliveHosts)+len(explicit))
		kept = append(kept, aliveHosts...)
		for _, h := range origHosts {
			if _, ok := explicit[h]; ok {
				kept = append(kept, h)
			}
		}
		hostIter = NewHostIterator(kept)
		down := len(origHosts) - hostIter.Total()

		// 收尾汇总默认可见，与 port-scan 的 completed、web-probe 的资产汇总对齐：
		// 存活行逐条回答「哪台机器活着」，汇总行回答「这批目标整体活了多少」。
		// started / method 这类阶段边界行仍由 StageLog（-debug）控制。
		if !s.options.Quiet && !s.options.LiveStats {
			s.clearProgressLine()
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageHostDiscovery,
				"completed",
				fmt.Sprintf("alive=%d/%d", len(aliveHosts), len(origHosts)),
				time.Since(discStart).Truncate(time.Second).String(),
			))
			// 只有展开出来的地址会被静默移出扫描范围（显式目标恒保留）。「沉默地丢掉目标」
			// 是最容易被误解的失败模式，这里补一行真实剔除数与逃生口，免得用户以为目标真死了。
			if down > 0 {
				gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StageHostDiscovery,
					fmt.Sprintf("down=%d", down),
					"not scanned, use -Pn to scan anyway",
				))
			}
		}
	} else if s.options.OnProgress != nil {
		s.options.OnProgress("host_discovery", "skipped", 0, 0, 0)
	}

	// Shuffle hosts to avoid sequential scanning detection
	hostIter.Shuffle()
	hosts := hostIter.GetHosts()

	total := hostIter.Total() * portTotal
	startTime := time.Now()

	// 并发按本机 fd 上限收敛。默认全局池是 500，但低配机器、Linux 服务器
	// （systemd 默认 1024）和容器（256~1024）的 RLIMIT_NOFILE 往往撑不住：fd 一旦
	// 吃满，连报告、日志、web 监听这些扫描之外的连接也会跟着失败。先尝试把软上限
	// 提到硬上限（nmap 的做法），再按剩余预算把池子收敛到 min(用户值, 预算)。
	// fdScanBudget 返回 0 表示拿不到限制或没有实质限制（Windows 亦然），保持用户配置。
	if raised, ok := raiseFDLimit(); ok && stageLog && !s.options.Quiet {
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan,
			"fd-limit", fmt.Sprintf("raised=%d", raised)))
	}
	rateLimit := s.options.RateLimit
	if budget := fdScanBudget(); budget > 0 && (rateLimit <= 0 || rateLimit > budget) {
		requested := rateLimit
		rateLimit = budget
		if !s.options.Quiet {
			gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
				"fd-limit",
				fmt.Sprintf("probes=%d", budget),
				fmt.Sprintf("concurrency=%d->%d", requested, rateLimit),
				"lowered to fit open-file limit",
			))
		}
	}

	if stageLog && !s.options.Quiet {
		if !s.options.LiveStats {
			// 端口排名数据版本属于内部实现细节，只在对齐调试时打印，避免污染常规输出。
			if isBuiltinPortsSpec(s.options.Ports) {
				gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan,
					"ports", fmt.Sprintf("ranking=%s", getPortRankingVersion())))
			}
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan,
				"started",
				fmt.Sprintf("hosts=%d", hostIter.Total()),
				fmt.Sprintf("ports=%s", s.options.Ports),
			))
		}
	}

	printEnabled := (s.options.Debug || s.options.LiveStats) && !s.options.Quiet && total > 0
	callbackEnabled := s.options.OnProgress != nil && total > 0
	var progressDone chan struct{}
	renderProgress := func(final bool) {
		curr := atomic.LoadUint64(&s.currentProgress)
		if int(curr) > total {
			curr = uint64(total)
		}
		percent := 0
		if total > 0 {
			percent = int(curr) * 100 / total
		}
		if final {
			percent = 100
			curr = uint64(total)
		}
		// 不再按整数百分比去重。刷新本来就只有每秒一次（ticker 驱动），去重只会让
		// 调用方反复重画同一个 finished，而 elapsed 还在增长，算出的速率于是越来越
		// 离谱（实测出现过 `0% 1/65535 0/s`，跨过 1% 才跳到下一帧）。
		if callbackEnabled {
			status := "running"
			if final {
				status = "completed"
			}
			s.options.OnProgress("portscan", status, int(curr), total, percent)
		}
		if !printEnabled {
			return
		}
		// 与漏洞扫描阶段共用同一条渲染口径，形状与字段完全一致。
		suffix := ""
		if s.options.LiveStats {
			if v := stageCursor.Load(); v != nil {
				if cur, ok := v.(string); ok && cur != "" {
					suffix = " " + cur
				}
			}
		}
		line := progress.RenderLine(utils.StagePortScan, percent, int64(curr), int64(total), time.Since(startTime), suffix)
		if line == "" {
			return
		}
		fmt.Fprint(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}

	if printEnabled || callbackEnabled {
		progressDone = make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-progressDone:
					return
				case <-ticker.C:
					renderProgress(false)
				}
			}
		}()
	}

	var wg sync.WaitGroup

	// Use ants for goroutine pooling
	scanCtx, scanStop := signal.NotifyContext(ctx, os.Interrupt)
	pool, err := ants.NewPoolWithFunc(rateLimit, func(i interface{}) {
		defer wg.Done()
		task := i.(scanTask)

		// Check context
		select {
		case <-scanCtx.Done():
			return
		default:
		}

		// Per-target concurrency gate: bound the probes in flight against a
		// single host so the global pool is not concentrated on one target.
		release := s.acquireHostSlot(scanCtx, task.host)
		if release == nil {
			return
		}
		defer release()

		s.scanTarget(scanCtx, task.host, task.port)

		atomic.AddUint64(&s.currentProgress, 1)
	})
	if err != nil {
		return err
	}
	defer pool.Release()
	// 供 handleFDExhausted 在运行时收缩在飞并发（见 shrinkPool）。
	s.pool = pool

	// Iterate and submit tasks
	if stageMajor {
	StageLoop:
		for _, st := range stagePlans {
			select {
			case <-scanCtx.Done():
				break StageLoop
			default:
			}

			if st.isS4Chunk {
				stageCursor.Store(fmt.Sprintf("stage=%s chunk=%d/%d", st.label, st.s4Chunk, st.s4Chunks))
			} else {
				stageCursor.Store(fmt.Sprintf("stage=%s", st.label))
			}

		SubmitLoop:
			for _, host := range hosts {
				select {
				case <-scanCtx.Done():
					break SubmitLoop
				default:
				}

				for _, port := range st.ports {
					select {
					case <-scanCtx.Done():
						break SubmitLoop
					default:
					}

					if s.isHostSuspicious(host) {
						break
					}

					s.maybeAdaptiveDelay()
					if err := s.throttleProbe(scanCtx, host); err != nil {
						break SubmitLoop
					}
					wg.Add(1)
					err := pool.Invoke(scanTask{host: host, port: port})
					if err != nil {
						wg.Done()
						time.Sleep(10 * time.Millisecond)
					}
				}
			}

			wg.Wait()
			if scanCtx.Err() != nil {
				break StageLoop
			}
		}
	} else {
	PortLoop:
		for _, host := range hosts {
			select {
			case <-scanCtx.Done():
				break
			default:
			}

			portIter.Reset()
			for {
				select {
				case <-scanCtx.Done():
					break
				default:
				}

				if s.isHostSuspicious(host) {
					break
				}

				s.maybeAdaptiveDelay()
				port, ok := portIter.Next()
				if !ok {
					break
				}

				if err := s.throttleProbe(scanCtx, host); err != nil {
					break PortLoop
				}

				wg.Add(1)
				err := pool.Invoke(scanTask{host: host, port: port})
				if err != nil {
					wg.Done()
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
	}

	wg.Wait()

	// A host leaves the decision buffer only after enough probes have been made
	// against it. A scan that ends before that would strand those results, so
	// emit whatever is still held before reporting completion.
	s.flushPendingResults()

	if scanCtx.Err() != nil && !s.options.Quiet {
		if printEnabled {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		if v := stageCursor.Load(); v != nil {
			if cur, ok := v.(string); ok && cur != "" {
				gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan, "interrupted", "partial results", cur))
			} else {
				gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan, "interrupted", "partial results"))
			}
		} else {
			gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan, "interrupted", "partial results"))
		}
	}
	scanStop()

	if progressDone != nil {
		// 只 close 不再置 nil：置 nil 是对 progressDone 变量的写，而进度协程正在
		// 读这个变量做 select，会构成数据竞争（-race 可复现）。
		close(progressDone)
	}
	if printEnabled || callbackEnabled {
		renderProgress(true)
		if printEnabled {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
	}
	// 收尾汇总默认可见，与 web-probe 的资产汇总、vuln-scan 的 completed 对齐：
	// 三个阶段的「结果行」之外都留一行结论，用户不用回翻进度条也知道这一阶段扫出了什么。
	// started / 端口排名这类阶段边界行仍由 StageLog（-debug）控制，常规输出只多这一行。
	if !s.options.Quiet && !s.options.LiveStats {
		// 阶段收尾行与进度条同走 stderr，先清行再打印，否则两者会拼在同一行上。
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan,
			"completed",
			fmt.Sprintf("hosts=%d", hostIter.Total()),
			fmt.Sprintf("tasks=%d", total),
			fmt.Sprintf("open=%d", atomic.LoadUint64(&s.resultsCount)),
			time.Since(startTime).Truncate(time.Second).String(),
		))
	}

	return nil
}

// discoveryMinHosts is the minimum number of expanded targets before a host
// discovery phase is performed. Smaller target sets are scanned directly so
// that live hosts whose ICMP/TCP discovery probes are filtered are never
// silently dropped.
const discoveryMinHosts = 8

type scanTask struct {
	host string
	port int
}

func (s *Scanner) isHostSuspicious(host string) bool {
	stAny, ok := s.hostStats.Load(host)
	if !ok {
		return false
	}
	st := stAny.(*hostScanStat)
	return atomic.LoadUint32(&st.mode) == hostModeSuspicious
}

type hostScanStat struct {
	scanned    uint64
	open       uint64
	timeouts   uint64
	srttNs     int64 // smoothed round-trip time in nanoseconds (0 = unknown)
	mode       uint32
	verifying  uint32
	warned     uint32
	mu         sync.Mutex
	verified   map[int]struct{}
	discovered map[int]struct{}
	pending    []*ScanResult
}

func newHostScanStat() *hostScanStat {
	return &hostScanStat{
		verified:   make(map[int]struct{}),
		discovered: make(map[int]struct{}),
		pending:    make([]*ScanResult, 0, 64),
	}
}

const (
	hostModeUndecided  uint32 = 0
	hostModeNormal     uint32 = 1
	hostModeSuspicious uint32 = 2
	hostModeDeciding   uint32 = 3
)

// verbose 表示是否打开诊断级输出。portscan 自身的进度条与阶段边界行由 Debug /
// LiveStats 控制，而 CLI 端统一把 -debug 映射到 StageLog（见 runner/engine.go，
// psOpts.Debug 恒为 false），所以两者任一为真都算诊断模式。
func (s *Scanner) verbose() bool {
	return s != nil && s.options != nil && (s.options.Debug || s.options.StageLog)
}

// clearProgressLine 清掉进度条残留的半行。进度条用 \r 原地重绘、结尾不换行，光标停在
// 行尾，直接打印运维行就会叠在进度条上面。CLI 端的进度条由 main.go 渲染，所以这里不能
// 只看 portscan 自己的开关：Quiet 之外一律清一次。Quiet（-silent / SDK）下不渲染任何
// 进度条，清行序列反而会被旧终端渲染成乱码。
func (s *Scanner) clearProgressLine() {
	if s == nil || s.options == nil || s.options.Quiet {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[2K\r")
}

// poolShrinkFloor 是收缩全局池时的地板。fd 耗尽说明本机资源紧张，但把并发压到个位数
// 只会让扫描退化成不可用，所以收缩到底也保住这个量级。
const poolShrinkFloor = 16

// handleFDExhausted 处理「本机 fd/句柄耗尽」这一类失败。它不是目标行为，所以既不进
// st.timeouts（会把丢包率算高、误报 filtered），也不累加 consecutiveErrors（会触发与
// 目标无关的降速）。首次触发时告警一次并收缩在飞并发，让系统把 fd 还回来。
func (s *Scanner) handleFDExhausted() {
	atomic.AddUint64(&s.fdErrors, 1)
	if !atomic.CompareAndSwapUint32(&s.fdWarned, 0, 1) {
		return
	}
	if !s.options.Quiet {
		s.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
			"fd-exhausted",
			fmt.Sprintf("failed=%d", atomic.LoadUint64(&s.fdErrors)),
			fdAdvice(),
		))
	}
	s.shrinkPool()
}

// shrinkPool 尽最大努力把全局池减半，减少同时在飞的连接数。只在 fd 耗尽时调用一次
// （由 fdWarned 保证），且钳到地板。ants 的 Tune 不接受 0（0 表示无上限），所以必须
// 先钳到 poolShrinkFloor 再传。
func (s *Scanner) shrinkPool() {
	p := s.pool
	if p == nil {
		return
	}
	size := p.Cap()
	if size <= poolShrinkFloor {
		return
	}
	next := size / 2
	if next < poolShrinkFloor {
		next = poolShrinkFloor
	}
	p.Tune(next)
}

// throttleProbe 在提交一个探测前等够限速器要求的间隔。全局闸门与单目标闸门串行
// 通过；两道都不限速时只是两次原子读，没有额外开销。返回非 nil 表示 ctx 已结束。
//
// 这里阻塞的是唯一的提交协程，所以「睡够间隔」本身就是限速手段，池里的 worker 不受影响。
func (s *Scanner) throttleProbe(ctx context.Context, host string) error {
	if s.limiter != nil {
		if err := s.limiter.wait(ctx); err != nil {
			return err
		}
	}
	return s.hostLimit.wait(ctx, host)
}

// reportCongestion 渲染拥塞控制器发出的降速/恢复告警。自动降速必须显式可见：用户
// 看到扫描变慢时需要知道这是我们主动收手保护链路，而不是工具出了问题或目标变慢。
func (s *Scanner) reportCongestion(ev congestionEvent) {
	if s.options == nil || s.options.Quiet {
		return
	}
	s.clearProgressLine()
	if ev.Recovered {
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan,
			"recovered",
			fmt.Sprintf("rate=%d->%d", ev.OldRate, ev.NewRate),
			"link healthy again",
		))
		return
	}
	facts := []string{
		fmt.Sprintf("rate=%d->%d", ev.OldRate, ev.NewRate),
		fmt.Sprintf("no-reply=%d%%", ev.LossPct),
	}
	if ev.BaselineRT > 0 {
		facts = append(facts,
			fmt.Sprintf("gw-rtt=%s", ev.LinkRTT.Truncate(time.Millisecond)),
			fmt.Sprintf("baseline=%s", ev.BaselineRT.Truncate(time.Millisecond)),
		)
	}
	if ev.Reason == "link-rtt" {
		facts = append(facts, "local link congested, easing off to protect it")
	} else {
		facts = append(facts, "probes unanswered, easing off to protect the local network")
	}
	facts = append(facts, "-pcps 0 disables")
	gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
		append([]string{"throttled"}, facts...)...))
}

// maybeAdaptiveDelay 是针对「目标在限我们的速」的逐探测退避。注意它只统计硬错误：
// 超时不算，因为被防火墙 drop 的端口本来就不回包，把它当错误会让每个提交都睡满
// 1s，扫描直接废掉。链路层面的持续丢包由 congestionController 统一收敛（它有窗口
// 统计，不会因为一个被过滤的目标就误判），两者职责不重叠。
func (s *Scanner) maybeAdaptiveDelay() {
	errCount := atomic.LoadInt32(&s.consecutiveErrors)
	currentDelay := atomic.LoadInt32(&s.adaptiveDelay)

	if errCount > 20 {
		newDelay := currentDelay + 100
		if newDelay > 1000 {
			newDelay = 1000
		}
		atomic.StoreInt32(&s.adaptiveDelay, newDelay)

		if s.verbose() && errCount%10 == 0 {
			s.clearProgressLine()
			gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
				"throttled",
				fmt.Sprintf("errors=%d", errCount),
				fmt.Sprintf("delay=%dms", newDelay),
			))
		}
		time.Sleep(time.Duration(newDelay) * time.Millisecond)
		return
	}

	if errCount > 5 {
		atomic.CompareAndSwapInt32(&s.adaptiveDelay, 0, 10)
		time.Sleep(time.Duration(atomic.LoadInt32(&s.adaptiveDelay)) * time.Millisecond)
		return
	}

	if currentDelay > 0 && atomic.LoadUint64(&s.currentProgress)%50 == 0 {
		atomic.AddInt32(&s.adaptiveDelay, -10)
		if atomic.LoadInt32(&s.adaptiveDelay) < 0 {
			atomic.StoreInt32(&s.adaptiveDelay, 0)
		}
	}
}

// acquireHostSlot bounds how many probes are in flight against a single
// target. Concentrating the whole global pool on one host can trip its
// SYN-flood protection and make live ports look closed. It returns a release
// function, or nil if the context was cancelled before a slot was free.
func (s *Scanner) acquireHostSlot(ctx context.Context, host string) func() {
	limit := s.options.MaxHostConcurrency
	if limit <= 0 {
		return func() {}
	}
	v, ok := s.hostSems.Load(host)
	if !ok {
		actual, _ := s.hostSems.LoadOrStore(host, make(chan struct{}, limit))
		v = actual
	}
	sem := v.(chan struct{})
	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
		return nil
	}
}

// attemptTimeoutFor scales the connect timeout with the round trip time
// measured for this host. A fast host does not need a full second of patience,
// so shortening the first attempt speeds up large scans; a slow host keeps
// enough headroom that its open ports are not mistaken for closed. Retries
// always use the full user budget (see checkPortOpen).
func (s *Scanner) attemptTimeoutFor(st *hostScanStat, base time.Duration) time.Duration {
	if !s.options.AdaptiveTimeout {
		return base
	}
	srtt := atomic.LoadInt64(&st.srttNs)
	if srtt <= 0 {
		return base
	}
	t := time.Duration(srtt) * 4
	const floor = 200 * time.Millisecond
	if t < floor {
		t = floor
	}
	if t > base {
		t = base
	}
	return t
}

// observeRTT folds a measured round trip into the host's smoothed RTT
// estimate (EWMA, alpha = 1/8). Only non-timeout outcomes are recorded so a
// dropped probe does not inflate the estimate and slow later attempts.
func (s *Scanner) observeRTT(st *hostScanStat, d time.Duration) {
	if !s.options.AdaptiveTimeout || d <= 0 {
		return
	}
	ns := d.Nanoseconds()
	for {
		cur := atomic.LoadInt64(&st.srttNs)
		var next int64
		if cur == 0 {
			next = ns
		} else {
			next = cur - cur/8 + ns/8
		}
		if atomic.CompareAndSwapInt64(&st.srttNs, cur, next) {
			return
		}
	}
}

// checkPortOpen attempts to establish a connection to the target
// It handles proxy, timeout, and retries.
// Returns the open connection (if successful) or error.
// Caller is responsible for closing the connection.
func (s *Scanner) checkPortOpen(st *hostScanStat, host string, port int) (net.Conn, error) {
	// net.JoinHostPort brackets IPv6 literals; fmt.Sprintf("%s:%d") does not
	// and produces an address net.Dial cannot parse.
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var err error

	for i := 0; i <= s.options.Retries; i++ {
		// First attempt uses the RTT-adaptive budget; retries use the full user
		// budget and escalate, since a first-attempt timeout is often just
		// congestion/loss and giving the retry more time recovers slow or
		// rate-limited hosts instead of marking the port closed.
		attemptTimeout := s.options.Timeout
		if i == 0 {
			attemptTimeout = s.attemptTimeoutFor(st, s.options.Timeout)
		} else {
			attemptTimeout = s.options.Timeout + time.Duration(i)*s.options.Timeout/2
		}
		start := time.Now()
		conn, err = net.DialTimeout("tcp", address, attemptTimeout)

		if err == nil {
			s.observeRTT(st, time.Since(start))
			return conn, nil
		}

		// A "refused" reply also measured a real round trip; a timeout did not.
		isTimeout := false
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			isTimeout = true
		}
		if !isTimeout {
			s.observeRTT(st, time.Since(start))
		}

		// Retry logic
		if isConnRefused(err) {
			return nil, err // Connection refused usually means host is up but port closed
		}

		if i < s.options.Retries {
			time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
		}
	}
	return nil, err
}

func (s *Scanner) scanTarget(ctx context.Context, host string, port int) {
	stAny, _ := s.hostStats.LoadOrStore(host, newHostScanStat())
	st := stAny.(*hostScanStat)
	if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
		return
	}

	// 1. Check if port is open using shared logic
	conn, err := s.checkPortOpen(st, host, port)

	if err != nil {
		// 本机 fd/句柄耗尽不是目标的信号：它既不说明端口开着，也不说明被防火墙丢弃。
		// 若落入 default 分支，会同时污染 st.timeouts（误报 filtered）和
		// consecutiveErrors（触发与目标无关的降速），所以这里单独处理并直接返回，
		// 不进入按目标统计与启发式判定。
		if isFDExhausted(err) {
			s.handleFDExhausted()
			return
		}
		scanned := atomic.AddUint64(&st.scanned, 1)
		isTimeout := false
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			isTimeout = true
		}
		switch {
		case isTimeout:
			// A timeout usually means the port is filtered (packet dropped by a
			// firewall) rather than closed; treat it as a distinct signal and
			// never let it be mistaken for a hard error.
			atomic.AddUint64(&st.timeouts, 1)
			atomic.StoreInt32(&s.consecutiveErrors, 0)
			// 拥塞控制器看的正是这一路信号：回包与否按窗口统计，一个被过滤的目标
			// 只能把窗口丢包率推高，是否降速由控制器按阈值决定（见 congestion.go）。
			s.congestion.observe(false)
		case isConnRefused(err):
			// 收到 RST 说明对端回了话，路径是通的。
			atomic.StoreInt32(&s.consecutiveErrors, 0)
			s.congestion.observe(true)
		default:
			atomic.AddInt32(&s.consecutiveErrors, 1)
			s.congestion.observe(false)
		}
		s.maybeDecideHost(ctx, host, st, scanned)
		s.maybeWarnFiltered(host, st, scanned)
		return
	}

	// Connection successful
	atomic.StoreInt32(&s.consecutiveErrors, 0)
	s.congestion.observe(true)
	defer conn.Close()

	scanned := atomic.AddUint64(&st.scanned, 1)
	atomic.AddUint64(&st.open, 1)

	st.mu.Lock()
	st.discovered[port] = struct{}{}
	st.mu.Unlock()

	s.maybeDecideHost(ctx, host, st, scanned)
	if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
		return
	}

	// 连接还握在手里，直接复用它做被动 banner 抓取与指纹识别，不产生额外连接。
	res := &ScanResult{
		Host:        host,
		Port:        port,
		State:       PortStateOpen,
		ServiceInfo: *s.grabber.Grab(conn, host, port),
	}

	if s.shouldBufferHost(st) {
		st.mu.Lock()
		mode := atomic.LoadUint32(&st.mode)
		if (mode == hostModeUndecided || mode == hostModeDeciding) && len(st.pending) < 2048 {
			st.pending = append(st.pending, res)
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()
		if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
			return
		}
	}

	s.emitResult(res)
}

func (s *Scanner) shouldBufferHost(st *hostScanStat) bool {
	if !s.hostHeuristicsEnabled() {
		return false
	}
	mode := atomic.LoadUint32(&st.mode)
	return mode == hostModeUndecided || mode == hostModeDeciding
}

// heuristicsMinPorts is the smallest per-host port count at which the
// buffer/decide/warn heuristics are worth running. They only resolve after a
// few hundred probes against a host, so a handful of ports would add jitter
// for nothing. The default `top` scan (600 ports) sits comfortably above it.
//
// The predecessor of this gate only enabled the heuristics for `full` scans,
// which silently turned them off for the default scan — a host dropping most
// probes (packet filter / rate limiter) then got no `filtered` warning at all,
// and its incomplete result set was easy to mistake for a scanner bug.
const heuristicsMinPorts = 500

func (s *Scanner) hostHeuristicsEnabled() bool {
	return atomic.LoadUint64(&s.scanPortTotal) >= heuristicsMinPorts
}

// flushPendingResults emits every result still held in a host's decision buffer
// and marks that host decided. Results are only buffered while a host is
// undecided, so this is a no-op for hosts that were already resolved (their
// buffer is empty) and for hosts flagged as suspicious (their buffer was
// dropped and re-verified instead).
func (s *Scanner) flushPendingResults() {
	s.hostStats.Range(func(_, v any) bool {
		st, ok := v.(*hostScanStat)
		if !ok || st == nil {
			return true
		}
		st.mu.Lock()
		pending := st.pending
		st.pending = nil
		atomic.StoreUint32(&st.mode, hostModeNormal)
		st.mu.Unlock()
		for _, res := range pending {
			s.emitResult(res)
		}
		return true
	})
}

func (s *Scanner) maybeDecideHost(ctx context.Context, host string, st *hostScanStat, scanned uint64) {
	if !s.hostHeuristicsEnabled() {
		return
	}
	if scanned < 50 {
		return
	}
	mode := atomic.LoadUint32(&st.mode)
	if mode != hostModeUndecided && mode != hostModeDeciding {
		return
	}
	if !atomic.CompareAndSwapUint32(&st.mode, hostModeUndecided, hostModeDeciding) && atomic.LoadUint32(&st.mode) != hostModeDeciding {
		return
	}

	open := atomic.LoadUint64(&st.open)
	openRate := float64(open) / float64(scanned)
	if openRate >= 0.98 {
		// Everything answers: almost certainly a security device/proxy instead of
		// real listeners. Keep the state so ports already discovered are still
		// verified below (verifyAndEmit also re-checks every discovered port),
		// instead of silently dropping them. Buffered results are dropped here to
		// release the banners they hold.
		st.mu.Lock()
		atomic.StoreUint32(&st.mode, hostModeSuspicious)
		st.pending = nil
		st.mu.Unlock()
		// 与 filtered 同理：这是排查阶段的诊断，默认不打扰终端，-debug 才显示。
		if s.verbose() {
			s.clearProgressLine()
			gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
				"suspected",
				fmt.Sprintf("host=%s", host),
				fmt.Sprintf("open-rate=%.2f%%", openRate*100),
				fmt.Sprintf("probes=%d/%d", open, scanned),
				"verify-only",
			))
		}
		if atomic.CompareAndSwapUint32(&st.verifying, 0, 1) {
			go s.verifyAndEmit(ctx, host, st)
		}
		return
	}

	if openRate > 0.90 && scanned < 200 {
		atomic.StoreUint32(&st.mode, hostModeUndecided)
		return
	}
	if openRate > 0.95 && scanned < 500 {
		atomic.StoreUint32(&st.mode, hostModeUndecided)
		return
	}

	var pending []*ScanResult
	st.mu.Lock()
	if len(st.pending) > 0 {
		pending = append(pending, st.pending...)
		st.pending = st.pending[:0]
	}
	atomic.StoreUint32(&st.mode, hostModeNormal)
	st.mu.Unlock()
	for _, res := range pending {
		s.emitResult(res)
	}
}

// maybeWarnFiltered surfaces (once per host, full-port scans only) the case
// where a host drops almost every probe. That normally means a packet-filtering
// firewall, and the result set for such a host may be incomplete. It never
// discards data; it only makes the condition visible instead of silently
// reporting every port as closed.
func (s *Scanner) maybeWarnFiltered(host string, st *hostScanStat, scanned uint64) {
	if !s.hostHeuristicsEnabled() {
		return
	}
	if scanned < 200 {
		return
	}
	if atomic.LoadUint32(&st.warned) == 1 {
		return
	}
	// 0.80 rather than a stricter 0.95: a rate-limited or partially-filtering
	// host usually drops a fraction (not almost all) of the probes, so a very
	// high bar silently hides exactly the case this warning exists for.
	timeouts := atomic.LoadUint64(&st.timeouts)
	if float64(timeouts)/float64(scanned) < 0.80 {
		return
	}
	if !atomic.CompareAndSwapUint32(&st.warned, 0, 1) {
		return
	}
	// 这是诊断信息（排查「结果为何不完整」时才需要），不是扫描结果，默认不打扰
	// 终端；-debug 才显示，并先清掉进度条所在行。
	if s.verbose() {
		s.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StagePortScan,
			"filtered",
			fmt.Sprintf("host=%s", host),
			fmt.Sprintf("drop-rate=%.2f%%", float64(timeouts)/float64(scanned)*100),
			fmt.Sprintf("probes=%d/%d", timeouts, scanned),
			"results may be incomplete",
		))
	}
}

func (s *Scanner) emitResult(res *ScanResult) {
	atomic.AddUint64(&s.resultsCount, 1)

	if s.options.OnResult != nil {
		if s.options.Debug && !s.options.Quiet {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		s.options.OnResult(res)
	}
}

func (s *Scanner) verifyAndEmit(ctx context.Context, host string, st *hostScanStat) {
	// Verify the common-ports baseline plus every port already discovered as
	// open, so a host that answers everything (proxy/firewall) does not lose the
	// real services we already found.
	base := []int{80, 443, 22, 21, 25, 110, 143, 445, 3389, 135, 139, 3306, 5432, 6379, 27017, 8080, 8443, 8000, 8888, 9200}
	seen := make(map[int]struct{}, len(base)+16)
	ports := make([]int, 0, len(base)+16)
	for _, p := range base {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	st.mu.Lock()
	for p := range st.discovered {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	st.mu.Unlock()

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ok, info := s.verifyPort(ctx, host, port)
		if !ok {
			continue
		}

		st.mu.Lock()
		if _, exists := st.verified[port]; exists {
			st.mu.Unlock()
			continue
		}
		st.verified[port] = struct{}{}
		st.mu.Unlock()

		s.emitResult(&ScanResult{
			Host:        host,
			Port:        port,
			State:       PortStateOpen,
			ServiceInfo: *info,
		})
	}
}

// verifyPort 复核可疑主机上的单个端口。可疑主机的典型特征是「每个端口都能连上」，
// 所以只连上不算数，必须真的收到服务端数据（banner 或规则命中）才认定为真实服务。
func (s *Scanner) verifyPort(ctx context.Context, host string, port int) (bool, *ServiceInfo) {
	timeout := 800 * time.Millisecond
	if s.options.Timeout > 0 && s.options.Timeout < timeout {
		timeout = s.options.Timeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	// 复核路径必须拿到证据，因此固定使用带主动探针的抓取器。
	info := s.verifyGrabber.Grab(conn, host, port)
	if info.Banner == "" && info.Confidence < ConfidenceProbable {
		return false, nil
	}
	return true, info
}
