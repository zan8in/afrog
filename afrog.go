package afrog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"

	"github.com/zan8in/afrog/v3/pkg/catalog"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/curated/service"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pocs"
)

// SDKScanner SDK版本的扫描器，专为库调用优化
type SDKScanner struct {
	// runner 内部扫描引擎实例
	runner *runner.Runner

	// results 存储所有扫描结果
	results []*result.Result

	// mu 用于保护results的并发访问
	mu sync.Mutex

	openPortsMu sync.Mutex
	openPorts   map[string]map[int]struct{}

	// options 存储扫描配置选项
	options *config.Options

	// sdkOpts 保存原始SDK配置选项
	sdkOpts *SDKOptions

	// 实时结果回调（同步版本）
	OnResult func(*result.Result)

	OnPort func(host string, port int)

	OnWebProbe func(r WebProbeResult)

	// 实时结果通道（流式版本）
	ResultChan chan *result.Result

	PortChan chan PortScanResult

	HostChan chan HostDiscoveryResult

	WebProbeChan chan WebProbeResult

	PhaseProgressChan chan PhaseProgress

	ScanInfoChan chan ScanInfoUpdate

	closeChansOnce sync.Once

	runStartOnce sync.Once
	runDoneOnce  sync.Once
	runStarted   chan struct{}
	runDone      chan struct{}

	// 控制流式输出的context
	ctx    context.Context
	cancel context.CancelFunc

	// 扫描统计信息
	stats *ScanStats

	phaseMu sync.Mutex
	phases  map[string]PhaseProgress

	lastVulnPhasePercent int32
}

// ScanStats 扫描统计信息
type ScanStats struct {
	StartTime      time.Time
	EndTime        time.Time
	TotalTargets   int
	TotalPocs      int
	TotalScans     int
	CompletedScans int32
	FoundVulns     int32
}

type PortScanResult struct {
	Host string
	Port int
}

type HostDiscoveryResult struct {
	Host string
}

type WebProbeResult struct {
	URL       string
	Title     string
	Server    string
	PoweredBy string
}

type PhaseProgress struct {
	Phase    string
	Status   string
	Finished int64
	Total    int64
	Percent  int
}

type ScanInfoUpdate struct {
	TotalTargets int
	Targets      []string
	TotalPocs    int
	TotalScans   int
	OOBEnabled   bool
	OOBStatus    string
}

// SDKOptions SDK扫描配置选项（优化版）
type SDKOptions struct {
	// ========== 目标配置 ==========
	Targets     []string // 扫描目标列表
	TargetsFile string   // 目标文件路径

	// ========== POC配置 ==========
	PocFile         string   // POC文件或目录路径（必须）
	AppendPoc       []string // 附加POC文件或目录路径
	Search          string   // POC搜索关键词
	Severity        string   // 严重程度过滤
	ExcludePocs     []string
	ExcludePocsFile string

	// ========== 性能配置 ==========
	RateLimit                      int // 请求速率限制 (默认: 150)
	ReqLimitPerTarget              int
	AutoReqLimit                   bool
	Polite                         bool
	Balanced                       bool
	Aggressive                     bool
	Concurrency                    int // 并发数 (默认: 25)
	Retries                        int // 重试次数 (默认: 1)
	Timeout                        int // 超时时间秒 (默认: 10)
	MaxHostError                   int // 主机最大错误数 (默认: 3)
	Smart                          bool
	DisableFingerprint             bool
	EnableWebProbe                 bool
	FingerprintFilterMode          string
	MaxRespBodySize                int
	BruteMaxRequests               int
	DefaultAccept                  bool
	VulnerabilityScannerBreakpoint bool

	PortScan        bool
	PSPorts         string
	PSRateLimit     int
	PSTimeout       int
	PSRetries       int
	PSSkipDiscovery bool
	PSS4Chunk       int

	// ========== 网络配置 ==========
	Proxy   string // HTTP/SOCKS5代理
	Headers []string

	// ========== OOB配置 ==========
	EnableOOB      bool   // 是否启用OOB检测 (默认: false)
	OOB            string // OOB适配器类型: ceyeio, dnslogcn, alphalog, xray, revsuit
	OOBKey         string // OOB API密钥
	OOBDomain      string // OOB域名
	OOBApiUrl      string // OOB API地址
	OOBHttpUrl     string // OOB HTTP地址
	OOBRateLimit   int
	OOBConcurrency int

	// ========== 输出配置 ==========
	EnableStream bool // 启用流式输出

	Dingtalk bool
	Wecom    bool

	CuratedEnabled     string
	CuratedEndpoint    string
	CuratedTimeout     int
	CuratedForceUpdate bool
}

// NewSDKOptions 创建默认配置
func NewSDKOptions() *SDKOptions {
	return &SDKOptions{
		RateLimit:             150,
		Concurrency:           25,
		Retries:               1,
		Timeout:               50,
		MaxHostError:          3,
		MaxRespBodySize:       2,
		BruteMaxRequests:      5000,
		DefaultAccept:         true,
		FingerprintFilterMode: "strict",
		PSPorts:               "top",
		PSS4Chunk:             1000,
		OOBRateLimit:          25,
		OOBConcurrency:        25,
	}
}

// NewSDKScanner 创建SDK扫描器实例
func NewSDKScanner(opts *SDKOptions) (*SDKScanner, error) {
	if opts == nil {
		opts = NewSDKOptions()
	}

	// 转换为内部配置
	options := convertSDKOptions(opts)

	// 强制SDK模式设置
	options.Silent = true
	options.DisableUpdateCheck = true
	options.DisableOutputHtml = true
	options.SDKMode = true
	options.EnableOOB = opts.EnableOOB

	// 禁用所有文件输出
	options.Json = ""
	options.JsonAll = ""
	options.Output = ""

	// 使用空配置，避免读取配置文件
	// SDK 模式下，尝试读取默认配置文件以获取 OOB 配置
	cfg, err := config.NewConfig("")
	if err != nil {
		// 如果读取失败，则使用空配置
		cfg = &config.Config{}
	}
	options.Config = cfg

	if v := strings.TrimSpace(opts.CuratedEnabled); v != "" {
		options.Config.Curated.Enabled = v
	}
	if v := strings.TrimSpace(opts.CuratedEndpoint); v != "" {
		options.Config.Curated.Endpoint = v
	}
	if opts.CuratedTimeout > 0 {
		options.Config.Curated.TimeoutSec = opts.CuratedTimeout
	}
	options.CuratedForceUpdate = opts.CuratedForceUpdate
	if err := applyCuratedMount(options); err != nil {
		return nil, err
	}

	// 设置OOB配置（只有启用OOB且配置了OOB适配器才设置）
	if opts.EnableOOB && opts.OOB != "" {
		options.OOB = opts.OOB
		options.OOBKey = opts.OOBKey
		options.OOBDomain = opts.OOBDomain
		options.OOBApiUrl = opts.OOBApiUrl
		options.OOBHttpUrl = opts.OOBHttpUrl

		// 如果 SDK 选项中未提供 OOB 配置，尝试从配置文件中读取
		if options.OOBKey == "" && options.OOBDomain == "" && options.OOBApiUrl == "" && options.OOBHttpUrl == "" {
			switch options.OOB {
			case "ceyeio":
				options.OOBKey = cfg.Reverse.Ceye.ApiKey
				options.OOBDomain = cfg.Reverse.Ceye.Domain
			case "dnslogcn":
				options.OOBDomain = cfg.Reverse.Dnslogcn.Domain
			case "alphalog":
				options.OOBDomain = cfg.Reverse.Alphalog.Domain
				options.OOBApiUrl = cfg.Reverse.Alphalog.ApiUrl
			case "xray":
				options.OOBKey = cfg.Reverse.Xray.XToken
				options.OOBDomain = cfg.Reverse.Xray.Domain
				options.OOBApiUrl = cfg.Reverse.Xray.ApiUrl
			case "revsuit":
				options.OOBKey = cfg.Reverse.Revsuit.Token
				options.OOBDomain = cfg.Reverse.Revsuit.DnsDomain
				options.OOBApiUrl = cfg.Reverse.Revsuit.ApiUrl
				options.OOBHttpUrl = cfg.Reverse.Revsuit.HttpUrl
			}
		}

		if options.OOB == "dnslogcn" && options.OOBDomain == "" {
			options.OOBDomain = "dnslog.cn"
		}
	}

	// 验证配置
	if err := validateSDKConfig(options); err != nil {
		return nil, err
	}

	// 创建runner
	r, err := createSDKRunner(options)
	if err != nil {
		return nil, fmt.Errorf("创建扫描引擎失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	scanner := &SDKScanner{
		runner:     r,
		results:    make([]*result.Result, 0),
		options:    options,
		sdkOpts:    opts,
		ctx:        ctx,
		cancel:     cancel,
		openPorts:  make(map[string]map[int]struct{}),
		runStarted: make(chan struct{}),
		runDone:    make(chan struct{}),
		stats: &ScanStats{
			StartTime: time.Now(),
		},
		phases: make(map[string]PhaseProgress),
	}
	atomic.StoreInt32(&scanner.lastVulnPhasePercent, -1)

	options.OnPortScanResult = func(host string, port int) {
		scanner.openPortsMu.Lock()
		pm, ok := scanner.openPorts[host]
		if !ok {
			pm = make(map[int]struct{})
			scanner.openPorts[host] = pm
		}
		pm[port] = struct{}{}
		scanner.openPortsMu.Unlock()

		if scanner.PortChan != nil {
			ch := scanner.PortChan
			func() {
				defer func() { _ = recover() }()
				select {
				case ch <- PortScanResult{Host: host, Port: port}:
				case <-scanner.ctx.Done():
					return
				default:
				}
			}()
		}

		if scanner.OnPort != nil {
			scanner.OnPort(host, port)
		}
	}

	options.OnHostDiscovered = func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if scanner.HostChan != nil {
			ch := scanner.HostChan
			func() {
				defer func() { _ = recover() }()
				select {
				case ch <- HostDiscoveryResult{Host: host}:
				case <-scanner.ctx.Done():
					return
				default:
				}
			}()
		}
	}

	scanner.runner.OnWebProbe = func(meta runner.WebMeta) {
		if scanner.WebProbeChan == nil && scanner.OnWebProbe == nil {
			return
		}
		r := WebProbeResult{
			URL:       strings.TrimSpace(meta.URL),
			Title:     strings.TrimSpace(meta.Title),
			Server:    strings.TrimSpace(meta.Server),
			PoweredBy: strings.TrimSpace(meta.PoweredBy),
		}
		if scanner.WebProbeChan != nil {
			ch := scanner.WebProbeChan
			func() {
				defer func() { _ = recover() }()
				select {
				case ch <- r:
				case <-scanner.ctx.Done():
					return
				default:
				}
			}()
		}
		if scanner.OnWebProbe != nil {
			scanner.OnWebProbe(r)
		}
	}

	// 如果启用流式输出，创建结果通道
	if opts.EnableStream {
		scanner.ResultChan = make(chan *result.Result, 100)
		scanner.PhaseProgressChan = make(chan PhaseProgress, 64)
		scanner.ScanInfoChan = make(chan ScanInfoUpdate, 16)
	}

	if opts.PortScan {
		scanner.PortChan = make(chan PortScanResult, 100)
		scanner.HostChan = make(chan HostDiscoveryResult, 256)
	}

	if opts.EnableWebProbe {
		scanner.WebProbeChan = make(chan WebProbeResult, 100)
	}

	options.OnPhaseProgress = func(phase string, status string, finished int64, total int64, percent int) {
		phase = strings.ToLower(strings.TrimSpace(phase))
		if phase == "" {
			return
		}
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		pp := PhaseProgress{
			Phase:    phase,
			Status:   strings.ToLower(strings.TrimSpace(status)),
			Finished: finished,
			Total:    total,
			Percent:  percent,
		}
		scanner.phaseMu.Lock()
		scanner.phases[phase] = pp
		scanner.phaseMu.Unlock()
		if scanner.PhaseProgressChan != nil {
			ch := scanner.PhaseProgressChan
			func() {
				defer func() { _ = recover() }()
				select {
				case ch <- pp:
				case <-scanner.ctx.Done():
					return
				default:
				}
			}()
		}
	}

	options.OnScanInfoUpdate = func(info config.ScanInfoUpdate) {
		scanner.stats.TotalTargets = info.TotalTargets
		scanner.stats.TotalPocs = info.TotalPocs
		scanner.stats.TotalScans = info.TotalScans
		if scanner.ScanInfoChan != nil {
			ch := scanner.ScanInfoChan
			up := ScanInfoUpdate{
				TotalTargets: info.TotalTargets,
				Targets:      append([]string(nil), info.Targets...),
				TotalPocs:    info.TotalPocs,
				TotalScans:   info.TotalScans,
				OOBEnabled:   info.OOBEnabled,
				OOBStatus:    info.OOBStatus,
			}
			func() {
				defer func() { _ = recover() }()
				select {
				case ch <- up:
				case <-scanner.ctx.Done():
					return
				default:
				}
			}()
		}
	}

	// 计算扫描统计
	pocSlice := options.CreatePocList()
	fingerprintPocs, pocSlice := options.FingerprintPoCs(pocSlice)

	allTargets := make([]string, 0, options.Targets.Len())
	for _, t := range options.Targets.List() {
		s, ok := t.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		allTargets = append(allTargets, s)
	}
	idx := targets.BuildTargetIndex(allTargets)
	netTargets := idx.NetTargets()

	isNetOnlyPoc := func(p poc.Poc) bool {
		hasHTTP := false
		hasNet := false
		hasGo := false
		for _, rm := range p.Rules {
			t := strings.ToLower(strings.TrimSpace(rm.Value.Request.Type))
			switch t {
			case "", poc.HTTP_Type, poc.HTTPS_Type:
				hasHTTP = true
			case poc.TCP_Type, poc.UDP_Type, poc.SSL_Type:
				hasNet = true
			case poc.GO_Type:
				hasGo = true
			default:
				hasHTTP = true
			}
		}
		if hasGo {
			return false
		}
		return hasNet && !hasHTTP
	}

	taskCount := 0
	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		taskCount += len(fingerprintPocs) * len(allTargets)
	}
	for _, p := range pocSlice {
		if !isNetOnlyPoc(p) {
			taskCount += len(allTargets)
		} else {
			taskCount += len(netTargets)
		}
	}

	pocTotal := len(pocSlice)
	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		pocTotal += len(fingerprintPocs)
	}

	scanner.stats.TotalTargets = len(allTargets)
	scanner.stats.TotalPocs = pocTotal
	scanner.stats.TotalScans = taskCount

	return scanner, nil
}

// Run 执行扫描（同步版本）
func (s *SDKScanner) Run() error {
	// 在扫描开始前输出基本信息
	s.printScanInfo()
	err := s.run()
	s.closeChans()
	return err
}

// RunAsync 执行扫描（异步版本）
func (s *SDKScanner) RunAsync() error {
	go func() {
		// 在扫描开始前输出基本信息
		s.printScanInfo()
		s.run()
		s.closeChans()
	}()
	return nil
}

func (s *SDKScanner) closeChans() {
	s.closeChansOnce.Do(func() {
		if s.ResultChan != nil {
			close(s.ResultChan)
		}
		if s.PortChan != nil {
			close(s.PortChan)
		}
		if s.HostChan != nil {
			close(s.HostChan)
		}
		if s.WebProbeChan != nil {
			close(s.WebProbeChan)
		}
		if s.PhaseProgressChan != nil {
			close(s.PhaseProgressChan)
		}
		if s.ScanInfoChan != nil {
			close(s.ScanInfoChan)
		}
	})
}

// run 内部扫描执行
func (s *SDKScanner) run() error {
	s.runStartOnce.Do(func() {
		close(s.runStarted)
	})
	defer s.runDoneOnce.Do(func() {
		close(s.runDone)
	})

	// 设置结果处理器
	s.runner.OnResult = func(r *result.Result) {
		atomic.AddInt32(&s.stats.CompletedScans, 1)
		if s.options != nil && s.options.OnPhaseProgress != nil {
			total := int64(s.stats.TotalScans)
			completed := int64(atomic.LoadInt32(&s.stats.CompletedScans))
			percent := 100
			if total > 0 {
				percent = int(completed * 100 / total)
				if percent > 100 {
					percent = 100
				}
				if percent < 0 {
					percent = 0
				}
			}
			if int32(percent) != atomic.LoadInt32(&s.lastVulnPhasePercent) {
				atomic.StoreInt32(&s.lastVulnPhasePercent, int32(percent))
				status := "running"
				if total == 0 || (completed >= total && percent >= 100) {
					status = "completed"
				}
				s.options.OnPhaseProgress("vuln", status, completed, total, percent)
			}
		}

		if r.IsVul {
			s.mu.Lock()
			s.results = append(s.results, r)
			atomic.AddInt32(&s.stats.FoundVulns, 1)
			s.mu.Unlock()

			// 同步回调
			if s.OnResult != nil {
				s.OnResult(r)
			}

			// 流式输出
			if s.ResultChan != nil {
				ch := s.ResultChan
				func() {
					defer func() { _ = recover() }()
					select {
					case ch <- r:
					case <-s.ctx.Done():
						return
					default:
					}
				}()
			}

			// 如果设置了发现漏洞即停止
			if s.options.VulnerabilityScannerBreakpoint {
				return
			}
		}
	}

	s.runner.OnFingerprint = func(targetKey string, hits []fingerprint.Hit) {
		for _, hit := range hits {
			sev := strings.TrimSpace(hit.Severity)
			if sev == "" {
				sev = "info"
			}
			name := strings.TrimSpace(hit.Name)
			if name == "" {
				name = strings.TrimSpace(hit.ID)
			}

			rst := s.runner.FingerprintResult(targetKey, hit.ID)
			if rst == nil {
				rst = &result.Result{
					IsVul:      true,
					Target:     targetKey,
					FullTarget: targetKey,
					PocInfo: &poc.Poc{
						Id: hit.ID,
						Info: poc.Info{
							Name:     name,
							Severity: sev,
							Tags:     hit.Tags,
						},
					},
					FingerResult: []fingerprint.Hit{hit},
				}
			} else {
				rst.IsVul = true
				if rst.PocInfo == nil {
					rst.PocInfo = &poc.Poc{Id: hit.ID}
				} else {
					rst.PocInfo.Id = hit.ID
				}
				rst.PocInfo.Info.Name = name
				rst.PocInfo.Info.Severity = sev
				rst.PocInfo.Info.Tags = hit.Tags
				rst.FingerResult = []fingerprint.Hit{hit}
			}
			if strings.TrimSpace(rst.FullTarget) == "" {
				rst.FullTarget = rst.Target
			}
			if s.runner.OnResult != nil {
				s.runner.OnResult(rst)
			}
		}
	}

	// 执行扫描
	s.runner.Execute()

	if s.options != nil && s.options.OnPhaseProgress != nil {
		total := int64(s.stats.TotalScans)
		completed := int64(atomic.LoadInt32(&s.stats.CompletedScans))
		percent := 100
		if total > 0 {
			percent = int(completed * 100 / total)
			if percent > 100 {
				percent = 100
			}
			if percent < 0 {
				percent = 0
			}
		}
		status := "completed"
		if s.ctx != nil && s.ctx.Err() != nil {
			status = "interrupted"
		} else if total > 0 && completed < total {
			status = "interrupted"
		}
		if status == "completed" {
			percent = 100
			if total > 0 {
				completed = total
			}
		}
		s.options.OnPhaseProgress("vuln", status, completed, total, percent)
	}

	s.stats.EndTime = time.Now()
	return nil
}

// GetResults 获取所有扫描结果
func (s *SDKScanner) GetResults() []*result.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]*result.Result, len(s.results))
	copy(results, s.results)
	return results
}

func (s *SDKScanner) GetOpenPorts() map[string][]int {
	s.openPortsMu.Lock()
	defer s.openPortsMu.Unlock()

	out := make(map[string][]int, len(s.openPorts))
	for host, ports := range s.openPorts {
		if len(ports) == 0 {
			continue
		}
		dst := make([]int, 0, len(ports))
		for p := range ports {
			dst = append(dst, p)
		}
		out[host] = dst
	}
	return out
}

// GetStats 获取扫描统计信息
func (s *SDKScanner) GetStats() ScanStats {
	stats := *s.stats
	stats.CompletedScans = atomic.LoadInt32(&s.stats.CompletedScans)
	stats.FoundVulns = atomic.LoadInt32(&s.stats.FoundVulns)
	return stats
}

// GetProgress 获取扫描进度（0-100）
func (s *SDKScanner) GetProgress() float64 {
	clip := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}

	getPhasePercent := func(name string) int {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return 0
		}
		s.phaseMu.Lock()
		pp, ok := s.phases[name]
		s.phaseMu.Unlock()
		if !ok {
			return 0
		}
		if pp.Percent < 0 {
			return 0
		}
		if pp.Percent > 100 {
			return 100
		}
		return pp.Percent
	}

	vulnPercent := 100.0
	if s.stats.TotalScans > 0 {
		completed := atomic.LoadInt32(&s.stats.CompletedScans)
		vulnPercent = float64(completed) / float64(s.stats.TotalScans) * 100
	}

	hasPort := s.sdkOpts != nil && s.sdkOpts.PortScan
	hasWebProbe := s.sdkOpts != nil && s.sdkOpts.EnableWebProbe

	portStagePercent := 100.0
	if hasPort {
		hostDisc := getPhasePercent("host_discovery")
		portscan := getPhasePercent("portscan")
		if hostDisc == 0 && portscan == 0 {
			portStagePercent = 0
		} else {
			portStagePercent = (float64(hostDisc) + float64(portscan)) / 2
		}
	}

	webprobePercent := 100.0
	if hasWebProbe {
		wp := getPhasePercent("webprobe")
		webprobePercent = float64(wp)
	}

	wPort := 0.0
	if hasPort {
		wPort = 0.2
	}
	wWeb := 0.0
	if hasWebProbe {
		wWeb = 0.2
	}
	wVuln := 1.0 - wPort - wWeb
	if wVuln < 0 {
		wVuln = 0
	}

	return clip(wPort*portStagePercent + wWeb*webprobePercent + wVuln*clip(vulnPercent))
}

// Stop 停止扫描
func (s *SDKScanner) Stop() {
	s.cancel()
	s.options.VulnerabilityScannerBreakpoint = true
	if s.runner != nil {
		s.runner.Stop()
	}
}

// Close 关闭扫描器，释放资源
func (s *SDKScanner) Close() {
	s.Stop()
	if s.runStarted != nil {
		select {
		case <-s.runStarted:
			if s.runDone != nil {
				<-s.runDone
			}
		default:
		}
	}
	s.closeChans()
	s.results = nil
}

// HasVulnerabilities 检查是否发现漏洞
func (s *SDKScanner) HasVulnerabilities() bool {
	return atomic.LoadInt32(&s.stats.FoundVulns) > 0
}

// GetVulnerabilityCount 获取漏洞数量
func (s *SDKScanner) GetVulnerabilityCount() int {
	return int(atomic.LoadInt32(&s.stats.FoundVulns))
}

func (s *SDKScanner) Pause() {
	if s.runner != nil {
		s.runner.Pause()
	}
}

func (s *SDKScanner) Resume() {
	if s.runner != nil {
		s.runner.Resume()
	}
}

func (s *SDKScanner) IsPaused() bool {
	if s.runner == nil {
		return false
	}
	return s.runner.IsPaused()
}

func (s *SDKScanner) IsStopping() bool {
	return s.options.VulnerabilityScannerBreakpoint
}

// SetProxy 动态设置代理
func (s *SDKScanner) SetProxy(proxy string) {
	s.options.Proxy = proxy
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:             proxy,
		Timeout:           s.options.Timeout,
		Retries:           s.options.Retries,
		MaxRespBodySize:   s.options.MaxRespBodySize,
		ReqLimitPerTarget: s.options.ReqLimitPerTarget,
		DefaultAccept:     s.options.DefaultAccept,
	})
}

// SetRateLimit 动态设置速率限制
func (s *SDKScanner) SetRateLimit(rateLimit int) {
	s.options.RateLimit = rateLimit
}

// SetConcurrency 动态设置并发数
func (s *SDKScanner) SetConcurrency(concurrency int) {
	s.options.Concurrency = concurrency
}

// ========== OOB检测相关函数 ==========

// IsOOBEnabled 检查是否启用了OOB检测
func (s *SDKScanner) IsOOBEnabled() bool {
	// 首先检查SDK配置中是否明确启用了OOB
	if s.sdkOpts != nil && s.sdkOpts.EnableOOB {
		return true
	}
	// 检查是否配置了OOB相关参数
	return s.options.OOB != "" && (s.options.OOBKey != "" || s.options.OOBDomain != "")
}

// GetOOBStatus 获取OOB状态信息
func (s *SDKScanner) GetOOBStatus() (bool, string) {
	// 首先检查是否在SDK选项中明确启用了OOB
	sdkOpts := s.getSDKOptions()
	if sdkOpts != nil && !sdkOpts.EnableOOB {
		return false, "OOB未配置或未启用"
	}

	if !s.IsOOBEnabled() {
		return false, "OOB未配置或未启用"
	}

	if s.runner == nil {
		return false, "扫描器未初始化"
	}

	// 只有在启用OOB时才进行连接检测
	if sdkOpts != nil && sdkOpts.EnableOOB {
		return s.checkOOBConnection()
	}

	return false, "OOB未启用"
}

// getSDKOptions 获取SDK配置选项
func (s *SDKScanner) getSDKOptions() *SDKOptions {
	return s.sdkOpts
}

// checkOOBConnection 检查OOB连接状态 - SDK专用检测函数
func (s *SDKScanner) checkOOBConnection() (bool, string) {
	// 从配置中获取当前OOB服务名称
	serviceName := strings.ToLower(s.options.OOB)
	if serviceName == "" {
		return false, "OOB未配置"
	}

	// 检查配置完整性
	if s.options.OOBKey == "" && s.options.OOBDomain == "" {
		return false, fmt.Sprintf("%s (配置不完整)", serviceName)
	}

	// 尝试创建OOB适配器进行连接测试，这里使用和runner相同的逻辑，但在SDK中独立执行
	if oobAdapter, err := s.createOOBAdapter(); err == nil {
		if oobAdapter.IsVaild() {
			return true, fmt.Sprintf("%s (连接正常)", serviceName)
		} else {
			return false, fmt.Sprintf("%s (连接失败)", serviceName)
		}
	} else {
		return false, fmt.Sprintf("%s (初始化失败: %v)", serviceName, err)
	}
}

// OOBAdapter 简化的OOB适配器接口
type OOBAdapter interface {
	IsVaild() bool
}

// simpleOOBAdapter 简单的OOB适配器实现
type simpleOOBAdapter struct {
	valid bool
}

func (s *simpleOOBAdapter) IsVaild() bool {
	return s.valid
}

// createOOBAdapter 创建OOB适配器 - SDK内部使用
func (s *SDKScanner) createOOBAdapter() (OOBAdapter, error) {
	// 检查配置完整性
	if s.options.OOBKey == "" && s.options.OOBDomain == "" {
		return nil, fmt.Errorf("配置不完整")
	}

	// 进行OOB反链可用性检测
	if oobAdapter, err := oobadapter.NewOOBAdapter(s.options.OOB, &oobadapter.ConnectorParams{
		Key:     s.options.OOBKey,
		Domain:  s.options.OOBDomain,
		HTTPUrl: s.options.OOBHttpUrl,
		ApiUrl:  s.options.OOBApiUrl,
	}); err == nil {
		if oobAdapter.IsVaild() {
			return &simpleOOBAdapter{valid: true}, nil
		} else {
			return &simpleOOBAdapter{valid: false}, nil
		}
	} else {
		return &simpleOOBAdapter{valid: false}, err
	}

}

// printScanInfo 输出扫描基本信息
func (s *SDKScanner) printScanInfo() {
	fmt.Printf("\n========== 扫描信息 ==========\n")
	fmt.Printf("目标数量: %d\n", s.stats.TotalTargets)
	fmt.Printf("POC数量: %d\n", s.stats.TotalPocs)
	fmt.Printf("总扫描任务: %d\n", s.stats.TotalScans)

	// 输出目标列表
	if s.stats.TotalTargets <= 5 {
		fmt.Printf("扫描目标: ")
		targets := s.options.Targets.List()
		for i, target := range targets {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%v", target)
		}
		fmt.Printf("\n")
	} else {
		fmt.Printf("目标过多，仅显示前3个: ")
		targets := s.options.Targets.List()
		for i := 0; i < 3 && i < len(targets); i++ {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%v", targets[i])
		}
		fmt.Printf("...\n")
	}

	// OOB状态 - 只在明确启用OOB时才显示
	if s.sdkOpts != nil && s.sdkOpts.EnableOOB {
		if oobEnabled, oobStatus := s.GetOOBStatus(); oobEnabled {
			fmt.Printf("OOB状态: ✓ %s\n", oobStatus)
		} else {
			fmt.Printf("OOB状态: ✗ %s\n", oobStatus)
		}
	} else {
		fmt.Printf("OOB状态: ✗ OOB未配置或未启用\n")
	}

	fmt.Printf("=============================\n")
}

func applyCuratedMount(options *config.Options) error {
	if options == nil || options.Config == nil {
		return nil
	}
	cur := options.Config.Curated
	enabled := strings.ToLower(strings.TrimSpace(cur.Enabled))
	endpoint := strings.TrimSpace(cur.Endpoint)
	if enabled == "off" || enabled == "false" || enabled == "0" || endpoint == "" {
		_ = os.Setenv("AFROG_CURATED_DISABLED", "1")
		_ = os.Unsetenv("AFROG_POCS_CURATED_DIR")
		return nil
	}

	_ = os.Unsetenv("AFROG_CURATED_DISABLED")
	svc := service.New(service.Config{
		Endpoint:      endpoint,
		Channel:       strings.TrimSpace(cur.Channel),
		CuratedPocDir: "",
		LicenseKey:    strings.TrimSpace(cur.LicenseKey),
		NoUpdate:      cur.AutoUpdate != nil && !*cur.AutoUpdate && !options.CuratedForceUpdate,
		ForceUpdate:   options.CuratedForceUpdate,
		ClientVersion: config.Version,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cur.TimeoutSec)*time.Second)
	if cur.TimeoutSec <= 0 {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	dir, err := svc.Mount(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curated mount failed: %s\n", strings.TrimSpace(err.Error()))
		return nil
	}
	if strings.TrimSpace(dir) != "" {
		_ = os.Setenv("AFROG_POCS_CURATED_DIR", dir)
	}
	return nil
}

// convertSDKOptions 转换SDK配置到内部配置
func convertSDKOptions(opts *SDKOptions) *config.Options {
	options := &config.Options{
		TargetsFile:                    opts.TargetsFile,
		PocFile:                        opts.PocFile,
		AppendPoc:                      opts.AppendPoc,
		Search:                         opts.Search,
		Severity:                       opts.Severity,
		ExcludePocs:                    opts.ExcludePocs,
		ExcludePocsFile:                opts.ExcludePocsFile,
		RateLimit:                      opts.RateLimit,
		ReqLimitPerTarget:              opts.ReqLimitPerTarget,
		AutoReqLimit:                   opts.AutoReqLimit,
		Polite:                         opts.Polite,
		Balanced:                       opts.Balanced,
		Aggressive:                     opts.Aggressive,
		Concurrency:                    opts.Concurrency,
		Retries:                        opts.Retries,
		Timeout:                        opts.Timeout,
		MaxHostError:                   opts.MaxHostError,
		Proxy:                          opts.Proxy,
		MaxRespBodySize:                opts.MaxRespBodySize,
		BruteMaxRequests:               opts.BruteMaxRequests,
		DefaultAccept:                  opts.DefaultAccept,
		OOBRateLimit:                   opts.OOBRateLimit,
		OOBConcurrency:                 opts.OOBConcurrency,
		Smart:                          opts.Smart,
		DisableFingerprint:             opts.DisableFingerprint,
		EnableWebProbe:                 opts.EnableWebProbe,
		FingerprintFilterMode:          opts.FingerprintFilterMode,
		VulnerabilityScannerBreakpoint: opts.VulnerabilityScannerBreakpoint,
		PortScan:                       opts.PortScan,
		PSPorts:                        opts.PSPorts,
		PSRateLimit:                    opts.PSRateLimit,
		PSTimeout:                      opts.PSTimeout,
		PSRetries:                      opts.PSRetries,
		PSSkipDiscovery:                opts.PSSkipDiscovery,
		PSS4Chunk:                      opts.PSS4Chunk,
		Dingtalk:                       opts.Dingtalk,
		Wecom:                          opts.Wecom,
		CuratedEnabled:                 opts.CuratedEnabled,
		CuratedEndpoint:                opts.CuratedEndpoint,
		CuratedTimeout:                 opts.CuratedTimeout,
		CuratedForceUpdate:             opts.CuratedForceUpdate,
	}

	if options.MaxRespBodySize <= 0 {
		options.MaxRespBodySize = 2
	}
	if strings.TrimSpace(options.FingerprintFilterMode) == "" {
		options.FingerprintFilterMode = "strict"
	}
	if options.OOBRateLimit == 0 {
		options.OOBRateLimit = 25
	}
	if options.OOBConcurrency == 0 {
		options.OOBConcurrency = 25
	}
	if options.ReqLimitPerTarget == 0 {
		if options.Polite {
			options.ReqLimitPerTarget = 5
		} else if options.Balanced {
			options.ReqLimitPerTarget = 15
		} else if options.Aggressive {
			options.ReqLimitPerTarget = 50
		} else if options.AutoReqLimit {
			baseRate := options.RateLimit
			if baseRate <= 0 {
				baseRate = 150
			}
			r := baseRate / 10
			if r < 5 {
				r = 5
			}
			if r > 15 {
				r = 15
			}
			con := options.Concurrency
			if con <= 0 {
				con = 1
			}
			if con >= 100 && r > 8 {
				r = 8
			} else if con >= 50 && r > 12 {
				r = 12
			}
			options.ReqLimitPerTarget = r
		}
	}

	if len(opts.Headers) > 0 {
		for _, h := range opts.Headers {
			options.Header = append(options.Header, h)
		}
	}

	// 转换目标列表
	if len(opts.Targets) > 0 {
		for _, target := range opts.Targets {
			options.Target = append(options.Target, target)
		}
	}

	return options
}

// validateSDKConfig SDK配置验证
func validateSDKConfig(options *config.Options) error {
	limitModeCount := 0
	if options.ReqLimitPerTarget > 0 {
		limitModeCount++
	}
	if options.AutoReqLimit {
		limitModeCount++
	}
	if options.Polite {
		limitModeCount++
	}
	if options.Balanced {
		limitModeCount++
	}
	if options.Aggressive {
		limitModeCount++
	}
	if limitModeCount > 1 {
		return errors.New("only one of ReqLimitPerTarget/AutoReqLimit/Polite/Balanced/Aggressive can be used")
	}
	if options.ReqLimitPerTarget < 0 {
		return errors.New("ReqLimitPerTarget must be >= 0")
	}

	options.FingerprintFilterMode = strings.ToLower(strings.TrimSpace(options.FingerprintFilterMode))
	if options.FingerprintFilterMode == "" {
		options.FingerprintFilterMode = "strict"
	}
	if options.FingerprintFilterMode != "strict" && options.FingerprintFilterMode != "opportunistic" {
		options.FingerprintFilterMode = "strict"
	}

	// 验证目标
	if len(options.Target) == 0 && len(options.TargetsFile) == 0 {
		return errors.New("未指定扫描目标")
	}

	// 验证POC文件
	if options.PocFile == "" && len(options.AppendPoc) == 0 {
		// 如果PocFile为空且AppendPoc也为空，且不使用默认配置（这里允许为空，由Runner处理默认值）
		// return errors.New("必须指定POC文件或目录")
	}

	// 验证POC文件是否存在
	if options.PocFile != "" {
		if _, err := os.Stat(options.PocFile); err != nil {
			return fmt.Errorf("POC文件或目录不存在: %s", options.PocFile)
		}
	}

	if options.Config != nil {
		tokensEmpty := func(tokens []string) bool {
			for _, t := range tokens {
				if strings.TrimSpace(t) != "" {
					return false
				}
			}
			return true
		}

		if options.Dingtalk && tokensEmpty(options.Config.Webhook.Dingtalk.Tokens) {
			return errors.New("Dingtalk webhook token is required")
		}
		if options.Wecom && tokensEmpty(options.Config.Webhook.Wecom.Tokens) {
			return errors.New("Wecom webhook token is required")
		}
	}

	return nil
}

// createSDKRunner 创建SDK专用的Runner
func createSDKRunner(options *config.Options) (*runner.Runner, error) {
	// 初始化HTTP客户端
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:             options.Proxy,
		Timeout:           options.Timeout,
		Retries:           options.Retries,
		MaxRespBodySize:   options.MaxRespBodySize,
		ReqLimitPerTarget: options.ReqLimitPerTarget,
		DefaultAccept:     options.DefaultAccept,
	})

	// 处理目标
	seen := make(map[string]struct{})

	// 添加命令行目标
	if len(options.Target) > 0 {
		for _, rawTarget := range options.Target {
			trimmedTarget := strings.TrimSpace(rawTarget)
			if _, ok := seen[trimmedTarget]; !ok {
				seen[trimmedTarget] = struct{}{}
				options.Targets.Append(trimmedTarget)
			}
		}
	}

	// 从文件读取目标
	if len(options.TargetsFile) > 0 {
		allTargets, err := utils.ReadFileLineByLine(options.TargetsFile)
		if err != nil {
			return nil, err
		}
		for _, rawTarget := range allTargets {
			trimmedTarget := strings.TrimSpace(rawTarget)
			if len(trimmedTarget) > 0 {
				if _, ok := seen[trimmedTarget]; !ok {
					seen[trimmedTarget] = struct{}{}
					options.Targets.Append(trimmedTarget)
				}
			}
		}
	}

	// 验证目标
	if options.Targets.Len() == 0 {
		return nil, errors.New("未找到有效目标")
	}

	// 设置POC目录
	if options.PocFile != "" {
		options.PocsDirectory.Set(options.PocFile)
	}
	for _, p := range options.AppendPoc {
		options.PocsDirectory.Set(p)
	}

	// 清空Target切片
	options.Target = nil

	// 创建Runner
	r, err := runner.NewRunner(options)
	if err != nil {
		return nil, err
	}

	// SDK模式特殊处理
	c := catalog.New(options.PocsDirectory.String())
	allPocsYamlSlice := c.GetPocsPath(options.PocsDirectory)
	if len(allPocsYamlSlice) == 0 && len(pocs.EmbedFileList) == 0 {
		return nil, errors.New("未找到POC文件")
	}

	return r, nil
}
