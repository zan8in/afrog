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
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

// SDKScanner SDK版本的扫描器，专为库调用优化
type SDKScanner struct {
	// runner 内部扫描引擎实例
	runner *runner.Runner

	// results 存储所有扫描结果
	results []*result.Result

	// mu 用于保护results的并发访问
	mu sync.Mutex

	// options 存储扫描配置选项
	options *config.Options

	// sdkOpts 保存原始SDK配置选项
	sdkOpts *SDKOptions

	// 实时结果回调（同步版本）
	OnResult func(*result.Result)

	// 实时结果通道（流式版本）
	ResultChan chan *result.Result

	// 控制流式输出的context
	ctx    context.Context
	cancel context.CancelFunc

	// 扫描统计信息
	stats *ScanStats
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

// SDKOptions SDK扫描配置选项（优化版）
type SDKOptions struct {
	// ========== 目标配置 ==========
	Targets     []string // 扫描目标列表
	TargetsFile string   // 目标文件路径

	// ========== POC配置 ==========
	PocFile  string // POC文件或目录路径（必须）
	Search   string // POC搜索关键词
	Severity string // 严重程度过滤

	// ========== 性能配置 ==========
	RateLimit    int // 请求速率限制 (默认: 150)
	Concurrency  int // 并发数 (默认: 25)
	Retries      int // 重试次数 (默认: 1)
	Timeout      int // 超时时间秒 (默认: 10)
	MaxHostError int // 主机最大错误数 (默认: 3)

	// ========== 网络配置 ==========
	Proxy string // HTTP/SOCKS5代理

	// ========== OOB配置 ==========
	EnableOOB  bool   // 是否启用OOB检测 (默认: false)
	OOB        string // OOB适配器类型: ceyeio, dnslogcn, alphalog, xray, revsuit
	OOBKey     string // OOB API密钥
	OOBDomain  string // OOB域名
	OOBApiUrl  string // OOB API地址
	OOBHttpUrl string // OOB HTTP地址

	// ========== 输出配置 ==========
	EnableStream bool // 启用流式输出
}

// NewSDKOptions 创建默认配置
func NewSDKOptions() *SDKOptions {
	return &SDKOptions{
		RateLimit:    150,
		Concurrency:  25,
		Retries:      1,
		Timeout:      10,
		MaxHostError: 3,
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
	cfg, _ := config.NewConfig("")
	options.Config = cfg

	// 设置OOB配置（只有启用OOB且配置了OOB适配器才设置）
	if opts.EnableOOB && opts.OOB != "" {
		options.OOB = opts.OOB
		options.OOBKey = opts.OOBKey
		options.OOBDomain = opts.OOBDomain
		options.OOBApiUrl = opts.OOBApiUrl
		options.OOBHttpUrl = opts.OOBHttpUrl
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
		runner:  r,
		results: make([]*result.Result, 0),
		options: options,
		sdkOpts: opts,
		ctx:     ctx,
		cancel:  cancel,
		stats: &ScanStats{
			StartTime: time.Now(),
		},
	}

	// 如果启用流式输出，创建结果通道
	if opts.EnableStream {
		scanner.ResultChan = make(chan *result.Result, 100)
	}

	// 计算扫描统计
	scanner.stats.TotalTargets = options.Targets.Len()
	pocSlice := options.CreatePocList()
	scanner.stats.TotalPocs = len(pocSlice)
	scanner.stats.TotalScans = scanner.stats.TotalTargets * scanner.stats.TotalPocs

	return scanner, nil
}

// Run 执行扫描（同步版本）
func (s *SDKScanner) Run() error {
	// 在扫描开始前输出基本信息
	s.printScanInfo()
	return s.run()
}

// RunAsync 执行扫描（异步版本）
func (s *SDKScanner) RunAsync() error {
	go func() {
		// 在扫描开始前输出基本信息
		s.printScanInfo()
		s.run()
		if s.ResultChan != nil {
			close(s.ResultChan)
		}
	}()
	return nil
}

// run 内部扫描执行
func (s *SDKScanner) run() error {
	// 设置结果处理器
	s.runner.OnResult = func(r *result.Result) {
		atomic.AddInt32(&s.stats.CompletedScans, 1)

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
				select {
				case s.ResultChan <- r:
				case <-s.ctx.Done():
					return
				default:
					// 通道满了，跳过
				}
			}

			// 如果设置了发现漏洞即停止
			if s.options.VulnerabilityScannerBreakpoint {
				return
			}
		}
	}

	// 执行扫描
	s.runner.Execute()

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

// GetStats 获取扫描统计信息
func (s *SDKScanner) GetStats() ScanStats {
	stats := *s.stats
	stats.CompletedScans = atomic.LoadInt32(&s.stats.CompletedScans)
	stats.FoundVulns = atomic.LoadInt32(&s.stats.FoundVulns)
	return stats
}

// GetProgress 获取扫描进度（0-100）
func (s *SDKScanner) GetProgress() float64 {
	if s.stats.TotalScans == 0 {
		return 0
	}
	completed := atomic.LoadInt32(&s.stats.CompletedScans)
	return float64(completed) / float64(s.stats.TotalScans) * 100
}

// Stop 停止扫描
func (s *SDKScanner) Stop() {
	s.cancel()
	s.options.VulnerabilityScannerBreakpoint = true
}

// Close 关闭扫描器，释放资源
func (s *SDKScanner) Close() {
	s.cancel()
	if s.ResultChan != nil {
		close(s.ResultChan)
	}
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

// SetProxy 动态设置代理
func (s *SDKScanner) SetProxy(proxy string) {
	s.options.Proxy = proxy
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           proxy,
		Timeout:         s.options.Timeout,
		Retries:         s.options.Retries,
		MaxRespBodySize: s.options.MaxRespBodySize,
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

// convertSDKOptions 转换SDK配置到内部配置
func convertSDKOptions(opts *SDKOptions) *config.Options {
	options := &config.Options{
		TargetsFile:     opts.TargetsFile,
		PocFile:         opts.PocFile,
		Search:          opts.Search,
		Severity:        opts.Severity,
		RateLimit:       opts.RateLimit,
		Concurrency:     opts.Concurrency,
		Retries:         opts.Retries,
		MaxHostError:    opts.MaxHostError,
		Timeout:         opts.Timeout,
		Proxy:           opts.Proxy,
		MaxRespBodySize: 2,
		OOBRateLimit:    50,
		OOBConcurrency:  20,
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
	// 验证目标
	if len(options.Target) == 0 && len(options.TargetsFile) == 0 {
		return errors.New("未指定扫描目标")
	}

	// 验证POC文件
	if options.PocFile == "" {
		return errors.New("必须指定POC文件或目录")
	}

	// 验证POC文件是否存在
	if _, err := os.Stat(options.PocFile); err != nil {
		return fmt.Errorf("POC文件或目录不存在: %s", options.PocFile)
	}

	return nil
}

// createSDKRunner 创建SDK专用的Runner
func createSDKRunner(options *config.Options) (*runner.Runner, error) {
	// 初始化HTTP客户端
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           options.Proxy,
		Timeout:         options.Timeout,
		Retries:         options.Retries,
		MaxRespBodySize: options.MaxRespBodySize,
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
	options.PocsDirectory.Set(options.PocFile)

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
	if len(allPocsYamlSlice) == 0 {
		return nil, errors.New("未找到POC文件")
	}

	return r, nil
}
