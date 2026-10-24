package portscan

import (
	"time"
)

// 连接速率档位（连接/秒）。CPS 与并发是两个正交维度：RateLimit/MaxHostConcurrency
// 限制「同时有多少条连接在飞」，CPS 限制「每秒新开多少条连接」。只限并发是不够的：
// 500 并发在 1ms RTT 的内网里理论上限是 50 万连接/秒，会把出口设备的 NAT/conntrack
// 会话表打满（被过滤的端口不回包，表项要挂到 30~120s 超时才释放），同一网络里其他
// 人的新建连接就会失败。所以默认给一个保守的 CPS 天花板，需要打满时用 -aggressive。
const (
	PresetPoliteGlobalCPS    = 200
	PresetPolitePerHostCPS   = 20
	PresetBalancedGlobalCPS  = 1000
	PresetBalancedPerHostCPS = 100
	// DefaultGlobalCPS / DefaultPerHostCPS 是未指定档位时的默认，与 balanced 一致。
	DefaultGlobalCPS  = PresetBalancedGlobalCPS
	DefaultPerHostCPS = PresetBalancedPerHostCPS
)

// Options configuration for the port scanner
type Options struct {
	Targets                 []string // List of IPs, CIDRs, or ranges
	Ports                   string   // Port range string (e.g., "80,443,1000-2000" or "top")
	S4ChunkSize             int
	RateLimit               int  // 全局在飞探测上限（worker 池大小），不是每秒请求数；见 ConnectRateLimit
	ConnectRateLimit        int  // 全局连接建立速率上限（每秒新发起的探测数，0 = 不限）
	ConnectRateLimitPerHost int  // 单目标连接建立速率上限（每秒，0 = 不限）
	LinkProbe               bool // 周期性测量到默认网关的 RTT，作为链路拥塞信号
	MaxHostConcurrency      int  // Max concurrent probes per target (0 = unlimited)
	Timeout                 time.Duration
	Retries                 int
	AdaptiveTimeout         bool // Scale the connect timeout with measured RTT
	ScanMode                ScanMode
	ServiceProbes           bool   // Send active service probes (default: passive banner grabbing only)
	FingerprintDir          string // Optional directory with probes.yaml / services.yaml / ports.yaml that overrides the built-in set
	OnResult                func(*ScanResult)
	OnProgress              func(phase string, status string, finished int, total int, percent int)
	OnDiscoveredHost        func(host string)
	Debug                   bool
	LiveStats               bool
	StageLog                bool // Print phase boundary lines (HOST-DISC/PORT-SCAN started/completed); off by default
	Quiet                   bool
	SkipDiscovery           bool // Skip host discovery phase
	DiscoveryPorts          []int
	DiscoveryFallback       bool
	DiscoveryFallbackPorts  []int
	DiscoveryMethod         string
	IcmpConcurrency         int
	PingConcurrency         int
	DiscoveryTop            int
	DiscoveryRetries        int
	LogDiscoveredHosts      bool
}

// DefaultOptions returns a safe default configuration
func DefaultOptions() *Options {
	return &Options{
		Ports:                   "full",
		S4ChunkSize:             1000,
		RateLimit:               500,
		ConnectRateLimit:        DefaultGlobalCPS,
		ConnectRateLimitPerHost: DefaultPerHostCPS,
		LinkProbe:               true,
		MaxHostConcurrency:      100,
		Timeout:                 1000 * time.Millisecond,
		// Retries 默认 0。TCP connect 扫描里「超时」无法区分「端口关闭但不回包」
		// 与「探测包被丢弃」，对每个 filtered 端口重试会把单端口成本从一次超时
		// 放大到 (1+Retries) 次超时外加退避睡眠：1000ms 超时 + 2 次重试（且重试
		// 预算递增到 1.5s / 2.0s）实测单端口 4.3s，100 并发只有 23 端口/秒，
		// 65535 端口要扫近 50 分钟 —— 扫描器再准，用户等不到结果也没有意义。
		// 需要「宁可慢也不漏」时用 -ptries 显式开启。
		Retries:                0,
		AdaptiveTimeout:        true,
		ScanMode:               ScanModeAuto,
		Quiet:                  false,
		DiscoveryFallback:      true,
		DiscoveryFallbackPorts: defaultDiscoveryFallbackPorts(),
		DiscoveryMethod:        "auto",
		IcmpConcurrency:        1000,
		PingConcurrency:        50,
		DiscoveryTop:           10,
		DiscoveryRetries:       1,
		LogDiscoveredHosts:     true,
	}
}
