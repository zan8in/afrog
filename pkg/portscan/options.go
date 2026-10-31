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
	PresetBalancedPerHostCPS = 50
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
	// OnDiscoveredHost 上报一个存活主机。proto 是判定依据（icmp / ping / tcp），
	// 与终端 `序号 [alive] host [icmp]` 行的方括号属性同源。
	OnDiscoveredHost func(host, proto string)
	// OnStageLog 上报阶段运维行（[INF]/[WRN] + 阶段名 + 事实），供 JSON 事件流 /
	// Web 端复刻终端输出。终端打印受 Quiet 控制，钩子本身不受影响。
	OnStageLog             func(level, stage string, facts []string)
	Debug                  bool
	LiveStats              bool
	StageLog               bool // Print phase boundary lines (HOST-DISC/PORT-SCAN started/completed); off by default
	Quiet                  bool
	SkipDiscovery          bool // Skip host discovery phase
	DiscoveryPorts         []int
	DiscoveryFallback      bool
	DiscoveryFallbackPorts []int
	DiscoveryMethod        string
	IcmpConcurrency        int
	PingConcurrency        int
	DiscoveryTop           int
	DiscoveryRetries       int
	LogDiscoveredHosts     bool

	// ReportStates 控制是否把非开放端口（closed / filtered）也作为结果上报。默认关闭：
	// 全端口扫描下一次 filtered 判定可能命中成千上万个端口，默认全量输出会淹没开放端口
	// 行与后续阶段的结果。开启后用户才能区分「被防火墙静默丢弃」(filtered) 与「端口确实
	// 关闭」(closed)——这两者在故障排查里的含义完全不同。这些行只用于展示端口状态分布，
	// 不会进入开放端口集合或后续扫描目标。
	ReportStates bool

	// aliveSeq 是存活主机结果行的序号计数器，按本次扫描递增。放在 Options 上是因为
	// 打印发生在 portscan 内部，而发现过程会跨 icmp / ping / tcp 多个阶段，需要一个
	// 生命周期覆盖整轮发现的共享计数（各阶段的 phaseProgress 是相互独立的）。
	aliveSeq uint64
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
		MaxHostConcurrency:      50,
		Timeout:                 1000 * time.Millisecond,
		// Retries 默认 1：只对「超时」重试，收到 RST（端口确实关闭）会立即返回，
		// 因此绝大多数目标的成本不变。单次探测的漏报代价太高——首次 SYN 常因
		// 瞬时丢包、ARP 冷启动、目标/中间设备的端口扫描防护被静默丢弃，没有第二次
		// 机会就等于把一个真实开放端口永久记成 closed/filtered。
		// 需要更快时可用 -ptries 0 显式关闭。
		Retries:                1,
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
