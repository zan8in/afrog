package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rs/xid"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/output"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsign"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/validator"
	"github.com/zan8in/afrog/v3/pkg/webhook/dingtalk"
	"github.com/zan8in/afrog/v3/pkg/webhook/wecom"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/formatter"
	fileutil "github.com/zan8in/pins/file"
	"gopkg.in/yaml.v2"
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

	AfrogUpdate *AfrogUpdate

	// Pocs Directory
	PocsDirectory utils.StringSlice

	// Targets 是扫描目标及其状态计数（协议校验通过 / 错误次数）。
	// 用 TargetSet 而不是有序线性表：扫描热路径会按「目标 × PoC」频繁查询它，
	// 详见 targetset.go 的说明。
	Targets TargetSet

	// target URLs/hosts to scan
	Target goflags.StringSlice

	// list of target URLs/hosts to scan (one per line)
	TargetsFile string

	// PoC file or directory to scan.
	// Deprecated: 语义为“独占”（屏蔽内置与用户目录 PoC），新代码请使用 PocPaths + PocPathsOnly。
	PocFile string

	// PocPaths 是追加式的 PoC 输入，支持文件、目录和 glob 通配符（如 "dir/*.yaml"）。
	// 与内置、curated、my、local 来源合并，同名时以 PocPaths 优先。
	PocPaths []string

	// PocPathsOnly 为 true 时只加载 PocPaths/AppendPoc/PocFile 指定的 PoC，
	// 屏蔽内置与用户目录来源。
	PocPathsOnly bool

	// Append PoC file or directory to scan
	AppendPoc goflags.StringSlice

	// show afrog-pocs list
	PocList bool

	// show a afrog-pocs detail
	PocDetail string

	PocMigrate string

	ExcludePocs     goflags.StringSlice
	ExcludePocsFile string

	// file to write output to (optional), support format: html
	Output string

	// file to write output to (optional), support format: json
	Json string

	// file to write output to (optional), support format: json
	JsonAll string

	// search PoC by keyword , eg: -s tomcat
	Search string

	SearchKeywords []string

	// no progress if silent is true
	Silent  bool
	NoColor bool

	// pocs to run based on severity. Possible values: info, low, medium, high, critical
	Severity string

	SeverityKeywords []string

	// update afrog-pocs
	UpdatePocs bool

	// update afrog version
	Update bool

	// Disable update check
	DisableUpdateCheck bool

	MonitorTargets bool

	// POC Execution Duration Tracker
	PocExecutionDurationMonitor bool
	PedmLogLimit                int
	PedmSlowThresholdSec        int
	PedmSlowLogLimit            int
	PedmSummaryTop              int
	PedmSummaryBy               string
	TaskHardTimeoutSec          int
	TaskSmartTimeout            bool
	TaskTimeoutVisibleCapSec    int
	TaskTimeoutNetCapSec        int
	TaskTimeoutGoCapSec         int
	// JsScriptTimeout 是单个 javascript PoC 脚本的执行上限（秒），0 表示不设脚本级上限。
	JsScriptTimeout int
	// EnableJSPoc 是否启用 javascript 类型 PoC 的执行。
	// 默认开启；如需关闭，使用 -enable-js-poc=false。
	EnableJSPoc bool
	// RequireSignedJSPoc 为 true 时，未签名或签名无效的 javascript PoC 将被跳过。
	// 默认关闭（宽松模式：有签名则验，验不过仅告警不拦截）。
	RequireSignedJSPoc bool
	// PocSign 是 -pocsign 指定的 PoC 文件或目录，用于就地签名（工具模式）。
	PocSign string
	// jsReport 汇总本次 PoC 加载中 javascript 相关的启用/跳过情况。
	// 加载期只填充不打印，由 PrintJSReport 在启动横幅之后统一输出，
	// 避免这些信息插进 Core/POC/Cur/OOB 横幅中间。
	jsReport jsLoadReport

	// Single Vulnerability Stopper
	VulnerabilityScannerBreakpoint bool

	// Scan count num(targets * allpocs)
	Count int

	// Current Scan count num
	CurrentCount uint32

	// Thread lock
	OptLock sync.Mutex

	// Callback scan result
	// OnResult OnResult

	// maximum number of requests to send per second (default 150)
	RateLimit         int
	ReqLimitPerTarget int
	AutoReqLimit      bool
	Polite            bool
	Balanced          bool
	Aggressive        bool

	// setFlags 记录本次运行中用户显式传入的 flag 名。用于区分「沿用默认值」与
	// 「用户明确指定」——例如 -auto-req-limit 默认开启，而 -rlt 的 0 值既可能是
	// 「用户要求不限速」，也可能只是「没设置」，只有知道 flag 是否显式传入才能区分。
	setFlags map[string]bool

	// maximum number of afrog-pocs to be executed in parallel (default 25)
	Concurrency int

	// maximum number of requests to send per second (default 150)
	OOBRateLimit int

	// maximum number of afrog-pocs to be executed in parallel (default 25)
	OOBConcurrency int

	// Smart Control Concurrency
	Smart                 bool
	DisableFingerprint    bool
	EnableWebProbe        bool
	FingerprintFilterMode string
	Test                  bool

	// number of times to retry a failed request (default 1)
	Retries int

	//
	MaxHostError int

	// time to wait in seconds before timeout (default 10)
	Timeout int

	// http/socks5 proxy to use
	Proxy string

	MaxRespBodySize int

	BruteMaxRequests int

	// afrog process count (target total × pocs total)
	ProcessTotal uint32

	DisableOutputHtml bool

	// NoSaveDB 为真时不把命中写入 result 表：结果只在控制台/事件流里出现，不进漏洞
	// 报告与台账。用于测试性扫描或确认不重要的目标，避免污染报告。
	NoSaveDB bool

	OJ *output.OutputJson

	// Cookie string

	Header        goflags.StringSlice
	DefaultAccept bool

	Version bool

	Web bool

	// webhook
	Dingtalk bool

	// webhook wecom
	Wecom bool

	// resume
	Resume          string
	ResumeDoneTasks uint32

	// debug
	Debug     bool
	LiveStats bool

	// 以 NDJSON 事件流输出到 stdout，供程序消费
	JsonStream bool

	// sort
	// -sort severity (default low, info, medium, high, critical)
	// -sort a-z
	Sort string

	// cyberspace search
	Cyberspace string

	// cyberspace search keywords
	Query string

	// query count
	QueryCount int

	// oobadapter, eg: `-oob ceyeio` or `-oob dnslogcn` or `-oob alphalog`
	OOB                string
	OOBKey             string
	OOBDomain          string
	OOBHttpUrl         string
	OOBApiUrl          string
	OOBPollInterval    int
	OOBHitRetention    int
	OOBFinalizeTimeout int

	// SDK模式标志，用于控制OOB检测行为
	SDKMode   bool
	EnableOOB bool

	// enable pre-scan host port scanning
	PortScan    bool
	PSPorts     string
	PSRateLimit int
	// PSCPS / PSCPSHost 是端口扫描的每秒新建连接上限（全局 / 单目标），0 = 不限速。
	// 负值表示「按 -polite/-balanced/-aggressive 档位自动」，见 ResolvePortScanRates。
	PSCPS               int
	PSCPSHost           int
	PSLinkProbe         bool
	PSTimeout           int
	PSRetries           int
	PSSkipDiscovery     bool
	PSS4Chunk           int
	PSHostConcurrency   int
	PSNoAdaptiveTimeout bool
	PSServiceProbe      bool
	PSFingerprintDir    string
	// PSReportStates 让端口预扫描把非开放端口（closed / filtered）也作为结果上报，
	// 默认只上报开放端口。开启后才能区分「被防火墙丢弃」与「端口确实关闭」。
	PSReportStates    bool
	WebFingerprintDir string
	WebFavicon        bool
	// WebProbeTimeout 是 Web 探测阶段单次请求/证书获取的超时（秒），默认 30。
	// 与全局 -timeout 解耦：信息收集阶段不该被漏洞扫描的长超时拖住。
	WebProbeTimeout  int
	OnPortScanResult func(info PortScanInfo)
	// OnHostDiscovered 上报存活主机，proto 是判定依据（icmp / ping / tcp）。
	OnHostDiscovered func(host, proto string)
	// OnStageLog 上报阶段运维行（[INF]/[WRN]/[ERR] + 阶段名 + 事实），
	// 供 JSON 事件流 / Web 诊断页复刻终端输出。
	OnStageLog       func(level, stage string, facts []string)
	OnPhaseProgress  func(phase string, status string, finished int64, total int64, percent int)
	OnScanInfoUpdate func(info ScanInfoUpdate)
	OnPedmLog        func(line string)

	// path to the afrog configuration file
	ConfigFile string

	// Validate POC YAML syntax
	Validate string

	CuratedEnabled     string
	CuratedEndpoint    string
	CuratedTimeout     int
	CuratedForceUpdate bool
}

type ScanInfoUpdate struct {
	TotalTargets int
	Targets      []string
	TotalPocs    int
	TotalScans   int
	OOBEnabled   bool
	OOBStatus    string
}

// PortScanInfo 是一个开放端口的端口指纹识别结果。
// Confidence 取值 port/probable/certain，表示识别证据的强弱。
type PortScanInfo struct {
	Host string
	Port int
	// State 是端口状态：open / closed / filtered / unknown。默认只上报 open，
	// 打开 -ps-states 后才会出现 closed / filtered。
	State      string
	Service    string
	Product    string
	Version    string
	Device     string
	Hostname   string
	OS         string
	CPE        string
	Info       string
	TLS        bool
	Confidence string
	Banner     string
	Extras     map[string]string
}

func NewOptions() (*Options, error) {

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Target, "target", "t", nil, "target URLs/hosts to scan (comma separated)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.TargetsFile, "target-file", "T", "", "list of target URLs/hosts to scan (one per line)"),
		flagSet.StringVarP(&options.Cyberspace, "cyberspace", "cs", "", "cyberspace search, eg: -cs zoomeye"),
		flagSet.StringVarP(&options.Query, "query", "q", "", "cyberspace search keywords, eg: -q app:'tomcat'"),
		flagSet.IntVarP(&options.QueryCount, "query-count", "qc", 100, "cyberspace search data count, eg: -qc 1000"),
		flagSet.StringVar(&options.Resume, "resume", "", "resume scan using resume.afg"),
	)

	flagSet.CreateGroup("pocs", "PoCs",
		flagSet.StringVarP(&options.PocFile, "poc-file", "P", "", "PoC file or directory to scan"),
		flagSet.StringSliceVarP(&options.AppendPoc, "append-poc", "ap", nil, "append PoC file or directory to scan (comma separated)", goflags.NormalizedOriginalStringSliceOptions),
		flagSet.StringVar(&options.PocMigrate, "pocmigrate", "", "migrate legacy PoCs to current syntax (file or directory)"),
		flagSet.StringVar(&options.PocSign, "pocsign", "", "sign a PoC file or directory in place using your ed25519 key (auto-generated on first use)"),
		flagSet.StringSliceVarP(&options.ExcludePocs, "exclude-pocs", "ep", nil, "pocs to exclude from the scan (comma-separated)", goflags.NormalizedOriginalStringSliceOptions),
		flagSet.StringVarP(&options.ExcludePocsFile, "exclude-pocs-file", "epf", "", "list of pocs to exclude from scan (file)"),
		flagSet.BoolVarP(&options.PocList, "poc-list", "pl", false, "show afrog-pocs list"),
		flagSet.StringVarP(&options.PocDetail, "poc-detail", "pd", "", "show a afrog-pocs detail"),
	)

	flagSet.CreateGroup("select", "Select",
		flagSet.StringVarP(&options.Search, "search", "s", "", "search PoC by keyword , eg: -s tomcat,phpinfo"),
		flagSet.StringVarP(&options.Severity, "severity", "S", "", "pocs to run based on severity. support: info, low, medium, high, critical, unknown"),
		flagSet.StringVar(&options.Sort, "sort", "", "scan sorting: severity|a-z"),
	)

	flagSet.CreateGroup("network", "Network",
		flagSet.IntVar(&options.Timeout, "timeout", 50, "time to wait in seconds before timeout"),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
		flagSet.StringSliceVarP(&options.Header, "header", "H", nil, "custom header/cookie to include in all http request in key:value format (comma separated), eg: -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: JSESSION=xxx;'", goflags.StringSliceOptions),
		flagSet.BoolVar(&options.DefaultAccept, "http-default-accept", true, "add Accept: */* when PoC doesn't set Accept"),
	)

	flagSet.CreateGroup("performance", "Performance",
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 25, "maximum number of afrog-pocs to be executed in parallel"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.ReqLimitPerTarget, "req-limit-per-target", "rlt", 0, "maximum number of requests per second per target (host:port), 0 disables"),
		flagSet.BoolVar(&options.AutoReqLimit, "auto-req-limit", true, "adaptive per-target request limit (host:port), on by default; set -auto-req-limit=false to disable"),
		flagSet.BoolVar(&options.Polite, "polite", false, "use polite per-target request limit (host:port)"),
		flagSet.BoolVar(&options.Balanced, "balanced", false, "use balanced per-target request limit (host:port)"),
		flagSet.BoolVar(&options.Aggressive, "aggressive", false, "use aggressive per-target request limit (host:port)"),
		flagSet.BoolVar(&options.Smart, "smart", false, "intelligent adjustment of concurrency based on changes in the total number of assets being scanned"),
		flagSet.IntVar(&options.MaxHostError, "mhe", 3, "max errors for a host before skipping from scan"),
		flagSet.IntVar(&options.MaxRespBodySize, "mrbs", 2, "max of http response body size"),
		flagSet.IntVar(&options.BruteMaxRequests, "brute-max-requests", 5000, "max brute requests per rule, 0 disables"),
	)

	flagSet.CreateGroup("oob", "OOB",
		flagSet.StringVar(&options.OOB, "oob", "", "set Out-of-Band (OOB) adapter, eg: -oob ceyeio or -oob dnslogcn or -oob alphalog"),
		flagSet.IntVarP(&options.OOBRateLimit, "oob-rate-limit", "orl", 25, "oob poc maximum number of requests to send per second"),
		flagSet.IntVarP(&options.OOBConcurrency, "oob-concurrency", "oc", 25, "oob poc maximum number of afrog-pocs to be executed in parallel"),
		flagSet.IntVar(&options.OOBPollInterval, "oob-poll-interval", 2, "oob polling interval in seconds"),
		flagSet.IntVar(&options.OOBHitRetention, "oob-hit-retention", 10, "oob hit retention in minutes"),
		flagSet.IntVar(&options.OOBFinalizeTimeout, "oob-finalize-timeout", -1, "oob finalize wait timeout in seconds, -1 uses pending timeout (clamped 5-60), 0 disables waiting"),
	)

	flagSet.CreateGroup("stages", "Stages",
		flagSet.BoolVarP(&options.PortScan, "portscan", "ps", false, "enable pre-scan host port scanning for input assets"),
		flagSet.StringVarP(&options.PSPorts, "ports", "p", "top", "ports definition for port pre-scan, e.g. '80,443,1000-2000' or 'top' or 'full' (only the specified ports are scanned)"),
		flagSet.BoolVarP(&options.PSSkipDiscovery, "ps-skip-discovery", "Pn", false, "skip host discovery before port pre-scan"),
		flagSet.IntVarP(&options.PSRateLimit, "ps-rate", "prate", 0, "max concurrent probes across all hosts in port pre-scan (global worker pool size, not a per-second rate)"),
		flagSet.IntVar(&options.PSCPS, "pcps", -1, "max new connections per second in port pre-scan, across all hosts (0 = unlimited, -1 = follow -polite/-balanced/-aggressive; default limits the rate to protect the NAT/conntrack table of the local network)"),
		flagSet.IntVar(&options.PSCPSHost, "pcps-host", -1, "max new connections per second in port pre-scan against a single host (0 = unlimited, -1 = follow -polite/-balanced/-aggressive)"),
		flagSet.BoolVar(&options.PSLinkProbe, "ps-link-probe", true, "measure the default gateway RTT during port pre-scan and ease off the connection rate when the local link saturates; disable with -ps-link-probe=false"),
		flagSet.IntVarP(&options.PSTimeout, "ps-timeout-ms", "ptimeout", 0, "port pre-scan timeout in milliseconds"),
		flagSet.IntVarP(&options.PSRetries, "ps-retries", "ptries", 0, "retries per port in port pre-scan (0 = no retry, the default; raise it only on lossy targets where completeness matters more than speed)"),
		flagSet.IntVar(&options.PSS4Chunk, "ps-s4-chunk", 1000, "port pre-scan s4 chunk size when ports=full"),
		flagSet.IntVar(&options.PSHostConcurrency, "ps-host-concurrency", 0, "max concurrent probes against a single host in port pre-scan (0 = module default)"),
		flagSet.BoolVar(&options.PSNoAdaptiveTimeout, "ps-no-adaptive-timeout", false, "disable RTT-adaptive connect timeout in port pre-scan"),
		flagSet.BoolVar(&options.PSServiceProbe, "ps-service-probe", false, "send active service probes (application payloads) during port pre-scan to identify services more accurately"),
		flagSet.StringVar(&options.PSFingerprintDir, "ps-fingerprint-dir", "", "directory with probes.yaml/services.yaml/ports.yaml overriding the built-in port fingerprint set"),
		flagSet.BoolVar(&options.PSReportStates, "ps-states", false, "report closed/filtered ports as results in port pre-scan (default: report only open ports)"),
		flagSet.BoolVar(&options.EnableWebProbe, "w", true, "collect web asset info (url/status/title/server/tech-stack fingerprint) before scanning; enabled by default, disable with -w=false"),
		flagSet.StringVar(&options.WebFingerprintDir, "w-fingerprint-dir", "", "directory with rules.yaml overriding the built-in web fingerprint set"),
		flagSet.BoolVar(&options.WebFavicon, "w-favicon", false, "fetch /favicon.ico during web probe to match favicon rules (adds one extra request per target)"),
		flagSet.IntVar(&options.WebProbeTimeout, "w-timeout", 30, "web probe timeout in seconds for each request and certificate fetch, independent of the global -timeout"),
		flagSet.BoolVar(&options.DisableFingerprint, "nf", false, "disable fingerprint stage (skip PoCs tagged 'fingerprint')"),
		flagSet.StringVar(&options.FingerprintFilterMode, "fingerprint-filter-mode", "strict", "fingerprint filter mode for app-specific PoCs: strict|opportunistic"),
		flagSet.BoolVar(&options.MonitorTargets, "mt", false, "enable the monitor-target feature during scanning"),
		flagSet.BoolVar(&options.VulnerabilityScannerBreakpoint, "vsb", false, "Once a vulnerability is detected, the scanning program will immediately halt the scan and report the identified vulnerability."),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "write to the HTML file, including all vulnerability results"),
		flagSet.StringVarP(&options.Json, "json", "j", "", "write to the JSON file, but it will not include the request and response content"),
		flagSet.StringVarP(&options.JsonAll, "json-all", "ja", "", "write to the JSON file, including all vulnerability results"),
		flagSet.BoolVarP(&options.DisableOutputHtml, "disable-output-html", "doh", false, "disable the automatic generation of HTML reports (higher priority than the -o command)"),
		flagSet.BoolVar(&options.NoSaveDB, "no-save-db", false, "do not write vulnerability results into the sqlite database (test scans; keeps the report and ledger clean)"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVar(&options.Silent, "silent", false, "only results only"),
		flagSet.BoolVar(&options.LiveStats, "live-stats", false, "render live stats in a single-line status display"),
		flagSet.BoolVar(&options.JsonStream, "json-stream", false, "以 NDJSON 事件流输出到 stdout，供程序消费"),
	)

	flagSet.CreateGroup("pedm", "PEDM",
		flagSet.BoolVar(&options.PocExecutionDurationMonitor, "pedm", false, "enable PoC Execution Duration Monitor (PEDM)"),
		flagSet.IntVar(&options.PedmLogLimit, "pedm-log-limit", 0, "print the first N started PoC tasks, 0 disables"),
		flagSet.IntVar(&options.PedmSlowThresholdSec, "pedm-slow-sec", 30, "print running/completed slow PoC tasks at or above this threshold in seconds, 0 disables"),
		flagSet.IntVar(&options.PedmSlowLogLimit, "pedm-slow-log-limit", 20, "maximum completed slow-task logs to print, 0 disables completed slow-task logs"),
		flagSet.IntVar(&options.PedmSummaryTop, "pedm-summary-top", 10, "print top N slowest PoCs and target+PoC pairs when scan ends, 0 disables summary"),
		flagSet.StringVar(&options.PedmSummaryBy, "pedm-summary-by", "max", "PEDM summary sort key: max|avg"),
		flagSet.IntVar(&options.TaskHardTimeoutSec, "task-hard-timeout-sec", 0, "hard timeout for one target+PoC task in seconds, 0 disables"),
		flagSet.BoolVar(&options.TaskSmartTimeout, "task-smart-timeout", false, "estimate per-PoC task timeout from PoC content and use it as the primary hard timeout"),
		flagSet.IntVar(&options.TaskTimeoutVisibleCapSec, "task-timeout-visible-cap-sec", 300, "maximum smart timeout for regular HTTP PoCs"),
		flagSet.IntVar(&options.TaskTimeoutNetCapSec, "task-timeout-net-cap-sec", 360, "maximum smart timeout for tcp/udp/ssl PoCs"),
		flagSet.IntVar(&options.TaskTimeoutGoCapSec, "task-timeout-go-cap-sec", 420, "maximum smart timeout for go PoCs"),
		flagSet.IntVar(&options.JsScriptTimeout, "js-script-timeout", 60, "maximum execution time for one javascript PoC script in seconds, 0 disables"),
		flagSet.BoolVar(&options.EnableJSPoc, "enable-js-poc", true, "enable javascript PoC execution (enabled by default; set -enable-js-poc=false to disable running script code from PoC files)"),
		flagSet.BoolVar(&options.RequireSignedJSPoc, "require-signed-js-poc", false, "skip javascript PoCs whose signature is missing or invalid (lenient by default: verify if present, warn only)"),
	)

	flagSet.CreateGroup("debug", "Debug & Tools",
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests, responses and phase logs"),
		flagSet.BoolVar(&options.Test, "test", false, "test mode (requires gating disabled)"),
		flagSet.StringVar(&options.Validate, "validate", "", "validate POC YAML syntax, support file or directory"),
		flagSet.BoolVarP(&options.Version, "version", "v", false, "show afrog version"),
	)

	flagSet.CreateGroup("services", "Services & Integrations",
		flagSet.BoolVar(&options.Web, "web", false, "Start a web server."),
		flagSet.BoolVar(&options.Dingtalk, "dingtalk", false, "Start a dingtalk webhook."),
		flagSet.BoolVar(&options.Wecom, "wecom", false, "Start a wecom webhook."),
	)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVar(&options.ConfigFile, "config", "", "path to the afrog configuration file"),
	)

	flagSet.CreateGroup("curated", "Curated",
		flagSet.StringVar(&options.CuratedEnabled, "curated", "", "curated pocs mode: auto|on|off"),
		flagSet.StringVar(&options.CuratedEndpoint, "curated-endpoint", "", "curated service endpoint"),
		flagSet.IntVar(&options.CuratedTimeout, "curated-timeout", 0, "curated mount timeout seconds"),
		flagSet.BoolVar(&options.CuratedForceUpdate, "curated-force-update", false, "force curated pocs update check now"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVarP(&options.Update, "update", "un", false, "update afrog engine to the latest released version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic afrog-pocs update check"),
	)

	_ = flagSet.Parse()

	// 记录显式传入的 flag，供 VerifyOptions 区分「默认值」与「用户指定」。
	options.setFlags = make(map[string]bool)
	flagSet.CommandLine.Visit(func(f *flag.Flag) { options.setFlags[f.Name] = true })

	if err := options.VerifyOptions(); err != nil {
		return options, err
	}

	return options, nil
}

// ResolvePortScanRates 把端口扫描的限速档位落成具体数值。
//
// 为什么端口扫描默认要限速：并发上限约束的是「同时有多少条连接在飞」，约束不了
// 「每秒新开多少条连接」。500 并发在 1ms RTT 的内网里理论上限是 50 万连接/秒，而
// 出口设备的 NAT/conntrack 会话表通常只有几千条；被过滤的端口不回包，表项要挂到
// 30~120s 超时才释放，表满之后同网段所有人的新建连接都会失败。默认档（全局 1000、
// 单目标 100）把压力压到常见家用/办公路由能承受的量级，需要打满时用 -aggressive
// 或 -pcps 0 显式放开。
func (opt *Options) ResolvePortScanRates() {
	if opt.PSCPS >= 0 && opt.PSCPSHost >= 0 {
		return
	}
	var global, perHost int
	switch {
	case opt.Polite:
		global, perHost = portscan.PresetPoliteGlobalCPS, portscan.PresetPolitePerHostCPS
	case opt.Aggressive:
		global, perHost = 0, 0 // 显式要求不限速
	default:
		// -balanced 与未指定档位同为默认档。
		global, perHost = portscan.DefaultGlobalCPS, portscan.DefaultPerHostCPS
	}
	if opt.PSCPS < 0 {
		opt.PSCPS = global
	}
	if opt.PSCPSHost < 0 {
		opt.PSCPSHost = perHost
	}
}

// deriveAutoStartRate 推导自适应限速的起始速率：与 -rl 挂钩，并按并发做保守收敛。
//
// 起速只是起点——健康目标会在运行时被加性抬升，劣化目标会被乘性压低；这一步只决定
// 开局不要把压力给太满。
func deriveAutoStartRate(opt *Options) int {
	baseRate := opt.RateLimit
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
	con := opt.Concurrency
	if con <= 0 {
		con = 1
	}
	// 并发越高，单目标起速越保守，避免多目标同时起步时瞬间堆叠连接。
	if con >= 100 && r > 8 {
		r = 8
	} else if con >= 50 && r > 12 {
		r = 12
	}
	return r
}

// resolveRequestLimitMode 把用户的限速选择落成 ReqLimitPerTarget / AutoReqLimit 两个字段。
// 优先级：显式指定 > 默认走自适应。
//
// 为什么要看 setFlags：-auto-req-limit 现在默认开启，而 -rlt 的 0 值既可能是
// 「用户明确要求不限速」，也可能只是「没设置」。只有知道 flag 是否被显式传入，
// 才能正确区分这两者，否则 -rlt 0 会把默认的自适应误当成「不限速」。
func (opt *Options) resolveRequestLimitMode() error {
	explicitRlt := opt.setFlags["req-limit-per-target"]
	explicitAuto := opt.setFlags["auto-req-limit"]

	presetCount := 0
	if opt.Polite {
		presetCount++
	}
	if opt.Balanced {
		presetCount++
	}
	if opt.Aggressive {
		presetCount++
	}
	if presetCount > 1 {
		return fmt.Errorf("only one of --polite/--balanced/--aggressive can be used")
	}
	if opt.ReqLimitPerTarget < 0 {
		return fmt.Errorf("--req-limit-per-target must be >= 0")
	}

	// 三个互斥的显式档位最多只能选一个。
	chosen := 0
	if explicitRlt {
		chosen++
	}
	if explicitAuto && opt.AutoReqLimit {
		chosen++
	}
	if presetCount > 0 {
		chosen++
	}
	if chosen > 1 {
		return fmt.Errorf("only one of --req-limit-per-target/--auto-req-limit/--polite/--balanced/--aggressive can be used")
	}

	switch {
	case explicitRlt:
		// 用户显式给了 -rlt：>0 为固定速率，0 为完全不限速。
		opt.AutoReqLimit = false
	case presetCount > 0:
		opt.AutoReqLimit = false
		switch {
		case opt.Polite:
			opt.ReqLimitPerTarget = 5
		case opt.Balanced:
			opt.ReqLimitPerTarget = 15
		default:
			opt.ReqLimitPerTarget = 50
		}
	case opt.AutoReqLimit:
		// 默认档：自适应限速。起速保守，运行时由 AIMD 依据目标状态升降，
		// 上限由 runner 放开到全局速率，健康目标基本不受限。
		opt.ReqLimitPerTarget = deriveAutoStartRate(opt)
	default:
		// 显式 -auto-req-limit=false：完全不限速。
		opt.ReqLimitPerTarget = 0
	}
	return nil
}

func (opt *Options) VerifyOptions() error {

	// -silent 面向「只取结果」的场景（常见于老旧终端/日志管道），这里同样关闭 ANSI 着色：
	// 旧终端会把转义序列渲染成乱码，反而看不清结果。
	if opt.NoColor || opt.Silent {
		log.EnableColor = false
		// 日志分级标签（[WRN]/[ERR]）由 gologger 自己着色，与 log.EnableColor 无关，需一并关闭。
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}

	if len(opt.Validate) > 0 {
		validator.ValidatePocFiles(opt.Validate)
		os.Exit(0)
	}

	if strings.TrimSpace(opt.PocMigrate) != "" {
		r, err := poc.MigrateLegacyPocs(opt.PocMigrate)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("seen=%d changed=%d changes=%d\n", r.FilesSeen, r.FilesChanged, r.Changes)
		os.Exit(0)
	}

	if strings.TrimSpace(opt.PocSign) != "" {
		priv, err := pocsign.ResolveSigningKey()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		n, err := pocsign.SignPath(opt.PocSign, priv)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pub := pocsign.PublicKeyOf(priv)
		fmt.Printf("signed=%d key=%s\n", n, pocsign.Fingerprint(pub))
		fmt.Printf("pubkey=%s\n", pocsign.EncodePublicKeyB64(pub))
		os.Exit(0)
	}

	// update afrog-pocs
	au, err := NewAfrogUpdate(true)
	if err != nil {
		return err
	}
	opt.AfrogUpdate = au

	if !opt.DisableUpdateCheck {
		info, _ := au.AfrogUpdatePocs()
		if len(info) > 0 && opt.UpdatePocs {
			gologger.Info().Msg(info)
		}
	}

	if opt.Version {
		ShowVersion()
		os.Exit(0)
	}

	config, err := NewConfig(opt.ConfigFile)
	if err != nil {
		return err
	}
	opt.Config = config

	if opt.Config != nil {
		if v := strings.TrimSpace(opt.CuratedEnabled); v != "" {
			opt.Config.Curated.Enabled = v
		}
		if v := strings.TrimSpace(opt.CuratedEndpoint); v != "" {
			opt.Config.Curated.Endpoint = v
		}
		if opt.CuratedTimeout > 0 {
			opt.Config.Curated.TimeoutSec = opt.CuratedTimeout
		}
		normalizeCuratedDefaults(opt.Config)
	}

	if err := sqlite.NewWebSqliteDB(); err != nil {
		return fmt.Errorf("init sqlite db error: %v", err)
	}

	if opt.Dingtalk {
		if dingtalk.IsTokensEmpty(opt.Config.Webhook.Dingtalk.Tokens) {
			return fmt.Errorf("Dingtalk webhook token is required")
		}
	}

	if opt.Wecom {
		if wecom.IsTokensEmpty(opt.Config.Webhook.Wecom.Tokens) {
			return fmt.Errorf("Wecom webhook token is required")
		}
	}

	if opt.Web {
		return nil
	}

	opt.FingerprintFilterMode = strings.ToLower(strings.TrimSpace(opt.FingerprintFilterMode))
	if opt.FingerprintFilterMode == "" {
		opt.FingerprintFilterMode = "strict"
	}
	if opt.FingerprintFilterMode != "strict" && opt.FingerprintFilterMode != "opportunistic" {
		opt.FingerprintFilterMode = "strict"
	}

	opt.PedmSummaryBy = strings.ToLower(strings.TrimSpace(opt.PedmSummaryBy))
	if opt.PedmSummaryBy == "" {
		opt.PedmSummaryBy = "max"
	}
	if opt.PedmSummaryBy != "max" && opt.PedmSummaryBy != "avg" {
		opt.PedmSummaryBy = "max"
	}
	if opt.PedmLogLimit < 0 {
		return fmt.Errorf("--pedm-log-limit must be >= 0")
	}
	if opt.PedmSlowThresholdSec < 0 {
		return fmt.Errorf("--pedm-slow-sec must be >= 0")
	}
	if opt.PedmSlowLogLimit < 0 {
		return fmt.Errorf("--pedm-slow-log-limit must be >= 0")
	}
	if opt.PedmSummaryTop < 0 {
		return fmt.Errorf("--pedm-summary-top must be >= 0")
	}
	if opt.TaskHardTimeoutSec < 0 {
		return fmt.Errorf("--task-hard-timeout-sec must be >= 0")
	}
	if opt.JsScriptTimeout < 0 {
		return fmt.Errorf("--js-script-timeout must be >= 0")
	}
	if opt.TaskTimeoutVisibleCapSec <= 0 {
		return fmt.Errorf("--task-timeout-visible-cap-sec must be > 0")
	}
	if opt.TaskTimeoutNetCapSec <= 0 {
		return fmt.Errorf("--task-timeout-net-cap-sec must be > 0")
	}
	if opt.TaskTimeoutGoCapSec <= 0 {
		return fmt.Errorf("--task-timeout-go-cap-sec must be > 0")
	}
	if opt.OOBFinalizeTimeout < -1 {
		return fmt.Errorf("--oob-finalize-timeout must be >= -1")
	}
	if opt.OOBFinalizeTimeout > 3600 {
		return fmt.Errorf("--oob-finalize-timeout must be <= 3600")
	}

	if err := opt.resolveRequestLimitMode(); err != nil {
		return err
	}

	opt.ResolvePortScanRates()

	// init append poc
	if len(opt.AppendPoc) > 0 {
		poc.InitLocalAppendList(opt.AppendPoc)
	}

	// init test poc
	if len(opt.PocFile) > 0 {
		poc.InitLocalTestList([]string{opt.PocFile})
		// 修复 afrog 工具中使用 -P 命令指定不存在的YAML文件时，会错误地扫描所有PoC文件的问题 @edit 2024/08/09
		if len(poc.LocalTestList) == 0 {
			gologger.Error().Msg("Unable to locate a valid afrog PoC YAML file.")
			os.Exit(0)
		}
	}

	// initialized embed poc、local poc and append poc
	if len(pocs.EmbedFileList) == 0 && len(poc.LocalFileList) == 0 && len(poc.LocalAppendList) == 0 && len(poc.LocalTestList) == 0 {
		return fmt.Errorf("PoCs is not empty")
	}

	if opt.PocList {
		err := opt.PrintPocList()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	if len(opt.PocDetail) > 0 {
		opt.ReadPocDetail()
		os.Exit(0)
	}

	if opt.Update {
		err := updateEngine()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	if !(len(opt.Target) > 0 || len(opt.TargetsFile) > 0 || (len(opt.Cyberspace) > 0 && len(opt.Query) > 0)) {
	}

	return nil
}

func (o *Options) SetSearchKeyword() bool {
	o.SearchKeywords = o.SearchKeywords[:0]
	if strings.TrimSpace(o.Search) == "" {
		return false
	}
	for _, v := range strings.Split(o.Search, ",") {
		k := strings.ToLower(strings.TrimSpace(v))
		if k == "" {
			continue
		}
		o.SearchKeywords = append(o.SearchKeywords, k)
	}
	return len(o.SearchKeywords) > 0
}

func (o *Options) CheckPocKeywords(id, name, tags string) bool {
	if len(o.SearchKeywords) > 0 {
		idLower := strings.ToLower(id)
		nameLower := strings.ToLower(name)
		tagsLower := strings.ToLower(tags)
		for _, v := range o.SearchKeywords {
			if strings.Contains(idLower, v) || strings.Contains(nameLower, v) || strings.Contains(tagsLower, v) {
				return true
			}
		}
	}
	return false
}

func (o *Options) SetSeverityKeyword() bool {
	if len(o.Severity) > 0 {
		arr := strings.Split(o.Severity, ",")
		if len(arr) > 0 {
			for _, v := range arr {
				o.SeverityKeywords = append(o.SeverityKeywords, strings.TrimSpace(v))
			}
			return true
		}
	}
	return false
}

func (o *Options) CheckPocSeverityKeywords(severity string) bool {
	if len(o.SeverityKeywords) > 0 {
		for _, v := range o.SeverityKeywords {
			if strings.EqualFold(severity, v) {
				return true
			}
		}
	}
	return false
}

func (o *Options) FilterPocSeveritySearch(pocId, pocInfoName, pocTags, severity string) bool {
	var isShow bool
	if len(o.Search) > 0 && o.SetSearchKeyword() && len(o.Severity) > 0 && o.SetSeverityKeyword() {
		if o.CheckPocKeywords(pocId, pocInfoName, pocTags) && o.CheckPocSeverityKeywords(severity) {
			isShow = true
		}
	} else if len(o.Severity) > 0 && o.SetSeverityKeyword() {
		if o.CheckPocSeverityKeywords(severity) {
			isShow = true
		}
	} else if len(o.Search) > 0 && o.SetSearchKeyword() {
		if o.CheckPocKeywords(pocId, pocInfoName, pocTags) {
			isShow = true
		}
	} else {
		isShow = true
	}
	return isShow
}

func filterPocSeveritySearchWithFingerprint(search, severityFilter, pocID, pocName, pocSeverity, pocTags string) bool {
	searchKeywords := make([]string, 0)
	if strings.TrimSpace(search) != "" {
		for _, v := range strings.Split(search, ",") {
			k := strings.ToLower(strings.TrimSpace(v))
			if k == "" {
				continue
			}
			searchKeywords = append(searchKeywords, k)
		}
	}
	severityKeywords := make([]string, 0)
	if strings.TrimSpace(severityFilter) != "" {
		for _, v := range strings.Split(severityFilter, ",") {
			k := strings.ToLower(strings.TrimSpace(v))
			if k == "" {
				continue
			}
			severityKeywords = append(severityKeywords, k)
		}
	}

	isFingerprint := func(tags string) bool {
		for _, t := range strings.Split(strings.ToLower(tags), ",") {
			if strings.TrimSpace(t) == "fingerprint" {
				return true
			}
		}
		return false
	}

	matchKeyword := func(id, name, tags string) bool {
		if len(searchKeywords) == 0 {
			return true
		}
		idLower := strings.ToLower(id)
		nameLower := strings.ToLower(name)
		tagsLower := strings.ToLower(tags)
		for _, k := range searchKeywords {
			if strings.Contains(idLower, k) || strings.Contains(nameLower, k) || strings.Contains(tagsLower, k) {
				return true
			}
		}
		return false
	}

	matchSeverity := func(sev string) bool {
		if len(severityKeywords) == 0 {
			return true
		}
		sevLower := strings.ToLower(strings.TrimSpace(sev))
		for _, s := range severityKeywords {
			if sevLower == s {
				return true
			}
		}
		return false
	}

	if len(searchKeywords) == 0 && len(severityKeywords) == 0 {
		return true
	}
	if !matchKeyword(pocID, pocName, pocTags) {
		return false
	}
	if matchSeverity(pocSeverity) {
		return true
	}
	return isFingerprint(pocTags)
}

func (o *Options) PrintPocList() error {
	// 使用仓库层统一路径整合（包含 curated/my/append/local/builtin），仅按元信息读取，避免全量解析带来的 YAML panic
	pathItems, _ := pocsrepo.CollectOrderedPocPaths(o.AppendPoc)

	// 分组：embed, local, append, curated, my
	type metaItem struct {
		ID       string
		Name     string
		Severity string
		Authors  []string
	}
	groups := map[string][]metaItem{
		"embed":   {},
		"local":   {},
		"append":  {},
		"curated": {},
		"my":      {},
	}

	excludePocs, _ := o.parseExcludePocs()

	// 读取元信息并过滤
	for _, it := range pathItems {
		src := ""
		switch it.Source {
		case pocsrepo.SourceBuiltin:
			src = "embed"
		case pocsrepo.SourceLocal:
			src = "local"
		case pocsrepo.SourceAppend:
			src = "append"
		case pocsrepo.SourceCurated:
			src = "curated"
		case pocsrepo.SourceMy:
			src = "my"
		default:
			continue
		}

		var (
			id, name, tags, severity string
			authors                  []string
			err                      error
		)

		if it.Source == pocsrepo.SourceBuiltin {
			// 嵌入式路径以 embedded: 前缀，读取元信息
			path := strings.TrimPrefix(it.Path, "embedded:")
			pm, e := pocs.EmbedReadPocMetaByPath(path)
			err = e
			if err == nil {
				id = pm.Id
				name = pm.Info.Name
				tags = pm.Info.Tags
				severity = pm.Info.Severity
				authors = pocsrepo.SplitAuthors(pm.Info.Author)
			}
		} else {
			pm, e := poc.LocalReadPocMetaByPath(it.Path)
			err = e
			if err == nil {
				id = pm.Id
				name = pm.Info.Name
				tags = pm.Info.Tags
				severity = pm.Info.Severity
				authors = pocsrepo.SplitAuthors(pm.Info.Author)
			}
		}

		if err != nil {
			gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", it.Path, err)
			continue
		}

		// 保留原有过滤逻辑
		if !o.FilterPocSeveritySearch(id, name, tags, severity) {
			continue
		}
		// 排除列表
		excluded := false
		for _, ep := range excludePocs {
			v := strings.ToLower(ep)
			if strings.Contains(strings.ToLower(id), v) || strings.Contains(strings.ToLower(name), v) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		groups[src] = append(groups[src], metaItem{
			ID:       id,
			Name:     name,
			Severity: severity,
			Authors:  authors,
		})
	}

	// 对每个分组按严重级别排序并可选 a-z 排序（与扫描保持一致）
	severityOrder := []string{"info", "low", "medium", "high", "critical"}
	severitySort := func(list []metaItem) []metaItem {
		latest := []metaItem{}
		included := make(map[int]struct{})
		for _, sev := range severityOrder {
			for i, s := range list {
				if sev == strings.ToLower(s.Severity) {
					latest = append(latest, s)
					included[i] = struct{}{}
				}
			}
		}
		for i, s := range list {
			if _, ok := included[i]; !ok {
				latest = append(latest, s)
			}
		}
		if o.Sort == "a-z" {
			sort.Slice(latest, func(i, j int) bool {
				return latest[i].ID < latest[j].ID
			})
		}
		return latest
	}
	for k, v := range groups {
		groups[k] = severitySort(v)
	}

	// 增强分组展示样式：分段标题 + 计数，更醒目
	orderGroups := []string{"embed", "local", "append", "curated", "my"}
	groupDisplay := map[string]string{
		"embed":   "EMBED (嵌入)",
		"local":   "LOCAL (本地)",
		"append":  "APPEND (追加)",
		"curated": "CURATED (精选)",
		"my":      "MY (我的)",
	}

	total := 0
	for _, g := range orderGroups {
		total += len(groups[g])
	}

	number := 1
	for _, g := range orderGroups {
		if len(groups[g]) == 0 {
			continue
		}
		gologger.Print().Msgf("\n======== %s Count: %d ========\n", groupDisplay[g], len(groups[g]))
		for _, p := range groups[g] {
			gologger.Print().Msgf("%s [%s][%s][%s] author:%s\n",
				log.LogColor.Time(number),
				log.LogColor.Title(p.ID),
				log.LogColor.Green(p.Name),
				log.LogColor.GetColor(p.Severity, p.Severity),
				strings.Join(p.Authors, ","),
			)
			number++
		}
	}

	gologger.Print().Msgf("\n==============================================\n")
	gologger.Print().Msgf("Total: %d\n", total)

	return nil
}

func (o *Options) ReadPocDetail() {
	if content, err := pocs.EmbedReadContentByName(o.PocDetail); err == nil && len(content) > 0 {
		gologger.Print().Msgf("%s\n", string(content))
		return
	}
	if content, err := poc.LocalReadContentByName(o.PocDetail); err == nil && len(content) > 0 {
		gologger.Print().Msgf("%s\n", string(content))
		return
	}
}

func (o *Options) ReversePoCs(allpocs []poc.Poc) ([]poc.Poc, []poc.Poc) {
	result := []poc.Poc{}
	other := []poc.Poc{}
	for _, poc := range allpocs {
		flag := pocUsesOOB(poc)
		if flag {
			result = append(result, poc)
		} else {
			other = append(other, poc)
		}
	}
	return result, other
}

func pocUsesOOB(p poc.Poc) bool {
	if containsOOBToken(p.Expression) {
		return true
	}
	for _, it := range p.Set {
		if s, ok := it.Value.(string); ok && containsOOBToken(s) {
			return true
		}
	}
	for _, rm := range p.Rules {
		r := rm.Value
		if containsOOBToken(r.Expression) {
			return true
		}
		for _, e := range r.Expressions {
			if containsOOBToken(e) {
				return true
			}
		}
		req := r.Request
		if containsOOBToken(req.Path) || containsOOBToken(req.Host) || containsOOBToken(req.Body) || containsOOBToken(req.Raw) || containsOOBToken(req.Data) {
			return true
		}
		for _, hv := range req.Headers {
			if containsOOBToken(hv) {
				return true
			}
		}
	}
	return false
}

func containsOOBToken(s string) bool {
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	return strings.Contains(l, "oobcheck(") ||
		strings.Contains(l, "oobchecktoken(") ||
		strings.Contains(l, "oobevidence(") ||
		strings.Contains(l, "{{oob") ||
		strings.Contains(l, "{{ oob") ||
		strings.Contains(l, "oob_") ||
		strings.Contains(l, "oob.") ||
		strings.Contains(l, "oob()")
}

func (o *Options) FingerprintPoCs(allpocs []poc.Poc) ([]poc.Poc, []poc.Poc) {
	finger := make([]poc.Poc, 0)
	other := make([]poc.Poc, 0)

	for _, p := range allpocs {
		tags := strings.Split(strings.ToLower(p.Info.Tags), ",")
		isFinger := false
		for _, t := range tags {
			if strings.TrimSpace(t) == "fingerprint" {
				isFinger = true
				break
			}
		}
		if isFinger {
			finger = append(finger, p)
		} else {
			other = append(other, p)
		}
	}
	return finger, other
}

var legacyOOBCheckRe = regexp.MustCompile(`(?i)\boobcheck\s*\(\s*oob\s*,`)
var legacyOOBCheckTokenRe = regexp.MustCompile(`(?i)\boobchecktoken\s*\(`)
var legacyOOBWaitRe = regexp.MustCompile(`(?i)\boobwait\s*\(`)
var legacyOOBVarsRe = regexp.MustCompile(`(?i)\{\{\s*oobdns\s*\}\}|\{\{\s*oobhttp\s*\}\}`)
var legacyOOBSetInitRe = regexp.MustCompile(`(?im)^\s*oob\s*:\s*oob\(\)\s*$`)

func stripYAMLLineCommentLegacy(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

func stripYAMLCommentsLegacy(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	var b strings.Builder
	b.Grow(len(s))
	for i, line := range lines {
		b.WriteString(stripYAMLLineCommentLegacy(line))
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func detectLegacyOOBReasons(yamlText string) []string {
	src := stripYAMLCommentsLegacy(yamlText)
	reasons := make([]string, 0, 4)

	if legacyOOBVarsRe.MatchString(src) {
		reasons = append(reasons, "旧占位符 {{oobDNS}}/{{oobHTTP}}")
	}
	if legacyOOBCheckRe.MatchString(src) {
		reasons = append(reasons, "旧函数签名 oobCheck(oob, ...)")
	}
	if legacyOOBCheckTokenRe.MatchString(src) {
		reasons = append(reasons, "旧函数 oobCheckToken(...)")
	}
	if legacyOOBWaitRe.MatchString(src) {
		reasons = append(reasons, "旧函数 oobWait(...)")
	}
	if legacyOOBSetInitRe.MatchString(src) && len(reasons) > 0 {
		reasons = append(reasons, "旧初始化 set: oob: oob()")
	}
	return reasons
}

// AllowsCapability 判断当前配置是否允许执行指定能力等级的 PoC。
//
// 目前只区分两档：declarative 一律允许；network（javascript）跟随 -enable-js-poc；
// exec（本机命令执行）能力尚未实现，先一律拒绝——将来接上时只需改这里。
func (o *Options) AllowsCapability(level capability.Level) bool {
	switch {
	case level <= capability.Declarative:
		return true
	case level == capability.Network:
		return o.EnableJSPoc
	default:
		return false
	}
}

// CreatePocList 返回本次扫描要执行的 PoC 列表。
// 加载过程中被跳过的 PoC 会被丢弃，如需诊断信息请使用 CreatePocListWithDiagnostics。
func (o *Options) CreatePocList() []poc.Poc {
	pocList, _ := o.CreatePocListWithDiagnostics()
	return pocList
}

// CreatePocListWithDiagnostics 在返回 PoC 列表的同时，返回所有被跳过的 PoC 及其原因。
func (o *Options) CreatePocListWithDiagnostics() ([]poc.Poc, []PocLoadError) {
	type legacyItem struct {
		ID      string
		Path    string
		Reasons []string
	}

	pathItems, diagnostics := o.resolvePocPathItems()

	newPocSlice := make([]poc.Poc, 0, len(pathItems))
	legacy := make([]legacyItem, 0)
	jsReport := jsLoadReport{}
	verifier := pocsign.DefaultVerifier()

	for _, it := range pathItems {
		var (
			raw     []byte
			srcPath string
			err     error
		)

		if it.Source == pocsrepo.SourceBuiltin {
			srcPath = strings.TrimPrefix(it.Path, "embedded:")
			raw, err = pocs.EmbedReadContentByPath(srcPath)
		} else {
			srcPath = it.Path
			raw, err = os.ReadFile(srcPath)
		}
		if err != nil {
			diagnostics = append(diagnostics, PocLoadError{Path: it.Path, Reason: PocLoadReadFailed, Err: err})
			o.logPocDiscarded(srcPath, err)
			continue
		}

		pm := poc.PocMeta{}
		if e := yaml.Unmarshal(raw, &pm); e != nil {
			diagnostics = append(diagnostics, PocLoadError{Path: it.Path, Reason: PocLoadParseFailed, Err: e})
			o.logPocDiscarded(srcPath, e)
			continue
		}
		id := strings.TrimSpace(pm.Id)
		if id == "" {
			id = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(srcPath), ".yaml"), ".yml")
		}

		if !filterPocSeveritySearchWithFingerprint(o.Search, o.Severity, id, pm.Info.Name, pm.Info.Severity, pm.Info.Tags) {
			continue
		}

		reasons := detectLegacyOOBReasons(string(raw))
		if len(reasons) > 0 {
			legacy = append(legacy, legacyItem{ID: id, Path: srcPath, Reasons: reasons})
			diagnostics = append(diagnostics, PocLoadError{
				Path:   it.Path,
				ID:     id,
				Reason: PocLoadLegacyOOB,
				Detail: strings.Join(reasons, "; "),
			})
			continue
		}

		pp := poc.Poc{}
		if e := yaml.Unmarshal(raw, &pp); e != nil {
			diagnostics = append(diagnostics, PocLoadError{Path: it.Path, ID: id, Reason: PocLoadParseFailed, Err: e})
			o.logPocDiscarded(srcPath, e)
			continue
		}
		pp.Id = strings.TrimSpace(pp.Id)
		if pp.Id == "" {
			pp.Id = id
		}
		// 能力策略：declarative 一律放行；network（javascript）跟随 -enable-js-poc；
		// 将来的 exec 一档由 AllowsCapability 统一决定，这里无需改动。
		capLevel := pp.Capability()
		if !o.AllowsCapability(capLevel) {
			jsReport.disabled = append(jsReport.disabled, pp.Id)
			diagnostics = append(diagnostics, PocLoadError{
				Path:   it.Path,
				ID:     pp.Id,
				Reason: PocLoadJSPocDisabled,
				Detail: fmt.Sprintf("capability %q is not allowed (javascript: -enable-js-poc)", capLevel),
			})
			continue
		}
		if capLevel >= capability.Network {
			// 信任轴：仅在带代码/特权能力的 PoC 上做签名校验。
			// 宽松模式：有签名则验，验不过只告警；严格模式：未签名/签名无效一律跳过。
			sig, content, sigErr := pocsign.ExtractSignature(raw)
			signed := sigErr == nil && verifier.Verify(content, sig)
			if !signed && sigErr == nil {
				jsReport.invalid++
			}
			if !signed && o.RequireSignedJSPoc {
				jsReport.unsigned = append(jsReport.unsigned, pp.Id)
				diagnostics = append(diagnostics, PocLoadError{
					Path:   it.Path,
					ID:     pp.Id,
					Reason: PocLoadUnsignedJSPoc,
					Detail: "javascript PoC signature missing or invalid (strict mode: -require-signed-js-poc)",
				})
				continue
			}
		}
		if o.TaskSmartTimeout {
			estimate := poc.EstimateTaskTimeout(pp, poc.TaskTimeoutPolicy{
				VisibleCapSec: o.TaskTimeoutVisibleCapSec,
				NetCapSec:     o.TaskTimeoutNetCapSec,
				GoCapSec:      o.TaskTimeoutGoCapSec,
			})
			pp.EstimatedTaskTimeoutSec = estimate.TimeoutSec
			pp.EstimatedTaskTimeoutReason = estimate.Reason
		}
		newPocSlice = append(newPocSlice, pp)
	}

	if len(legacy) > 0 && !o.consoleQuiet() {
		total := len(legacy)
		const limit = 20
		gologger.Print().Msgf("检测到旧OOB POC（已跳过）：%d 个", total)
		n := total
		if n > limit {
			n = limit
		}
		for i := 0; i < n; i++ {
			it := legacy[i]
			gologger.Print().Msgf("- %s (%s)", it.ID, strings.Join(it.Reasons, "; "))
		}
		if total > n {
			gologger.Print().Msgf("+ %d more", total-n)
		}
		gologger.Print().Msg("建议：使用 -pocmigrate 迁移旧语法")
	}

	// javascript 加载汇总只记录、不在此处打印：由 PrintJSReport 在启动横幅
	// （Core/POC/Cur/OOB）之后统一输出，避免把这组横幅打断。
	o.jsReport = jsReport

	// 按严重级别排序但保留未设置 severity 的 POC
	latestPocSlice := []poc.Poc{}
	included := make(map[int]struct{})
	order := []string{"info", "low", "medium", "high", "critical"}
	for _, sev := range order {
		for i, s := range newPocSlice {
			if sev == strings.ToLower(s.Info.Severity) {
				latestPocSlice = append(latestPocSlice, s)
				included[i] = struct{}{}
			}
		}
	}
	for i, s := range newPocSlice {
		if _, ok := included[i]; !ok {
			latestPocSlice = append(latestPocSlice, s)
		}
	}

	// 排除列表（与 -pl 保持一致）
	excludePocs, _ := o.parseExcludePocs()
	finalPocSlice := []poc.Poc{}
	for _, pp := range latestPocSlice {
		if !isExcludePoc(pp, excludePocs) {
			finalPocSlice = append(finalPocSlice, pp)
		}
	}

	if o.Sort == "a-z" {
		sort.Sort(POCSlices(finalPocSlice))
	}

	return finalPocSlice, diagnostics
}

// consoleQuiet 表示当前不应该向控制台输出内容（SDK 模式或显式静默）。
func (o *Options) consoleQuiet() bool {
	return o != nil && (o.SDKMode || o.Silent)
}

// jsLoadReport 汇总一次 PoC 加载中与 javascript 相关的统计。
// 这些信息统一在启动横幅（Core/POC/Cur/OOB）之后由 PrintJSReport 输出，
// 以免插入横幅中间把一组内容打断。
type jsLoadReport struct {
	invalid  int      // 携带无效签名、宽松模式下仍放行的数量
	disabled []string // 因 -enable-js-poc=false 被跳过的 ID
	unsigned []string // 因严格模式（-require-signed-js-poc）被跳过的 ID
}

// PrintJSReport 在启动横幅之后打印 javascript PoC 的加载告警。
// 只输出"被跳过/签名无效"这类需要用户关注的情况；正常启用不打任何提示。
// SDK/静默模式下不输出（与加载期的原有约定一致）。
func (o *Options) PrintJSReport() {
	if o == nil || o.consoleQuiet() {
		return
	}
	r := o.jsReport

	printList := func(header, hint string, ids []string) {
		if len(ids) == 0 {
			return
		}
		const limit = 20
		gologger.Print().Msgf("%s：%d 个", header, len(ids))
		n := len(ids)
		if n > limit {
			n = limit
		}
		for i := 0; i < n; i++ {
			gologger.Print().Msgf("- %s", ids[i])
		}
		if len(ids) > n {
			gologger.Print().Msgf("+ %d more", len(ids)-n)
		}
		if hint != "" {
			gologger.Print().Msg(hint)
		}
	}

	printList("检测到 javascript PoC（已跳过）", "如需启用，去掉 -enable-js-poc=false（将执行 PoC 中的脚本代码，请确保来源可信）", r.disabled)
	printList("检测到未签名/签名无效的 javascript PoC（严格模式已跳过）", "如需放行，去掉 -require-signed-js-poc；为用户 PoC 签名可用 -pocsign <file>", r.unsigned)

	if r.invalid > 0 {
		gologger.Print().Msgf("警告：%d 个 javascript PoC 携带无效签名（宽松模式未拦截）", r.invalid)
	}
}

func (o *Options) logPocDiscarded(path string, err error) {
	if o.consoleQuiet() {
		return
	}
	gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", path, err)
}

// 定义包含 POC 结构的切片
type POCSlices []poc.Poc

// 实现 sort.Interface 接口的 Len、Less 和 Swap 方法
func (s POCSlices) Len() int {
	return len(s)
}

func (s POCSlices) Less(i, j int) bool {
	// 比较两个 poc.Id 字段的首字母
	return s[i].Id < s[j].Id
}

func (s POCSlices) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (o *Options) SmartControl() {
	numCPU := runtime.NumCPU()
	targetLen := o.Targets.Len()

	if o.Concurrency == 25 && targetLen <= 10 {
		o.Concurrency = 10
	} else if o.Concurrency == 25 && targetLen >= 1000 {
		o.Concurrency = numCPU * 30
	} else if o.Concurrency == 25 && targetLen >= 500 {
		o.Concurrency = numCPU * 20
	} else if o.Concurrency == 25 && targetLen >= 100 {
		o.Concurrency = numCPU * 10
	}
}

func (o *Options) parseExcludePocs() ([]string, error) {
	var excludePocs []string
	if len(o.ExcludePocs) > 0 {
		excludePocs = append(excludePocs, o.ExcludePocs...)
	}

	if len(o.ExcludePocsFile) > 0 {
		cdata, err := fileutil.ReadFile(o.ExcludePocsFile)
		if err != nil {
			if len(excludePocs) > 0 {
				return excludePocs, nil
			} else {
				return excludePocs, err
			}
		}
		for poc := range cdata {
			excludePocs = append(excludePocs, poc)
		}
	}
	return excludePocs, nil
}

func isExcludePoc(poc poc.Poc, excludePocs []string) bool {
	if len(excludePocs) == 0 {
		return false
	}
	for _, ep := range excludePocs {
		v := strings.ToLower(ep)
		if strings.Contains(strings.ToLower(poc.Id), v) || strings.Contains(strings.ToLower(poc.Info.Name), v) {
			return true
		}
	}
	return false
}

// 新增函数：获取基础文件名
func GetFileBaseName(options *Options) string {
	// 优先使用-T参数的文件名作为基础
	if options.TargetsFile != "" {
		// 去除路径和扩展名
		base := utils.GetFilename(options.TargetsFile)
		// 去除特殊字符
		base = utils.SanitizeFilename(base)
		if base != "" {
			return base
		}
	}

	// 次选使用第一个-t参数的特征
	if len(options.Target) > 0 && options.Target[0] != "" {
		// 尝试从URL中提取特征
		host := utils.ExtractHost(options.Target[0])
		// 去除特殊字符
		host = utils.SanitizeFilename(host)
		if host != "" {
			return host
		}
	}

	// 最终兜底方案使用xid
	return xid.New().String()
}

// 在 options.go 中新增一个辅助类型和函数（放在同文件的顶层位置）
type pocPathItem struct {
	name   string
	source string // "embed" / "local" / "append" / "curated" / "my"
	path   string
}

func (o *Options) collectOrderedPocPaths() []pocPathItem {
	// 薄封装：复用仓库层统一路径整合，转换为旧的结构以保持兼容
	pathItems, _ := pocsrepo.CollectOrderedPocPaths(o.AppendPoc)

	out := make([]pocPathItem, 0, len(pathItems))
	for _, pi := range pathItems {
		src := ""
		switch pi.Source {
		case pocsrepo.SourceBuiltin:
			src = "embed"
		case pocsrepo.SourceLocal:
			src = "local"
		case pocsrepo.SourceAppend:
			src = "append"
		case pocsrepo.SourceCurated:
			src = "curated"
		case pocsrepo.SourceMy:
			src = "my"
		default:
			continue
		}

		path := pi.Path
		if pi.Source == pocsrepo.SourceBuiltin && strings.HasPrefix(path, "embedded:") {
			path = strings.TrimPrefix(path, "embedded:")
		}

		base := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
		name := strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")

		out = append(out, pocPathItem{name: name, source: src, path: path})
	}

	return out
}
