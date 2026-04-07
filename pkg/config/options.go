package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rs/xid"
	"github.com/zan8in/afrog/v3/pkg/catalog"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/output"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/validator"
	"github.com/zan8in/afrog/v3/pkg/webhook/dingtalk"
	"github.com/zan8in/afrog/v3/pkg/webhook/wecom"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
	fileutil "github.com/zan8in/pins/file"
	sliceutil "github.com/zan8in/pins/slice"
	"gopkg.in/yaml.v2"
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

	AfrogUpdate *AfrogUpdate

	// Pocs Directory
	PocsDirectory utils.StringSlice

	Targets sliceutil.SafeSlice

	// target URLs/hosts to scan
	Target goflags.StringSlice

	// list of target URLs/hosts to scan (one per line)
	TargetsFile string

	// PoC file or directory to scan
	PocFile string

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
	Resume string

	// debug
	Debug     bool
	LiveStats bool

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
	OOB             string
	OOBKey          string
	OOBDomain       string
	OOBHttpUrl      string
	OOBApiUrl       string
	OOBPollInterval int
	OOBHitRetention int

	// SDK模式标志，用于控制OOB检测行为
	SDKMode   bool
	EnableOOB bool

	// enable pre-scan host port scanning
	PortScan         bool
	PSPorts          string
	PSRateLimit      int
	PSTimeout        int
	PSRetries        int
	PSSkipDiscovery  bool
	PSS4Chunk        int
	OnPortScanResult func(host string, port int)
	OnHostDiscovered func(host string)
	OnPhaseProgress  func(phase string, status string, finished int64, total int64, percent int)
	OnScanInfoUpdate func(info ScanInfoUpdate)

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
		flagSet.BoolVar(&options.AutoReqLimit, "auto-req-limit", false, "automatically set per-target request limit (host:port)"),
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
		flagSet.IntVar(&options.OOBPollInterval, "oob-poll-interval", 1, "oob polling interval in seconds"),
		flagSet.IntVar(&options.OOBHitRetention, "oob-hit-retention", 10, "oob hit retention in minutes"),
	)

	flagSet.CreateGroup("stages", "Stages",
		flagSet.BoolVarP(&options.PortScan, "portscan", "ps", false, "enable pre-scan host port scanning for input assets"),
		flagSet.StringVarP(&options.PSPorts, "ports", "p", "top", "ports definition for port pre-scan, e.g. '80,443,1000-2000' or 'top' or 'full' (custom ports also scan 'top')"),
		flagSet.BoolVarP(&options.PSSkipDiscovery, "ps-skip-discovery", "Pn", false, "skip host discovery before port pre-scan"),
		flagSet.IntVarP(&options.PSRateLimit, "ps-rate", "prate", 0, "port pre-scan rate limit"),
		flagSet.IntVarP(&options.PSTimeout, "ps-timeout-ms", "ptimeout", 0, "port pre-scan timeout in milliseconds"),
		flagSet.IntVarP(&options.PSRetries, "ps-retries", "ptries", 0, "port pre-scan retries"),
		flagSet.IntVar(&options.PSS4Chunk, "ps-s4-chunk", 1000, "port pre-scan s4 chunk size when ports=full"),
		flagSet.BoolVar(&options.EnableWebProbe, "w", false, "enable webprobe stage (alive web probing)"),
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
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVar(&options.Silent, "silent", false, "only results only"),
		flagSet.BoolVar(&options.LiveStats, "live-stats", false, "render live stats in a single-line status display"),
	)

	flagSet.CreateGroup("debug", "Debug & Tools",
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
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

	if err := options.VerifyOptions(); err != nil {
		return options, err
	}

	return options, nil
}

func (opt *Options) VerifyOptions() error {

	if opt.NoColor {
		log.EnableColor = false
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

	limitModeCount := 0
	if opt.ReqLimitPerTarget > 0 {
		limitModeCount++
	}
	if opt.AutoReqLimit {
		limitModeCount++
	}
	if opt.Polite {
		limitModeCount++
	}
	if opt.Balanced {
		limitModeCount++
	}
	if opt.Aggressive {
		limitModeCount++
	}
	if limitModeCount > 1 {
		return fmt.Errorf("only one of --req-limit-per-target/--auto-req-limit/--polite/--balanced/--aggressive can be used")
	}
	if opt.ReqLimitPerTarget < 0 {
		return fmt.Errorf("--req-limit-per-target must be >= 0")
	}

	if opt.ReqLimitPerTarget == 0 {
		if opt.Polite {
			opt.ReqLimitPerTarget = 5
		} else if opt.Balanced {
			opt.ReqLimitPerTarget = 15
		} else if opt.Aggressive {
			opt.ReqLimitPerTarget = 50
		} else if opt.AutoReqLimit {
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
			if con >= 100 && r > 8 {
				r = 8
			} else if con >= 50 && r > 12 {
				r = 12
			}
			opt.ReqLimitPerTarget = r
		}
	}

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

func (o *Options) CreatePocList() []poc.Poc {
	type legacyItem struct {
		ID      string
		Path    string
		Reasons []string
	}

	pathItems := []pocsrepo.PathItem{}
	if strings.TrimSpace(o.PocFile) != "" {
		c := catalog.New(o.PocFile)
		paths, _ := c.GetPocPath(o.PocFile)
		for _, pth := range paths {
			pathItems = append(pathItems, pocsrepo.PathItem{Path: pth, Source: pocsrepo.SourceLocal})
		}
	} else {
		pathItems, _ = pocsrepo.CollectOrderedPocPaths(o.AppendPoc)
	}

	newPocSlice := make([]poc.Poc, 0, len(pathItems))
	legacy := make([]legacyItem, 0)

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
			gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", srcPath, err)
			continue
		}

		pm := poc.PocMeta{}
		if e := yaml.Unmarshal(raw, &pm); e != nil {
			gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", srcPath, e)
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
			continue
		}

		pp := poc.Poc{}
		if e := yaml.Unmarshal(raw, &pp); e != nil {
			gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", srcPath, e)
			continue
		}
		newPocSlice = append(newPocSlice, pp)
	}

	if len(legacy) > 0 {
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

	return finalPocSlice
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
