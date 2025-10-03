package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rs/xid"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/output"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/validator"
	"github.com/zan8in/afrog/v3/pkg/web"
	"github.com/zan8in/afrog/v3/pkg/webhook/dingtalk"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
	fileutil "github.com/zan8in/pins/file"
	sliceutil "github.com/zan8in/pins/slice"
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

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
	Silent bool

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
	RateLimit int

	// maximum number of afrog-pocs to be executed in parallel (default 25)
	Concurrency int

	// maximum number of requests to send per second (default 150)
	OOBRateLimit int

	// maximum number of afrog-pocs to be executed in parallel (default 25)
	OOBConcurrency int

	// Smart Control Concurrency
	Smart bool

	// number of times to retry a failed request (default 1)
	Retries int

	//
	MaxHostError int

	// time to wait in seconds before timeout (default 10)
	Timeout int

	// http/socks5 proxy to use
	Proxy string

	MaxRespBodySize int

	// afrog process count (target total × pocs total)
	ProcessTotal uint32

	DisableOutputHtml bool

	OJ *output.OutputJson

	// Cookie string

	Header goflags.StringSlice

	Version bool

	Web bool

	// webhook
	Dingtalk bool

	// resume
	Resume string

	// debug
	Debug bool

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
	OOB        string
	OOBKey     string
	OOBDomain  string
	OOBHttpUrl string
	OOBApiUrl  string

	// SDK模式标志，用于控制OOB检测行为
	SDKMode   bool
	EnableOOB bool

	// path to the afrog configuration file
	ConfigFile string

	// Validate POC YAML syntax
	Validate string
}

func NewOptions() (*Options, error) {

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("target", "Target",
		flagSet.StringSliceVarP(&options.Target, "target", "t", nil, "target URLs/hosts to scan (comma separated)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.TargetsFile, "target-file", "T", "", "list of target URLs/hosts to scan (one per line)"),
		flagSet.StringVarP(&options.Cyberspace, "cyberspace", "cs", "", "cyberspace search, eg: -cs zoomeye"),
		flagSet.StringVarP(&options.Query, "query", "q", "", "cyberspace search keywords, eg: -q app:'tomcat'"),
		flagSet.IntVarP(&options.QueryCount, "query-count", "qc", 100, "cyberspace search data count, eg: -qc 1000"),
		flagSet.StringVar(&options.Resume, "resume", "", "resume scan using resume.afg"),
		flagSet.StringVar(&options.OOB, "oob", "", "set Out-of-Band (OOB) adapter, eg: -oob ceyeio or -oob dnslogcn or -oob alphalog"),
	)

	flagSet.CreateGroup("pocs", "PoCs",
		flagSet.StringVarP(&options.PocFile, "poc-file", "P", "", "PoC file or directory to scan"),
		flagSet.StringSliceVarP(&options.AppendPoc, "append-poc", "ap", nil, "append PoC file or directory to scan (comma separated)", goflags.NormalizedOriginalStringSliceOptions),
		flagSet.StringVarP(&options.PocDetail, "poc-detail", "pd", "", "show a afrog-pocs detail"),
		flagSet.BoolVarP(&options.PocList, "poc-list", "pl", false, "show afrog-pocs list"),
		flagSet.StringSliceVarP(&options.ExcludePocs, "exclude-pocs", "ep", nil, "pocs to exclude from the scan (comma-separated)", goflags.NormalizedOriginalStringSliceOptions),
		flagSet.StringVarP(&options.ExcludePocsFile, "exclude-pocs-file", "epf", "", "list of pocs to exclude from scan (file)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "write to the HTML file, including all vulnerability results"),
		flagSet.StringVarP(&options.Json, "json", "j", "", "write to the JSON file, but it will not include the request and response content"),
		flagSet.StringVarP(&options.JsonAll, "json-all", "ja", "", "write to the JSON file, including all vulnerability results"),
		flagSet.BoolVarP(&options.DisableOutputHtml, "disable-output-html", "doh", false, "disable the automatic generation of HTML reports (higher priority than the -o command)"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringVarP(&options.Search, "search", "s", "", "search PoC by keyword , eg: -s tomcat,phpinfo"),
		flagSet.StringVarP(&options.Severity, "severity", "S", "", "pocs to run based on severity. support: info, low, medium, high, critical, unknown"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 25, "maximum number of afrog-pocs to be executed in parallel"),
		flagSet.BoolVar(&options.Smart, "smart", false, "intelligent adjustment of concurrency based on changes in the total number of assets being scanned"),
		flagSet.IntVarP(&options.OOBRateLimit, "oob-rate-limit", "orl", 25, "oob poc maximum number of requests to send per second"),
		flagSet.IntVarP(&options.OOBConcurrency, "oob-concurrency", "oc", 25, "oob poc maximum number of afrog-pocs to be executed in parallel"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.IntVar(&options.Timeout, "timeout", 50, "time to wait in seconds before timeout"),
		flagSet.BoolVar(&options.MonitorTargets, "mt", false, "enable the monitor-target feature during scanning"),
		flagSet.IntVar(&options.MaxHostError, "mhe", 3, "max errors for a host before skipping from scan"),
		flagSet.IntVar(&options.MaxRespBodySize, "mrbs", 2, "max of http response body size"),
		flagSet.BoolVar(&options.Silent, "silent", false, "only results only"),
		flagSet.BoolVar(&options.PocExecutionDurationMonitor, "pedm", false, "This monitor tracks and records the execution time of each POC to identify the POC with the longest execution time."),
		flagSet.BoolVar(&options.VulnerabilityScannerBreakpoint, "vsb", false, "Once a vulnerability is detected, the scanning program will immediately halt the scan and report the identified vulnerability."),
		// flagSet.StringVar(&options.Cookie, "cookie", "", "custom global cookie, only applicable to http(s) protocol, eg: -cookie 'JSESSION=xxx;'"),
		flagSet.StringSliceVarP(&options.Header, "header", "H", nil, "custom header/cookie to include in all http request in key:value format (comma separated), eg: -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: JSESSION=xxx;'", goflags.StringSliceOptions),
		flagSet.StringVar(&options.Sort, "sort", "", "Scan sorting, default security level scanning, `-sort a-z` scan in alphabetical order"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVarP(&options.Update, "update", "un", false, "update afrog engine to the latest released version"),
		// flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to the latest released version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic afrog-pocs update check"),
	)

	flagSet.CreateGroup("proxy", "Proxy",
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVarP(&options.Version, "version", "v", false, "show afrog version"),
		flagSet.StringVar(&options.Validate, "validate", "", "validate POC YAML syntax, support file or directory"),
	)

	flagSet.CreateGroup("server", "Server",
		flagSet.BoolVar(&options.Web, "web", false, "Start a web server."),
	)

	flagSet.CreateGroup("webhook", "Webhook",
		flagSet.BoolVar(&options.Dingtalk, "dingtalk", false, "Start a dingtalk webhook."),
	)

	flagSet.CreateGroup("configurations", "Configurations",
		flagSet.StringVar(&options.ConfigFile, "config", "", "path to the afrog configuration file"),
	)

	_ = flagSet.Parse()

	if err := options.VerifyOptions(); err != nil {
		return options, err
	}

	return options, nil
}

func (opt *Options) VerifyOptions() error {

	if len(opt.Validate) > 0 {
		validator.ValidatePocFiles(opt.Validate)
		os.Exit(0)
	}

	// update afrog-pocs
	au, err := NewAfrogUpdate(true)
	if err != nil {
		return err
	}

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

	if err := sqlite.NewWebSqliteDB(); err != nil {
		return fmt.Errorf("init sqlite db error: %v", err)
	}

	if opt.Dingtalk {
		if dingtalk.IsTokensEmpty(opt.Config.Webhook.Dingtalk.Tokens) {
			return fmt.Errorf("Dingtalk webhook token is required")
		}
	}

	if opt.Web {
		serveraddress := ":16868"
		if config.ServerAddress != "" {
			serveraddress = config.ServerAddress
		}
		err = web.StartServer(serveraddress)
		if err != nil {
			gologger.Error().Msg(err.Error())
			os.Exit(0)
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

	if len(opt.Target) > 0 || len(opt.TargetsFile) > 0 || (len(opt.Cyberspace) > 0 && len(opt.Query) > 0) {

		ShowBanner(au, "")

		// oob setting
		// opt.SetOOBAdapter()

	} else {
		return fmt.Errorf("target or cyberspace or query is empty")
	}

	return nil
}

func (o *Options) SetSearchKeyword() bool {
	if len(o.Search) > 0 {
		arr := strings.Split(o.Search, ",")
		if len(arr) > 0 {
			for _, v := range arr {
				o.SearchKeywords = append(o.SearchKeywords, strings.TrimSpace(v))
			}
			return true
		}
	}
	return false
}

func (o *Options) CheckPocKeywords(id, name string) bool {
	if len(o.SearchKeywords) > 0 {
		for _, v := range o.SearchKeywords {
			v = strings.ToLower(v)
			if strings.Contains(strings.ToLower(id), v) || strings.Contains(strings.ToLower(name), v) {
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

func (o *Options) FilterPocSeveritySearch(pocId, pocInfoName, severity string) bool {
	var isShow bool
	if len(o.Search) > 0 && o.SetSearchKeyword() && len(o.Severity) > 0 && o.SetSeverityKeyword() {
		if o.CheckPocKeywords(pocId, pocInfoName) && o.CheckPocSeverityKeywords(severity) {
			isShow = true
		}
	} else if len(o.Severity) > 0 && o.SetSeverityKeyword() {
		if o.CheckPocSeverityKeywords(severity) {
			isShow = true
		}
	} else if len(o.Search) > 0 && o.SetSearchKeyword() {
		if o.CheckPocKeywords(pocId, pocInfoName) {
			isShow = true
		}
	} else {
		isShow = true
	}
	return isShow
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
			id, name, severity string
			authors            []string
			err                error
		)

		if it.Source == pocsrepo.SourceBuiltin {
			// 嵌入式路径以 embedded: 前缀，读取元信息
			path := strings.TrimPrefix(it.Path, "embedded:")
			pm, e := pocs.EmbedReadPocMetaByPath(path)
			err = e
			if err == nil {
				id = pm.Id
				name = pm.Info.Name
				severity = pm.Info.Severity
				authors = pocsrepo.SplitAuthors(pm.Info.Author)
			}
		} else {
			pm, e := poc.LocalReadPocMetaByPath(it.Path)
			err = e
			if err == nil {
				id = pm.Id
				name = pm.Info.Name
				severity = pm.Info.Severity
				authors = pocsrepo.SplitAuthors(pm.Info.Author)
			}
		}

		if err != nil {
			gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", it.Path, err)
			continue
		}

		// 保留原有过滤逻辑
		if !o.FilterPocSeveritySearch(id, name, severity) {
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
		flag := false
		for _, item := range poc.Set {
			key := item.Key.(string)
			if key == "oob" || key == "reverse" {
				flag = true
				break
			}
		}
		if flag {
			result = append(result, poc)
		} else {
			other = append(other, poc)
		}
	}
	return result, other
}

func (o *Options) CreatePocList() []poc.Poc {
	var pocSlice []poc.Poc

	if len(o.PocFile) > 0 && len(poc.LocalTestList) > 0 {
		for _, pocYaml := range poc.LocalTestList {
			if p, err := poc.LocalReadPocByPath(pocYaml); err == nil {
				pocSlice = append(pocSlice, p)
			} else {
				gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", pocYaml, err)
			}
		}
		return pocSlice
	}

	// 使用仓库层统一的路径整合与去重（优先级：curated > my > append > local > builtin）
	pathItems, _ := pocsrepo.CollectOrderedPocPaths(o.AppendPoc)

	// 读取并校验：格式错误的 POC 剔除并输出错误
	for _, it := range pathItems {
		if it.Source == pocsrepo.SourceBuiltin { // 嵌入式
			path := strings.TrimPrefix(it.Path, "embedded:")
			if p, err := pocs.EmbedReadPocByPath(path); err == nil {
				pocSlice = append(pocSlice, p)
			} else {
				gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", path, err)
			}
		} else { // curated/my/append/local
			if p, err := poc.LocalReadPocByPath(it.Path); err == nil {
				pocSlice = append(pocSlice, p)
			} else {
				gologger.Error().Msgf("Invalid POC format, discard: %s, error: %v", it.Path, err)
			}
		}
	}

	// 保留原有过滤逻辑
	newPocSlice := []poc.Poc{}
	for _, pp := range pocSlice {
		if o.FilterPocSeveritySearch(pp.Id, pp.Info.Name, pp.Info.Severity) {
			newPocSlice = append(newPocSlice, pp)
		}
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
