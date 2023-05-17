package config

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/output"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
	sliceutil "github.com/zan8in/pins/slice"
)

var (
	ReverseCeyeApiKey string
	ReverseCeyeDomain string
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

	// Pocs Directory
	PocsDirectory utils.StringSlice

	Targets sliceutil.SafeSlice

	// target URLs/hosts to scan
	Target string

	// list of target URLs/hosts to scan (one per line)
	TargetsFile string

	// PoC file or directory to scan
	PocFile string

	// show afrog-pocs list
	PocList bool

	// show a afrog-pocs detail
	PocDetail string

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

	//
	MonitorTargets bool

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

	// number of times to retry a failed request (default 1)
	Retries int

	//
	MaxHostError int

	// time to wait in seconds before timeout (default 10)
	Timeout int

	// http/socks5 proxy to use
	Proxy string

	// afrog process count (target total × pocs total)
	ProcessTotal uint32

	DisableOutputHtml bool

	OJ *output.OutputJson
}

func NewOptions() (*Options, error) {

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&options.Target, "target", "t", "", "target URLs/hosts to scan"),
		flagSet.StringVarP(&options.TargetsFile, "target-file", "T", "", "list of target URLs/hosts to scan (one per line)"),
	)

	flagSet.CreateGroup("pocs", "PoCs",
		flagSet.StringVarP(&options.PocFile, "poc-file", "P", "", "PoC file or directory to scan"),
		flagSet.StringVarP(&options.PocDetail, "poc-detail", "pd", "", "show a afrog-pocs detail"),
		flagSet.BoolVarP(&options.PocList, "poc-list", "pl", false, "show afrog-pocs list"),
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
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.BoolVarP(&options.MonitorTargets, "monitor-targets", "mt", false, "Enable the monitor-target feature during scanning."),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request (default 1)"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "time to wait in seconds before timeout (default 10)"),
		flagSet.IntVar(&options.MaxHostError, "mhe", 3, "max errors for a host before skipping from scan"),
		flagSet.BoolVar(&options.Silent, "silent", false, "only results only"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVarP(&options.Update, "update", "un", false, "update afrog engine to the latest released version"),
		// flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to the latest released version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic afrog-pocs update check"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
	)

	_ = flagSet.Parse()

	if err := options.verifyOptions(); err != nil {
		return options, err
	}

	return options, nil
}

func (opt *Options) verifyOptions() error {

	config, err := NewConfig()
	if err != nil {
		return err
	}
	opt.Config = config

	if len(opt.Config.Reverse.Ceye.Domain) == 0 || len(opt.Config.Reverse.Ceye.ApiKey) == 0 {
		homeDir, _ := os.UserHomeDir()
		configDir := homeDir + "/.config/afrog/afrog-config.yaml"
		gologger.Info().Msg("The reverse connection platform is not configured, which may affect the validation of certain RCE PoCs")
		gologger.Info().Msgf("go to `%s` to configure the reverse connection platform\n", configDir)
	}

	ReverseCeyeApiKey = opt.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = opt.Config.Reverse.Ceye.Domain

	if len(opt.Target) == 0 && len(opt.TargetsFile) == 0 {
		return fmt.Errorf("either `target` or `target-file` must be set")
	}

	if opt.PocList {
		err := opt.PrintPocList()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	if len(opt.PocDetail) > 0 {
		err := opt.ShowPocDetail(opt.PocDetail)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	if opt.Update {
		err := updateEngine()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	upgrade, err := upgrade.NewUpgrade(true)
	if err != nil {
		return err
	}

	if !opt.DisableUpdateCheck {
		info, _ := upgrade.UpgradePocs()
		if len(info) > 0 && opt.UpdatePocs {
			gologger.Info().Msg(info)
		}
	}

	ShowBanner(upgrade)

	if len(opt.Json) > 0 {
		opt.OJ = output.NewOutputJson(opt.Json)
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

func (o *Options) PrintPocList() error {
	plist, err := pocs.GetPocs()
	if err != nil {
		return err
	}

	number := 1
	for _, v := range plist {
		if poc, err := pocs.ReadPocs(v); err == nil {
			gologger.Print().Msgf("%s [%s][%s][%s] author:%s\n",
				log.LogColor.Time(number),
				log.LogColor.Title(poc.Id),
				log.LogColor.Green(poc.Info.Name),
				log.LogColor.GetColor(poc.Info.Severity, poc.Info.Severity), poc.Info.Author)
			number++
		}
	}
	gologger.Print().Msgf("--------------------------------\r\nTotal: %d\n", number-1)

	return nil
}

func (o *Options) ShowPocDetail(pocname string) error {
	path, err := pocs.GetPocDetail(pocname)
	if err != nil {
		return err
	}

	poc, err := pocs.ReadPocs(path)
	if err != nil {
		return err
	}

	fmt.Printf("id: %s\n\n", poc.Id)

	fmt.Printf("info:\n")
	fmt.Printf("  name: %s\n", poc.Info.Name)
	fmt.Printf("  author: %s\n", poc.Info.Author)
	fmt.Printf("  severity: %s\n", poc.Info.Severity)
	fmt.Printf("  verified: %v\n", poc.Info.Verified)
	if len(poc.Info.Description) > 0 {
		fmt.Printf("  description: %s\n", poc.Info.Description)
	}
	if len(poc.Info.Reference) > 0 {
		fmt.Printf("  reference:\n")
		for i, v := range poc.Info.Reference {
			fmt.Printf("    %d %s", i, v)
		}
	}
	fmt.Println()

	if len(poc.Set) > 0 {
		fmt.Printf("set:\n")
		for _, v := range poc.Set {
			key, value := v.Key, v.Value
			fmt.Printf("  %s:%s\n", key, value)
		}
	}

	fmt.Printf("rules:\n")
	if len(poc.Rules) > 0 {
		for _, v := range poc.Rules {
			fmt.Printf("  %s\n", v.Key)
			fmt.Printf("    request:\n")
			if len(v.Value.Request.Raw) > 0 {
				fmt.Printf("      raw: |\n")
				split := strings.Split(v.Value.Request.Raw, "\n")
				for _, v := range split {
					fmt.Printf("        %s\n", v)
				}

			} else {
				fmt.Printf("      method: %s\n", v.Value.Request.Method)
				fmt.Printf("      path: %s\n", v.Value.Request.Path)
				if len(v.Value.Request.Headers) > 0 {
					fmt.Printf("      headers:\n")
					for k, v := range v.Value.Request.Headers {
						fmt.Printf("        %s: %s\n", k, v)
					}
				}
			}
			if v.Value.Request.FollowRedirects {
				fmt.Printf("      follow_redirects: %v\n", v.Value.Request.FollowRedirects)
			}
			if len(v.Value.Expressions) > 0 {
				fmt.Printf("    expressions:\n")
				for _, v := range v.Value.Expressions {
					fmt.Printf("      %s\n", v)
				}
			} else {
				fmt.Printf("    expression: %s\n", v.Value.Expression)
			}
		}
		fmt.Printf("expression: %s\n", poc.Expression)
	}

	return nil
}
