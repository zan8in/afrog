package config

import (
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/pkg/output"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

	// Pocs Directory
	PocsDirectory utils.StringSlice

	// Target URLs/Domains to scan
	Targets utils.StringSlice

	// Target URLs/Domains to scan
	Target goflags.StringSlice

	// TargetsFilePath specifies the targets from a file to scan.
	TargetsFilePath string

	// PocsFilePath specifies the directory of pocs to scan.
	PocsFilePath string

	// output file to write found issues/vulnerabilities
	Output string

	// search PoC by keyword , eg: -s tomcat
	Search string

	SearchKeywords []string

	// no progress if silent is true
	Silent bool

	// pocs to run based on severity. Possible values: info, low, medium, high, critical
	Severity string

	SeverityKeywords []string

	// Scan Stable  eg: 1(generally)(default), 2(normal), 3(stablize)
	ScanStable string

	// disable output fingerprint in the console
	NoFinger bool

	// fingerprint scan only
	OnlyFinger bool

	// ports to scan eg: 80,443,8000-9000
	Port string

	// web port scan
	WebPort bool

	// disable show tips
	NoTips bool

	// update afrog-pocs
	UpdatePocs bool

	// update afrog version
	UpdateAfrogVersion bool

	// show pocs list
	PrintPocs bool

	// Scan count num(targets * allpocs)
	Count int

	// Current Scan count num
	CurrentCount uint32

	// Thread lock
	OptLock sync.Mutex

	// Callback scan result
	ApiCallBack ApiCallBack

	// maximum number of requests to send per second (default 150)
	RateLimit int

	// maximum number of afrog-pocs to be executed in parallel (default 25)
	Concurrency int

	// maximum number of fingerprint to be executed in parallel (default 25)
	FingerprintConcurrency int

	// max errors for a host before skipping from scan (default 30)
	MaxHostError int

	// number of times to retry a failed request (default 1)
	Retries int

	// time to wait in seconds before timeout (default 10)
	Timeout int

	// http/socks5 proxy to use
	Proxy string

	// afrog process count (target total × pocs total)
	ProcessTotal uint32

	//
	PocsTotal       uint32
	TargetsTotal    uint32
	BadTargetsTotal uint32

	// write output in JSONL(ines) format
	OutputJson string

	OJ *output.OutputJson
}

func ParseOptions() (*Options, error) {

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringSliceVarP(&options.Target, "target", "t", nil, "target URLs/hosts to scan", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.TargetsFilePath, "Targets", "T", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
	)

	flagSet.CreateGroup("pocs", "PoCs",
		flagSet.StringVarP(&options.PocsFilePath, "pocs", "P", "", "poc.yaml or poc directory paths to include in the scan（no default `afrog-pocs` directory）"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "output html report, eg: -o result.html"),
		flagSet.BoolVarP(&options.PrintPocs, "printpocs", "pp", false, "print afrog-pocs list"),
		flagSet.StringVar(&options.OutputJson, "json", "", "write output in JSON format, eg: -json result.json"),
	)

	flagSet.CreateGroup("filters", "Filtering",
		flagSet.StringVarP(&options.Search, "search", "s", "", "search PoC by `keyword` , eg: -s tomcat,phpinfo"),
		flagSet.StringVarP(&options.Severity, "severity", "S", "", "pocs to run based on severity. Possible values: info, low, medium, high, critical, unknown"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", DefaultRateLimit, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", DefaultConcurrency, "maximum number of afrog-pocs to be executed in parallel"),
		flagSet.IntVarP(&options.FingerprintConcurrency, "fingerprint-concurrency", "fc", 100, "maximum number of fingerprint to be executed in parallel"),
	)

	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.BoolVar(&options.Silent, "silent", false, "no progress, only results"),
		flagSet.BoolVarP(&options.NoFinger, "nofinger", "nf", false, "disable fingerprint"),
		flagSet.BoolVarP(&options.OnlyFinger, "onlyfinger", "of", false, "fingerprint scan only"),
		flagSet.BoolVarP(&options.NoTips, "notips", "nt", false, "disable show tips"),
		flagSet.StringVarP(&options.ScanStable, "scan-stable", "ss", "1", "scan stable. Possible values: generally=1, normal=2, stablize=3"),
		flagSet.IntVarP(&options.MaxHostError, "max-host-error", "mhe", 30, "max errors for a host before skipping from scan"),
		flagSet.IntVar(&options.Retries, "retries", DefaultRetries, "number of times to retry a failed request"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultTimeout, "time to wait in seconds before timeout"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVar(&options.UpdateAfrogVersion, "update", false, "update afrog engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to latest released version"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if err := options.validateOptions(); err != nil {
		return nil, err
	}

	return options, nil
}

var (
	errNoInputList = errors.New("no input list provided")
	errZeroValue   = errors.New("cannot be zero")
)

func (options *Options) validateOptions() error {

	if options.Target == nil && options.TargetsFilePath == "" {
		return errNoInputList
	}

	if options.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	}

	return nil
}

type ApiCallBack func(any)

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

func (o *Options) PrintPocList() {
	plist, err := pocs.PrintPocs()
	if err != nil {
		return
	}
	for _, v := range plist {
		gologger.Print().Msg(v)
	}
	gologger.Print().Msgf("----------------\r\nPoC Total: ", len(plist))
}
