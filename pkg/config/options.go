package config

import (
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/output"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
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
	Target string

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

	// write output in JSONL(ines) format
	OutputJson string

	OJ *output.OutputJson
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
