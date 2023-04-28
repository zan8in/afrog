package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/output"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
	sliceutil "github.com/zan8in/pins/slice"
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
	UpdateAfrogVersion bool

	//
	MonitorTargets bool

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

	// number of times to retry a failed request (default 1)
	Retries int

	//
	MaxHostNum int

	// time to wait in seconds before timeout (default 10)
	Timeout int

	// http/socks5 proxy to use
	Proxy string

	// afrog process count (target total × pocs total)
	ProcessTotal uint32

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

	fmt.Printf("id: %s\n", poc.Id)
	fmt.Println()

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
