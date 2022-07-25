package config

import (
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/utils"
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

	// Scan count num(targets * allpocs)
	Count int

	// Current Scan count num
	CurrentCount int

	// Thread lock
	OptLock sync.Mutex

	// Callback scan result
	ApiCallBack ApiCallBack

	// CheckLive
	CheckLiveMap sync.Map
}

type ApiCallBack func(interface{})

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

// check live by count, alive if result is true  else not alive.
func (o *Options) CheckLiveByCount(url string) bool {
	c, b := o.GetCheckLiveValue(url)
	if c >= 6 {
		// fmt.Println(url, "c>3", c, b)
		return false
	}
	if !b {
		o.SetCheckLiveValue(url)

		// c, b := o.GetCheckLiveValue(url)
		// fmt.Println(url, "no http(s)", c, b)
	}
	return true
}

func (o *Options) SetCheckLiveValue(key string) {
	c, b := o.CheckLiveMap.Load(key)
	if b && c.(int) < 6 {
		o.CheckLiveMap.Store(key, c.(int)+1)
	} else {
		o.CheckLiveMap.Store(key, 0)
	}
}

func (o *Options) GetCheckLiveValue(key string) (int, bool) {
	c, b := o.CheckLiveMap.LoadOrStore(key, 0)
	return c.(int), b
}
