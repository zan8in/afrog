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

	// disable output fingerprint in the console
	NoFinger bool

	// ports to scan eg: 80,443,8000-9000
	Port string

	// disable port scan
	NoPortScan bool

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
			if strings.Contains(id, v) || strings.Contains(name, v) {
				return true
			}
		}
	}
	return false
}
