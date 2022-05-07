package config

import (
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

	// no progress if silent is true
	Silent bool

	// disable output fingerprint in the console
	NoFinger bool

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
