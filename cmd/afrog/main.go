package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/fingerprint"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/targetlive"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
)

var (
	options   = &config.Options{}
	htemplate = &html.HtmlTemplate{}
	lock      sync.Mutex
	number    uint32 = 0
)

func main() {
	runner.ShowBanner()

	readConfig()

	starttime := time.Now()

	// fixed 99% bug
	// go func() {
	// 	startcount := options.CurrentCount
	// 	for {
	// 		time.Sleep(2 * time.Minute)
	// 		if options.CurrentCount > 0 && startcount == options.CurrentCount && len(options.TargetLive.ListRequestTargets()) == 0 {
	// 			fmt.Printf("\r%d/%d/%d%%/%s | hosts: %d, closed: %d | except: The program runs to %d end", options.CurrentCount, options.Count, int(options.CurrentCount)*100/options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s", len(options.Targets), options.TargetLive.GetNoLiveAtomicCount(), int(options.CurrentCount)*100/options.Count)
	// 			sleepEnd()
	// 			os.Exit(1)
	// 		}
	// 		startcount = options.CurrentCount
	// 	}
	// }()

	err := runner.New(options, htemplate, func(result any) {
		r := result.(*core.Result)

		defer func() {
			atomic.AddUint32(&options.CurrentCount, 1)
			if !options.Silent {
				fmt.Printf("\r%d/%d/%d%%/%s | hosts: %d, closed: %d", options.CurrentCount, options.Count, int(options.CurrentCount)*100/options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s", len(options.Targets), targetlive.TLive.GetNoLiveAtomicCount())
			}
		}()

		if r.IsVul {
			lock.Lock()
			if r.FingerResult != nil {
				fr := r.FingerResult.(fingerprint.Result)
				fingerprint.PrintFingerprintInfoConsole(fr)
			} else {

				atomic.AddUint32(&number, 1)
				r.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

				htemplate.Result = r
				htemplate.Number = utils.GetNumberText(int(number))
				htemplate.Append()

				if len(options.OutputJson) > 0 {
					options.OJ.AddJson(r.PocInfo.Id, r.PocInfo.Info.Severity, r.FullTarget)
				}
			}
			lock.Unlock()
		}

	})

	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	sleepEnd()
}

func sleepEnd() {
	time.Sleep(time.Second * 3)
}

func readConfig() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&options.Target, "target", "t", "", "target URLs/hosts to scan"),
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
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 25, "maximum number of afrog-pocs to be executed in parallel"),
		flagSet.IntVarP(&options.FingerprintConcurrency, "fingerprint-concurrency", "fc", 100, "maximum number of fingerprint to be executed in parallel"),
	)

	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.BoolVar(&options.Silent, "silent", false, "no progress, only results"),
		flagSet.BoolVarP(&options.NoFinger, "nofinger", "nf", false, "disable fingerprint"),
		flagSet.BoolVarP(&options.NoTips, "notips", "nt", false, "disable show tips"),
		flagSet.StringVarP(&options.ScanStable, "scan-stable", "ss", "1", "scan stable. Possible values: generally=1, normal=2, stablize=3"),
		flagSet.IntVarP(&options.MaxHostError, "max-host-error", "mhe", 30, "max errors for a host before skipping from scan"),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "time to wait in seconds before timeout"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVar(&options.UpdateAfrogVersion, "update", false, "update afrog engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to latest released version"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
	)

	_ = flagSet.Parse()

}
