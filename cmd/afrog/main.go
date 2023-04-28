package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "net/http/pprof"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/report"
	"github.com/zan8in/afrog/pkg/runner"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
)

var (
	lock   sync.Mutex
	rport  *report.Report
	err    error
	number uint32 = 0
)

func main() {

	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	runner.ShowBanner()

	options := parseOptions()

	if rport, err = report.NewReport(options.Output, report.DefaultTemplate); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	starttime := time.Now()

	err = runner.New(options, func(result any) {
		r := result.(*core.Result)

		if !options.Silent {
			defer func() {
				atomic.AddUint32(&options.CurrentCount, 1)
				if !options.Silent {
					fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if r.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			r.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			rport.SetResult(r)
			rport.Append(utils.GetNumberText(int(number)))

			if len(options.Json) > 0 {
				options.OJ.AddJson(r.PocInfo.Id, r.PocInfo.Info.Severity, r.FullTarget)
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

func parseOptions() *config.Options {
	options := &config.Options{}
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
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to (optional), support format: html"),
		flagSet.StringVarP(&options.Json, "json", "j", "", "file to write output to (optional), support format: json"),
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
		flagSet.BoolVarP(&options.MonitorTargets, "monitor-targets", "mt", true, "monitor targets state in the scan"),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request (default 1)"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "time to wait in seconds before timeout (default 10)"),
		flagSet.IntVar(&options.MaxHostNum, "mhe", 3, "max errors for a host before skipping from scan"),
		flagSet.BoolVar(&options.Silent, "silent", false, "only results only"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVar(&options.UpdateAfrogVersion, "update", false, "update afrog engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to latest released version"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.StringVar(&options.Proxy, "proxy", "", "list of http/socks5 proxy to use (comma separated or file input)"),
	)

	_ = flagSet.Parse()

	return options
}
