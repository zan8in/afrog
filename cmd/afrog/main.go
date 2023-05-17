package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "net/http/pprof"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pkg/runner"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

func main() {

	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	options, err := config.NewOptions()
	if err != nil {
		gologger.Error().Msg(err.Error())
		os.Exit(0)
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("Could not create runner: %s\n", err)
		os.Exit(0)
	}

	var (
		lock      = sync.Mutex{}
		starttime = time.Now()
		number    uint32
	)
	r.OnResult = func(result *result.Result) {

		if !options.Silent {
			defer func() {
				atomic.AddUint32(&options.CurrentCount, 1)
				if !options.Silent {
					fmt.Printf("\r%d%% (%d/%d), %s", int(options.CurrentCount)*100/int(options.Count), options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if result.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			if !options.DisableOutputHtml {
				r.Report.SetResult(result)
				r.Report.Append(utils.GetNumberText(int(number)))
			}

			if len(options.Json) > 0 || len(options.JsonAll) > 0 {
				r.JsonReport.SetResult(result)
				r.JsonReport.Append()
			}

			lock.Unlock()
		}

	}

	if err := r.Run(); err != nil {
		gologger.Error().Msgf("runner run err: %s\n", err)
		os.Exit(0)
	}

	if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
			os.Exit(0)
		}
	}

	time.Sleep(time.Second * 3)

}
