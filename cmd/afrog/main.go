package main

import (
	"fmt"
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
		gologger.Fatal().Msg(err.Error())
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
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
					fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if result.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			r.Report.SetResult(result)
			r.Report.Append(utils.GetNumberText(int(number)))

			if len(options.Json) > 0 {
				options.OJ.AddJson(result.PocInfo.Id, result.PocInfo.Info.Severity, result.FullTarget)
			}

			lock.Unlock()
		}

	}

	if err := r.Run(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	time.Sleep(time.Second * 3)

}
