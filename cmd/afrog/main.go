package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/fingerprint"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/runner"
	"github.com/zan8in/afrog/pkg/targetlive"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

var (
	htemplate = &html.HtmlTemplate{}
	lock      sync.Mutex
	number    uint32 = 0
)

func main() {
	runner.ShowBanner()

	options, err := config.ParseOptions()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	starttime := time.Now()

	err = runner.New(options, htemplate, func(result any) {
		r := result.(*core.Result)

		defer func() {
			options.Count = int(options.TargetsTotal) * int(options.PocsTotal)
			atomic.AddUint32(&options.CurrentCount, 1)
			if !options.Silent {
				fmt.Printf("\r%d/%d/%d%%/%s | hosts: %d, closed: %d", options.CurrentCount, options.Count, int(options.CurrentCount)*100/options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s", options.TargetsTotal, targetlive.TLive.GetNoLiveAtomicCount())
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
