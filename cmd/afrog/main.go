package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "net/http/pprof"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/db/sqlite"
	"github.com/zan8in/afrog/pkg/progress"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pkg/runner"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

func main() {
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

	err = sqlite.InitX()
	if err != nil {
		gologger.Error().Msg(err.Error())
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
					// 花里胡哨的进度条，看起来炫，实际并没什么卵用！ @edit 2024/01/03
					pgress := int(options.CurrentCount) * 100 / options.Count
					// bar := progress.CreateProgressBar(pgress, 50, '|', '=')
					// bar := progress.CreateProgressBar(pgress, 50, '▉', '░') 操蛋的 windows cmd 不兼容漂亮的进度条
					// fmt.Printf("\r%s %d%% (%d/%d), %s", bar, pgress, options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r%d%% (%d/%d), %s", int(options.CurrentCount)*100/int(options.Count), options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					fmt.Printf("\r[%s] %d%% (%d/%d), %s", progress.GetProgressBar(pgress, 0), pgress, options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if result.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			go sqlite.SetResultX(result)

			if options.Dingtalk {
				go r.Ding.SendMarkDownMessageBySlice("From afrog vulnerability Notice", r.Ding.MarkdownText(result.PocInfo.Id, result.PocInfo.Info.Severity, result.FullTarget))
			}

			if !options.DisableOutputHtml {
				r.Report.SetResult(result)
				r.Report.Append(utils.GetNumberText(int(number)))
			}

			if len(options.Json) > 0 || len(options.JsonAll) > 0 {
				r.JsonReport.SetResult(result)
				r.JsonReport.Append()
			}

			if options.VulnerabilityScannerBreakpoint {
				os.Exit(0)
			}

			lock.Unlock()
		}

		if options.Debug {
			result.Debug()
		}

	}

	// Setup graceful exits
	// resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func(runner *runner.Runner) {
		for range c {
			gologger.Print().Msg("")
			gologger.Info().Msg("CTRL+C pressed: Exiting")
			// gologger.Info().Msgf("Current scan progress: %s\n", runner.ScanProgress.String())

			resumeFileName, err := runner.ScanProgress.SaveScanProgress()
			if len(resumeFileName) > 0 {
				gologger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
				gologger.Info().Msgf("Resume Example: afrog -resume %s\n", resumeFileName)
			}
			if err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
			os.Exit(0)
		}
	}(r)

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
	gologger.Print().Msg("")

	sqlite.CloseX()
}
