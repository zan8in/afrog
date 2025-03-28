package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

func main() {
	options, err := config.NewOptions()
	if err != nil {
		gologger.Error().Msg(err.Error())
		os.Exit(0)
	}

	// 创建runner之后立即定义panic恢复
	var r *runner.Runner
	defer func() {
		if rec := recover(); rec != nil {
			gologger.Print().Msg("")
			gologger.Error().Msgf("Critical error occurred: %v", rec)
			if r != nil {
				saveProgressAndExit(r)
			}
			os.Exit(1)
		}
	}()

	r, err = runner.NewRunner(options)
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

		if options.Debug {
			result.Debug()
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

	}

	// Setup graceful exits
	// resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	// 捕获更多信号
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func(runner *runner.Runner) {
		for range c {
			gologger.Print().Msg("")
			gologger.Info().Msg("Received termination signal: Exiting")
			saveProgressAndExit(runner)
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

// 封装保存进度和退出逻辑
func saveProgressAndExit(r *runner.Runner) {
	resumeFileName, err := r.ScanProgress.SaveScanProgress()
	if len(resumeFileName) > 0 {
		gologger.Info().Msgf("Creating resume file: %s", resumeFileName)
		gologger.Info().Msgf("Resume Example: afrog -T urls.txt -resume %s", resumeFileName)
	}
	if err != nil {
		gologger.Error().Msgf("Couldn't create resume file: %s", err)
	}

	// 确保数据库关闭
	sqlite.CloseX()
	os.Exit(0)
}
