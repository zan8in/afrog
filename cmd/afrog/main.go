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
	"github.com/zan8in/fileutil"
	"github.com/zan8in/gologger"
)

func main() {

	options, err := config.NewOptions()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	var autoSaveFile string
	if len(options.Resume) > 0 {
		// 使用恢复文件路径作为保存路径
		autoSaveFile = options.Resume
	} else {
		// 新扫描任务才生成新文件名
		baseName := config.GetFileBaseName(options)
		autoSaveFile = fmt.Sprintf("afrog-resume-%s-%s.afg", baseName, time.Now().Format("20060102-150405"))
	}

	// 添加正常退出标记
	var normalExit bool
	defer func() {
		// 正常退出时删除自动保存文件
		if normalExit {
			if fileutil.FileExists(autoSaveFile) {
				if err := os.Remove(autoSaveFile); err == nil {
					gologger.Debug().Msgf("已清理自动保存文件: %s", autoSaveFile)
				}
			}
		}
		sqlite.CloseX()
	}()

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("Could not create runner: %s\n", err)
		return
	}

	err = sqlite.InitX()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	var (
		lock      = sync.Mutex{}
		starttime = time.Now()
		number    uint32
	)
	r.OnResult = func(result *result.Result) {
		// add recover @edit 2025/06/12
		defer func() {
			if err := recover(); err != nil {
				gologger.Error().Msgf("OnResult panic: %v", err)
			}
		}()

		if !options.Silent {
			defer func() {
				atomic.AddUint32(&options.CurrentCount, 1)
				if !options.Silent {
					// 花里胡哨的进度条，看起来炫，实际并没什么卵用！ @edit 2024/01/03
					pgress := int(options.CurrentCount) * 100 / options.Count
					// 兼容性进度条 @edit 2025/03/29
					fmt.Printf("\r[%s] %d%% (%d/%d), %s", progress.GetProgressBar(pgress, 0), pgress, options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r[%s] %d%% (%d/%d), %s", progress.CreateProgressBar(pgress, 50, '▉', '░'), pgress, options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
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

	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func(runner *runner.Runner) {
		for range c {
			gologger.Print().Msg("")
			gologger.Info().Msg("Scan termination signal received")

			// 立即保存进度
			if err := r.ScanProgress.AtomicSave(autoSaveFile); err != nil {
				gologger.Error().Msgf("Could not preserve scan state: %s", err)
			} else {
				gologger.Info().Msgf("Scan state archived: %s\n", autoSaveFile)
				// gologger.Info().Msgf("Resume command: afrog -T urls.txt -resume %s\n", autoSaveFile)
			}

			// 直接退出不触发正常清理
			sqlite.CloseX()
			// gologger.Info().Msg("Process terminated (exit code 1)")
			os.Exit(1)
		}
	}(r)

	// 启动定时保存协程
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := r.ScanProgress.AtomicSave(autoSaveFile); err != nil {
				gologger.Debug().Msgf("auto save file failed: %s", err)
			}
		}
	}()

	if err := r.Run(); err != nil {
		gologger.Error().Msgf("runner run err: %s\n", err)
		return
	}

	if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
			return
		}
	}

	time.Sleep(time.Second * 3)
	gologger.Print().Msg("")

	// 标记正常退出
	normalExit = true
}
