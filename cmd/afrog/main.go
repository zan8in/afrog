package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/curated/service"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/web"
	"github.com/zan8in/fileutil"
	"github.com/zan8in/gologger"
)

func main() {

	options, err := config.NewOptions()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	if options.Config != nil {
		cur := options.Config.Curated
		enabled := strings.ToLower(strings.TrimSpace(cur.Enabled))
		if enabled != "off" && enabled != "false" && enabled != "0" {
			svc := service.New(service.Config{
				Endpoint:      strings.TrimSpace(cur.Endpoint),
				Channel:       strings.TrimSpace(cur.Channel),
				CuratedPocDir: "",
				LicenseKey:    strings.TrimSpace(cur.LicenseKey),
				NoUpdate:      cur.AutoUpdate != nil && !*cur.AutoUpdate && !options.CuratedForceUpdate,
				ForceUpdate:   options.CuratedForceUpdate,
				ClientVersion: config.Version,
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cur.TimeoutSec)*time.Second)
			if cur.TimeoutSec <= 0 {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			dir, err := svc.Mount(ctx)
			if err != nil {
				gologger.Warning().Msgf("curated mount failed: %s", strings.TrimSpace(err.Error()))
			} else if strings.TrimSpace(dir) != "" {
				_ = os.Setenv("AFROG_POCS_CURATED_DIR", dir)
			}
		}
	}

	if !options.Web && options.AfrogUpdate != nil {
		var curated *config.Curated
		if options.Config != nil {
			curated = &options.Config.Curated
		}
		config.ShowBanner(options.AfrogUpdate, curated)
	}

	if options.Web {
		cfg := options.Config
		addr := ":16868"
		if cfg != nil && cfg.ServerAddress != "" {
			addr = cfg.ServerAddress
		}
		if err = sqlite.NewWebSqliteDB(); err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		if err = sqlite.InitX(); err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		defer sqlite.CloseX()
		if err = web.StartServer(addr); err != nil {
			gologger.Error().Msg(err.Error())
		}
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
	var interrupted atomic.Bool
	defer func() {
		// 正常退出时删除自动保存文件
		if normalExit {
			if fileutil.FileExists(autoSaveFile) {
				if err = os.Remove(autoSaveFile); err == nil {
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

	progressEnabled := !options.Silent

	progressLine := func() string {
		total := options.Count
		current := atomic.LoadUint32(&options.CurrentCount)
		pgress := 0
		if total > 0 {
			pgress = int(current) * 100 / total
		}
		elapsed := strings.Split(time.Since(starttime).String(), ".")[0] + "s"

		suffix := ""
		if options.LiveStats {
			suffix = r.LiveStatsSuffix()
		}
		return fmt.Sprintf("[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(pgress, 0), pgress, current, total, elapsed, suffix)
	}

	renderProgress := func() {
		line := progressLine()
		fmt.Fprint(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}

	var progressDone chan struct{}
	var progressOnce sync.Once

	r.OnFingerprint = func(targetKey string, hits []fingerprint.Hit) {
		if len(hits) == 0 {
			return
		}
		for _, hit := range hits {
			sev := strings.TrimSpace(hit.Severity)
			if sev == "" {
				sev = "info"
			}
			name := strings.TrimSpace(hit.Name)
			if name == "" {
				name = strings.TrimSpace(hit.ID)
			}

			rst := r.FingerprintResult(targetKey, hit.ID)
			if rst == nil {
				rst = &result.Result{
					IsVul:      true,
					Target:     targetKey,
					FullTarget: targetKey,
					PocInfo: &poc.Poc{
						Id: hit.ID,
						Info: poc.Info{
							Name:     name,
							Severity: sev,
							Tags:     hit.Tags,
						},
					},
					FingerResult: []fingerprint.Hit{hit},
				}
			} else {
				rst.IsVul = true
				if rst.PocInfo == nil {
					rst.PocInfo = &poc.Poc{Id: hit.ID}
				} else {
					rst.PocInfo.Id = hit.ID
				}
				rst.PocInfo.Info.Name = name
				rst.PocInfo.Info.Severity = sev
				rst.PocInfo.Info.Tags = hit.Tags
				rst.FingerResult = []fingerprint.Hit{hit}
			}
			if strings.TrimSpace(rst.FullTarget) == "" {
				rst.FullTarget = rst.Target
			}

			lock.Lock()
			fmt.Fprint(os.Stderr, "\r\033[2K\r")

			atomic.AddUint32(&number, 1)
			rst.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))
			if progressEnabled {
				renderProgress()
			}

			sqlite.SetResultX(rst)

			if options.Dingtalk {
				go r.Ding.SendMarkDownMessageBySlice("From afrog vulnerability Notice", r.Ding.MarkdownText(rst.PocInfo.Id, rst.PocInfo.Info.Severity, rst.FullTarget))
			}

			if !options.DisableOutputHtml {
				r.Report.SetResult(rst)
				r.Report.Append(utils.GetNumberText(int(number)))
			}

			if len(options.Json) > 0 || len(options.JsonAll) > 0 {
				r.JsonReport.SetResult(rst)
				r.JsonReport.Append()
			}

			lock.Unlock()
		}
	}

	r.OnResult = func(result *result.Result) {
		// add recover @edit 2025/06/12
		defer func() {
			if err := recover(); err != nil {
				gologger.Error().Msgf("OnResult panic: %v", err)
			}
		}()

		if options.LiveStats && progressEnabled {
			progressOnce.Do(func() {
				progressDone = make(chan struct{})
				lock.Lock()
				renderProgress()
				lock.Unlock()
				go func() {
					ticker := time.NewTicker(1 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-progressDone:
							return
						case <-ticker.C:
							lock.Lock()
							renderProgress()
							lock.Unlock()
						}
					}
				}()
			})
		}

		defer func() {
			atomic.AddUint32(&options.CurrentCount, 1)
			if progressEnabled && !options.LiveStats {
				lock.Lock()
				renderProgress()
				lock.Unlock()
			}
		}()

		if options.Debug {
			result.Debug()
		}

		if result.IsVul {
			lock.Lock()
			fmt.Fprint(os.Stderr, "\r\033[2K\r")

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))
			if progressEnabled {
				renderProgress()
			}

			sqlite.SetResultX(result)

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
	var signalOnce sync.Once
	go func(runner *runner.Runner) {
		for range c {
			handled := false
			signalOnce.Do(func() {
				handled = true
			})
			if !handled {
				os.Exit(1)
			}

			gologger.Print().Msg("")
			gologger.Info().Msg("Scan termination signal received")

			interrupted.Store(true)
			runner.Stop()

			// 立即保存进度
			if err := r.ScanProgress.AtomicSave(autoSaveFile); err != nil {
				gologger.Error().Msgf("Could not preserve scan state: %s", err)
			} else {
				gologger.Info().Msgf("Scan state archived: %s\n", autoSaveFile)
				// gologger.Info().Msgf("Resume command: afrog -T urls.txt -resume %s\n", autoSaveFile)
			}
		}
	}(r)

	// 启动定时保存协程
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Done():
				return
			case <-ticker.C:
				if err := r.ScanProgress.AtomicSave(autoSaveFile); err != nil {
					gologger.Debug().Msgf("auto save file failed: %s", err)
				}
			}
		}
	}()

	if err := r.Run(); err != nil {
		gologger.Error().Msgf("runner run err: %s\n", err)
		return
	}
	if progressDone != nil {
		close(progressDone)
		progressDone = nil
	}

	if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
			return
		}
	}

	sqlite.CloseX()
	gologger.Print().Msg("")

	lock.Lock()
	if progressEnabled {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
	lock.Unlock()

	status := "completed"
	if interrupted.Load() {
		status = "stopped"
	}
	gologger.Info().Msgf("%-9s | %-9s | tasks=%d/%d found=%d duration=%s",
		utils.StageVulnScan,
		status,
		atomic.LoadUint32(&options.CurrentCount),
		options.Count,
		atomic.LoadUint32(&number),
		time.Since(starttime).Truncate(time.Second),
	)

	// 标记正常退出
	normalExit = !interrupted.Load()
}

func expandTildePath(v string) string {
	s := strings.TrimSpace(os.ExpandEnv(v))
	if s == "" {
		return s
	}
	s = filepath.FromSlash(s)
	sep := string(os.PathSeparator)
	if s == "~" || strings.HasPrefix(s, "~"+sep) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return filepath.Clean(s)
		}
		if s == "~" {
			return home
		}
		return filepath.Join(home, strings.TrimPrefix(s, "~"+sep))
	}
	return filepath.Clean(s)
}
