package main

import (
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
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/jsonstream"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/scanapi"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/web"
	"github.com/zan8in/fileutil"
	"github.com/zan8in/gologger"
)

// shouldReportFingerprintHit 判断指纹命中是否上报。判定与事件流共用同一实现，
// 保证「写进报告/台账的命中」与「前端事件流看到的命中」是同一集合。
func shouldReportFingerprintHit(options *config.Options, severity string) bool {
	return jsonstream.ShouldReportFingerprint(options, severity)
}

func main() {

	// 子命令分派：goflags 只认 flag，`afrog serve` 这种子命令必须在解析前分流，
	// 否则 --listen 之类的参数会被当成未知 flag 报错。
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		if err := scanapi.ServeCommand(os.Args[2:]); err != nil {
			gologger.Error().Msg(err.Error())
		}
		return
	}

	options, err := config.NewOptions()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	// -json-stream 模式：stdout 只承载 NDJSON 事件流，人类可读输出一律改道或关闭
	jsonStreamMode := options.JsonStream
	var jsonStream *scanstream.Writer
	if jsonStreamMode {
		jsonstream.RedirectLogs()
		// Silent 关掉引擎的人类可读输出：stdout 此时只允许出现 NDJSON，
		// 任何「结果行」都不该额外打一份到控制台。
		options.Silent = true
		// 由执行器拉起时，任务 ID 由父进程通过 AFROG_TASK_ID 指定，事件信封与
		// 写库都要用它，父进程才能把事件与结果关联到同一个任务上。
		taskID := strings.TrimSpace(os.Getenv("AFROG_TASK_ID"))
		if taskID == "" {
			taskID = fmt.Sprintf("%s-%s", config.GetFileBaseName(options), time.Now().Format("20060102-150405"))
		}
		jsonStream = scanstream.NewWriter(os.Stdout, "local", taskID)
	}

	if options.Config != nil {
		// 会员（curated）能力的装配与 Web 端「会员中心」保存配置共用同一实现，
		// 避免"启动会清理残留、保存却不会"这类口径漂移。拉不到 PoC 不等于未激活。
		if err := web.AssembleCurated(options.Config.Curated, options.ConfigFile, options.CuratedForceUpdate); err != nil {
			gologger.Warning().Msgf("curated mount failed: %s", strings.TrimSpace(err.Error()))
		}
	}

	if !options.Web && !jsonStreamMode && options.AfrogUpdate != nil {
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
		// 多实例编排、AI 辅助、OOB 凭据与会员配置都来自 afrog-config.yaml
		// （cluster / ai / reverse / curated 段）；一并把配置文件路径交给 Web 层：
		// 界面保存时要写回这个文件。
		if cfg != nil {
			web.SetClusterConfig(cfg.Cluster, options.ConfigFile)
			web.SetAIConfig(cfg.AI, options.ConfigFile)
			web.SetOOBConfig(cfg.Reverse, options.ConfigFile)
		}
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
		webhookWG = sync.WaitGroup{}
		starttime = time.Now()
		number    uint32
	)

	progressEnabled := !options.Silent
	type oobFinalizeProgress struct {
		Active   bool
		Status   string
		Finished int64
		Total    int64
		Percent  int
	}
	var oobFinalize atomic.Value
	oobFinalize.Store(oobFinalizeProgress{})

	// 端口扫描与 Web 探测阶段的进度由 OnPhaseProgress 提供，这里存下来供进度条渲染。
	// 三个阶段共用 progress.RenderLine，形状与字段完全一致，用户从阶段名就能看出
	// 当前是在扫端口、探 Web 还是跑漏洞。
	type phaseBarState struct {
		status   string
		finished int64
		total    int64
		percent  int
		started  time.Time
	}
	var portBar, webBar atomic.Value
	portBar.Store(phaseBarState{})
	webBar.Store(phaseBarState{})
	recordPhase := func(dst *atomic.Value, status string, finished, total int64, percent int) {
		prev, _ := dst.Load().(phaseBarState)
		next := phaseBarState{status: status, finished: finished, total: total, percent: percent}
		// started 只在阶段进入 running 的那一刻取一次，后续同一个阶段的回调沿用，
		// 否则每次刷新都会把已用时间重置成 0，速率与 ETA 会算错。
		if status == "running" && prev.status != "running" {
			next.started = time.Now()
		} else {
			next.started = prev.started
		}
		dst.Store(next)
	}

	progressLine := func() string {
		if st, ok := webBar.Load().(phaseBarState); ok && st.status == "running" {
			return progress.RenderLine(utils.StageWebProbe, st.percent, st.finished, st.total, time.Since(st.started), "")
		}
		if st, ok := portBar.Load().(phaseBarState); ok && st.status == "running" {
			return progress.RenderLine(utils.StagePortScan, st.percent, st.finished, st.total, time.Since(st.started), "")
		}

		// 漏洞扫描阶段沿用 engine 统计的任务数（当前阶段之外 Count 还是 0，进度条留空）。
		total := int64(options.Count)
		if total <= 0 {
			return ""
		}
		current := int64(atomic.LoadUint32(&options.CurrentCount))
		pgress := int(current * 100 / total)

		suffix := ""
		if options.LiveStats {
			suffix = r.LiveStatsSuffix()
		} else {
			if pedm := r.PedmStatusSuffix(); pedm != "" {
				suffix += pedm
			}
			if v, ok := oobFinalize.Load().(oobFinalizeProgress); ok && strings.TrimSpace(v.Status) != "" {
				remain := v.Total - v.Finished
				if remain < 0 {
					remain = 0
				}
				if v.Total < 0 {
					v.Total = 0
				}
				suffix = fmt.Sprintf(" oobf=%d/%d %s", remain, v.Total, v.Status)
			}
		}
		tail := fmt.Sprintf(" found=%d%s", atomic.LoadUint32(&number), suffix)
		return progress.RenderLine(utils.StageVulnScan, pgress, current, total, time.Since(starttime), tail)
	}

	renderProgress := func() {
		line := progressLine()
		if line == "" {
			return
		}
		fmt.Fprint(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}

	printProgressAwareLog := func(line string) {
		lock.Lock()
		defer lock.Unlock()
		if progressEnabled && progressLine() != "" {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		gologger.Print().Msg(line)
		if progressEnabled && !options.LiveStats {
			renderProgress()
		}
	}

	var progressDone chan struct{}
	if progressEnabled {
		progressDone = make(chan struct{})
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

		prev := options.OnPhaseProgress
		options.OnPhaseProgress = func(phase string, status string, finished int64, total int64, percent int) {
			if prev != nil {
				prev(phase, status, finished, total, percent)
			}
			phase = strings.ToLower(strings.TrimSpace(phase))
			status = strings.ToLower(strings.TrimSpace(status))
			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}

			// 端口扫描 / Web 探测阶段的分母不是漏洞任务数，用阶段回调的数据单独渲染进度条。
			switch phase {
			case "portscan", "webprobe":
				if phase == "portscan" {
					recordPhase(&portBar, status, finished, total, percent)
				} else {
					recordPhase(&webBar, status, finished, total, percent)
				}
				lock.Lock()
				renderProgress()
				lock.Unlock()
				return
			case "oob_finalize":
			default:
				return
			}

			next := oobFinalizeProgress{
				Active:   status == "running",
				Status:   status,
				Finished: finished,
				Total:    total,
				Percent:  percent,
			}
			cur, _ := oobFinalize.Load().(oobFinalizeProgress)
			if cur.Status == next.Status && cur.Finished == next.Finished && cur.Total == next.Total && cur.Percent == next.Percent && cur.Active == next.Active {
				return
			}
			oobFinalize.Store(next)

			lock.Lock()
			renderProgress()
			lock.Unlock()
		}
	}

	options.OnPedmLog = func(line string) {
		printProgressAwareLog(line)
	}

	r.OnFingerprint = func(targetKey string, hits []fingerprint.Hit) {
		if len(hits) == 0 {
			return
		}
		for _, hit := range hits {
			sev := strings.TrimSpace(hit.Severity)
			if sev == "" {
				sev = "info"
			}
			if !shouldReportFingerprintHit(options, sev) {
				continue
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
			if !jsonStreamMode {
				rst.PrintColorResultInfoConsole()
			}
			if progressEnabled {
				renderProgress()
			}

			sqlite.SetResultX(rst)

			if options.Dingtalk {
				webhookWG.Add(1)
				go func() {
					defer webhookWG.Done()
					if err := r.Ding.SendMarkDownMessageBySlice("From afrog vulnerability Notice", r.Ding.MarkdownText(rst.PocInfo.Id, rst.PocInfo.Info.Severity, rst.FullTarget)); err != nil {
						gologger.Error().Msgf("dingtalk webhook send failed: %v", err)
					}
				}()
			}
			if options.Wecom {
				webhookWG.Add(1)
				go func() {
					defer webhookWG.Done()
					if err := r.Wecom.SendVulMessage(rst, r.Wecom.Markdown); err != nil {
						gologger.Error().Msgf("wecom webhook send failed: %v", err)
					}
				}()
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

		defer func() {
			if result == nil || !result.SkipCount {
				atomic.AddUint32(&options.CurrentCount, 1)
			}
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
			if !jsonStreamMode {
				result.PrintColorResultInfoConsole()
			}
			if progressEnabled {
				renderProgress()
			}

			sqlite.SetResultX(result)

			if options.Dingtalk {
				webhookWG.Add(1)
				go func() {
					defer webhookWG.Done()
					if err := r.Ding.SendMarkDownMessageBySlice("From afrog vulnerability Notice", r.Ding.MarkdownText(result.PocInfo.Id, result.PocInfo.Info.Severity, result.FullTarget)); err != nil {
						gologger.Error().Msgf("dingtalk webhook send failed: %v", err)
					}
				}()
			}

			if options.Wecom {
				webhookWG.Add(1)
				go func() {
					defer webhookWG.Done()
					if err := r.Wecom.SendVulMessage(result, r.Wecom.Markdown); err != nil {
						gologger.Error().Msgf("wecom webhook send failed: %v", err)
					}
				}()
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

	var jsonStreamFinish func(status string, found int64, executed int64)
	if jsonStream != nil {
		jsonStream.Status("starting")
		jsonStreamFinish = jsonstream.Attach(jsonStream, options, r, starttime)
		jsonStream.Status("running")
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
			gologger.Print().Msg("Scan termination signal received")

			interrupted.Store(true)
			runner.Stop()

			// 立即保存进度
			if err := r.ScanProgress.AtomicSave(autoSaveFile, atomic.LoadUint32(&options.CurrentCount), uint32(options.Count)); err != nil {
				gologger.Error().Msgf("Could not preserve scan state: %s", err)
			} else {
				gologger.Print().Msgf("Scan state archived: %s\n", autoSaveFile)
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
				if err := r.ScanProgress.AtomicSave(autoSaveFile, atomic.LoadUint32(&options.CurrentCount), uint32(options.Count)); err != nil {
					gologger.Debug().Msgf("auto save file failed: %s", err)
				}
			}
		}
	}()

	runErr := r.Run()

	// 中断/出错时同样要停掉进度条定时器并输出收尾汇总，
	// 否则终端会残留一行进度条，用户也看不到本轮完成情况与断点文件提示。
	if progressDone != nil {
		close(progressDone)
		progressDone = nil
	}

	if runErr != nil {
		if jsonStream != nil {
			jsonStream.Error("scan_failed", runErr.Error())
		}
		gologger.Error().Msgf("runner run err: %s\n", runErr.Error())
	} else if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
		}
	}

	webhookWG.Wait()
	sqlite.CloseX()
	gologger.Print().Msg("")

	lock.Lock()
	if progressEnabled {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
	lock.Unlock()

	status := "completed"
	if interrupted.Load() || runErr != nil {
		status = "stopped"
	}
	if jsonStreamFinish != nil {
		jsonStreamFinish(status, int64(atomic.LoadUint32(&number)), int64(atomic.LoadUint32(&options.CurrentCount)))
	}
	gologger.Print().Msgf("%-9s | %-9s | tasks=%d/%d found=%d duration=%s",
		utils.StageVulnScan,
		status,
		atomic.LoadUint32(&options.CurrentCount),
		options.Count,
		atomic.LoadUint32(&number),
		time.Since(starttime).Truncate(time.Second),
	)

	// 未跑完（中断/出错）时给出恢复命令，用户可以接着扫而不是从头再来。
	if status == "stopped" && fileutil.FileExists(autoSaveFile) {
		args := strings.Join(os.Args[1:], " ")
		if len(options.Resume) > 0 {
			gologger.Print().Msgf("resume: afrog %s", args)
		} else {
			gologger.Print().Msgf("resume: afrog %s -resume %s", args, autoSaveFile)
		}
	}

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
