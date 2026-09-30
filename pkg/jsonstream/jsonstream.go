// Package jsonstream 把 afrog CLI 的一次扫描接到 pkg/scanstream 的 NDJSON 事件流上。
//
// 它只服务于 `afrog -json-stream` 这一种运行方式：stdout 专门承载事件流，人类可读
// 输出一律改道 stderr。之所以放在库包里而不是 cmd/afrog 目录下，是因为 README 与
// 安装文档都写着 `go run cmd/afrog/main.go` / `go build -o afrog cmd/afrog/main.go`，
// 单文件构建不会编译同目录的其它文件。
package jsonstream

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
)

// stderrLogWriter 把所有级别的 gologger 输出都写到 stderr。
// gologger 默认 writer 会把 Silent/Print 级别写到 stdout，而 -json-stream 模式下
// stdout 必须只承载 NDJSON 事件流，因此这里统一改道。
type stderrLogWriter struct{}

func (stderrLogWriter) Write(data []byte, _ levels.Level) {
	_, _ = os.Stderr.Write(data)
	_, _ = os.Stderr.Write([]byte("\n"))
}

// RedirectLogs 把 gologger 的默认输出从「部分级别写 stdout」改为统一写 stderr。
func RedirectLogs() {
	gologger.DefaultLogger.SetWriter(stderrLogWriter{})
}

// buildResultEvidence 复用 -json-all 报告使用的请求/响应文本，避免自造格式。
// 参考 pkg/report/json.go 的 JsonContent：请求取 Raw 原文，响应经 UTF-8 归一化。
func buildResultEvidence(res *result.Result) *scanstream.Evidence {
	if res == nil {
		return nil
	}
	ev := &scanstream.Evidence{}
	for _, pr := range res.AllPocResult {
		if pr == nil {
			continue
		}
		ex := scanstream.Exchange{Matched: pr.IsVul}
		if req := pr.ResultRequest; req != nil {
			ex.Request = string(req.GetRaw())
		}
		if resp := pr.ResultResponse; resp != nil {
			ex.Response = utils.Str2UTF8(string(resp.GetRaw()))
		}
		ev.Exchanges = append(ev.Exchanges, ex)
	}
	if len(res.Extractor) > 0 {
		m := make(map[string]string, len(res.Extractor))
		for _, item := range res.Extractor {
			k, ok := item.Key.(string)
			if !ok {
				continue
			}
			if v, ok := item.Value.(string); ok {
				m[k] = utils.Str2UTF8(v)
			}
		}
		if len(m) > 0 {
			ev.Extractors = m
		}
	}
	if len(ev.Exchanges) == 0 && len(ev.Extractors) == 0 {
		return nil
	}
	return ev
}

// buildResultEvent 把内部 result 转换为 ResultEvent，非命中返回 nil。
func buildResultEvent(res *result.Result) *scanstream.ResultEvent {
	if res == nil || !res.IsVul {
		return nil
	}
	ev := &scanstream.ResultEvent{
		Target:   res.FullTarget,
		Evidence: buildResultEvidence(res),
	}
	if strings.TrimSpace(ev.Target) == "" {
		ev.Target = res.Target
	}
	if res.PocInfo != nil {
		ev.PocID = res.PocInfo.Id
		ev.PocName = res.PocInfo.Info.Name
		ev.Severity = res.PocInfo.Info.Severity
	}
	return ev
}

// ShouldReportFingerprint 判断某个指纹命中是否应该计入报告 / 台账 / 事件流。
//
// -S 指定了严重级别时只有匹配的级别会上报；未指定则全部上报。
// 命令行的指纹落库（曾出现「台账有、事件流没有」）与事件流共用这一个判定，
// 保证前端看到的命中集合与台账一致。
func ShouldReportFingerprint(options *config.Options, severity string) bool {
	if options == nil || strings.TrimSpace(options.Severity) == "" {
		return true
	}

	severity = strings.ToLower(strings.TrimSpace(severity))
	for _, item := range strings.Split(options.Severity, ",") {
		if strings.EqualFold(severity, strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

// webProbeFingerprint 把 WebMeta 的 Server/PoweredBy 合并为协议里的 fingerprint 字段。
func webProbeFingerprint(meta runner.WebMeta) string {
	parts := make([]string, 0, 2)
	if s := strings.TrimSpace(meta.Server); s != "" {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(meta.PoweredBy); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

// Attach 挂载所有事件钩子并启动扫描级进度上报。
// 返回的函数用于收尾：停止 ticker 并发送带 Summary 的 DoneEvent。
//
// 所有钩子都采用「先调用原有回调、再发送事件」的链式写法；
// Result 钩子先让原有回调完成（它可能持有调用方的锁），再写事件流，
// 避免两把锁交叉持有。
func Attach(w *scanstream.Writer, options *config.Options, r *runner.Runner, taskStart time.Time) func(status string, found int64, executed int64) {
	var statMu sync.Mutex
	bySeverity := make(map[string]int64)

	prevPhase := options.OnPhaseProgress
	options.OnPhaseProgress = func(phase string, status string, finished int64, total int64, percent int) {
		if prevPhase != nil {
			prevPhase(phase, status, finished, total, percent)
		}
		w.Phase(phase, status, finished, total, percent)
	}

	// 前置汇总：total_scans 就是命令行打印的 tasks=，消费方据此消除
	// 「前端总数」与「命令行总数」两个口径的差异。
	prevInfo := options.OnScanInfoUpdate
	options.OnScanInfoUpdate = func(info config.ScanInfoUpdate) {
		if prevInfo != nil {
			prevInfo(info)
		}
		w.ScanInfo(&scanstream.ScanInfoEvent{
			TotalTargets: info.TotalTargets,
			TotalPocs:    info.TotalPocs,
			TotalScans:   info.TotalScans,
			OOBEnabled:   info.OOBEnabled,
			OOBStatus:    info.OOBStatus,
		})
	}

	prevPort := options.OnPortScanResult
	options.OnPortScanResult = func(host string, port int) {
		if prevPort != nil {
			prevPort(host, port)
		}
		w.Port(host, port)
	}

	prevHost := options.OnHostDiscovered
	options.OnHostDiscovered = func(host string) {
		if prevHost != nil {
			prevHost(host)
		}
		w.Host(host)
	}

	prevWebProbe := r.OnWebProbe
	r.OnWebProbe = func(meta runner.WebMeta) {
		if prevWebProbe != nil {
			prevWebProbe(meta)
		}
		w.WebProbe(&scanstream.WebProbeEvent{
			URL:         meta.URL,
			Title:       meta.Title,
			Fingerprint: webProbeFingerprint(meta),
		})
	}

	prevResult := r.OnResult
	r.OnResult = func(res *result.Result) {
		if prevResult != nil {
			prevResult(res)
		}
		ev := buildResultEvent(res)
		if ev == nil {
			return
		}
		statMu.Lock()
		bySeverity[ev.Severity]++
		statMu.Unlock()
		w.Result(ev)
	}

	// 指纹命中（多为 info，例如 nginx-detect）走的是独立回调：它此前只写报告/台账，
	// 从不进事件流，于是「台账里有、扫描详情的漏洞列表是 0」。这里补上同一条通路，
	// 过滤规则与落库共用 ShouldReportFingerprint，避免前端比台账多出被过滤的命中。
	prevFingerprint := r.OnFingerprint
	r.OnFingerprint = func(targetKey string, hits []fingerprint.Hit) {
		if prevFingerprint != nil {
			prevFingerprint(targetKey, hits)
		}
		for _, hit := range hits {
			sev := strings.TrimSpace(hit.Severity)
			if sev == "" {
				sev = "info"
			}
			if !ShouldReportFingerprint(options, sev) {
				continue
			}
			name := strings.TrimSpace(hit.Name)
			if name == "" {
				name = strings.TrimSpace(hit.ID)
			}
			statMu.Lock()
			bySeverity[sev]++
			statMu.Unlock()
			w.Result(&scanstream.ResultEvent{
				Target:   targetKey,
				PocID:    hit.ID,
				PocName:  name,
				Severity: sev,
			})
		}
	}

	// 扫描级进度：每秒上报一次，口径与命令行 tasks= 一致。
	progressDone := make(chan struct{})
	progressStopped := make(chan struct{})
	go func() {
		defer close(progressStopped)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				finished := int64(atomic.LoadUint32(&options.CurrentCount))
				total := int64(options.Count)
				percent := 0
				if total > 0 {
					percent = int(finished * 100 / total)
				}
				if percent < 0 {
					percent = 0
				}
				if percent > 100 {
					percent = 100
				}
				w.Progress(percent, finished, total, 0, time.Since(taskStart).Milliseconds())
			}
		}
	}()

	var once sync.Once
	return func(status string, found int64, executed int64) {
		once.Do(func() { close(progressDone) })
		// 必须等 ticker 协程退出，否则 done 之后可能再冒出一条 progress 事件
		<-progressStopped

		statMu.Lock()
		dist := make(map[string]int64, len(bySeverity))
		for k, v := range bySeverity {
			dist[k] = v
		}
		statMu.Unlock()
		if len(dist) == 0 {
			dist = nil
		}

		w.Done(status, &scanstream.Summary{
			Executed:   executed,
			Found:      found,
			BySeverity: dist,
			ElapsedMs:  time.Since(taskStart).Milliseconds(),
		})
	}
}
