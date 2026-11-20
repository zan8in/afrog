package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

// scanRun 是一次子进程扫描的产物。
type scanRun struct {
	// Results 是归一化后的命中，字段与旧 verify.* 的 results 保持同构；
	// evidence 里是原生证据对象（id/digest/steps/replay）。
	Results []map[string]any
	// Status 取值 completed / timeout / failed / cancelled，与控制面的终态同源。
	Status string
	// Summary 是子进程给出的汇总（executed/found/by_severity/elapsed_ms）。
	Summary *scanstream.Summary
	// Error 是任务级错误文本，出错时有值。
	Error string
}

func newScanRun() *scanRun {
	// Results 预置为空切片：没有命中时若为 nil，会被序列化成 null，
	// 与 scan.start 等工具的 outputSchema 里 "results": array 冲突。
	return &scanRun{Results: []map[string]any{}}
}

// scanOutcome 是一次长任务提交的结果。
//
// 两种形态二选一：Run 非空表示跑完了（调用方拿到完整结果，与旧契约一致）；
// TaskID 非空而 Run 为 nil 表示转成了异步句柄，由 task.* 继续跟踪。
type scanOutcome struct {
	Run    *scanRun
	TaskID string
	// Status 是转句柄那一刻的控制面状态（跑完时为空，以 Run.Status 为准）。
	Status string
}

// Done 报告这次提交是否已经跑完（而不是转成了句柄）。
func (o *scanOutcome) Done() bool { return o != nil && o.Run != nil }

// baseScanSpec 是所有 MCP 扫描共享的底座。
//
// 单目标、按关键词选 PoC、默认开 Web 指纹：MCP 的动作是「对一个已知目标做按需检测」，
// 不是资产发现——所以不开端口扫描与主机发现。Web 指纹（-w）能独立满足
// requires: [thinkphp] 这类门控，是 -s 之外的第二条准入来源。
func baseScanSpec(target, search string) *executor.Spec {
	return &executor.Spec{
		Targets:        []string{strings.TrimSpace(target)},
		Search:         strings.TrimSpace(search),
		WebFingerprint: executor.BoolPtr(true),
	}
}

// submitScan 把一次扫描交给控制面任务层，并按 wait 的语义返回结果或句柄。
//
// wait > 0 是「短等窗口」：窗口内跑完就照旧返回完整结果，超窗口则返回 task_id 句柄，
// 由 task.* 继续跟踪（scan.start / act.brute 用这一档——它们无后处理，超窗口转异步
// 不丢任何东西）。wait <= 0 是「等它收尾」：一直等到任务终态再返回（verify.replay /
// poc.submit 用这一档——它们的后处理依赖跑完的结果，不能拆成两步）。
//
// 执行本身仍走独立子进程：SDK 的 HTTP 客户端、限速器与协议探测缓存都是进程级全局
// 状态，同进程并发 scanner 会互相污染参数。返回的 error 只表示「提交失败」。
func (s *Server) submitScan(ctx context.Context, spec *executor.Spec, timeout, wait time.Duration) (*scanOutcome, error) {
	mgr, err := s.taskManager()
	if err != nil {
		return nil, err
	}
	snap, err := mgr.SubmitSpec(spec, nil)
	if err != nil {
		return nil, err
	}
	taskID := snap.ID
	// 任务的超时不再靠调用方的 ctx：调用方可能在窗口结束后就走了，而任务还要继续跑。
	// 看护到点取消任务，并记下「这是超时结束的」，供状态如实回报 timeout。
	s.watchTimeout(mgr, taskID, timeout)

	run, done := s.awaitScan(ctx, mgr, taskID, wait)
	if !done {
		return &scanOutcome{TaskID: taskID, Status: s.currentStatus(mgr, taskID)}, nil
	}
	return &scanOutcome{Run: run, TaskID: taskID, Status: run.Status}, nil
}

// awaitScan 订阅任务事件并折叠成 scanRun；返回 done=false 表示没等到收尾。
//
// wait > 0 时只等这么久的窗口，超时即返回 done=false（调用方改用句柄继续跟踪）；
// wait <= 0 时一直等到任务收尾或调用方 ctx 结束。两种情况下的终态都以控制面快照
// 为准，而不是子进程自报的 done：排队取消、超时终止这些结论只有控制面知道。
func (s *Server) awaitScan(ctx context.Context, mgr *scantask.Manager, taskID string, wait time.Duration) (*scanRun, bool) {
	sub, _, err := mgr.Subscribe(taskID, 0)
	if err != nil {
		return nil, false
	}
	defer sub.Close()

	// 进度/日志通道：客户端带了 progressToken（或当前传输支持中途推送）时才有。
	report := progressFrom(ctx)
	logf := loggerFrom(ctx)

	run := newScanRun()

	var window <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		window = timer.C
	}

	for {
		select {
		case <-window:
			return nil, false
		case <-ctx.Done():
			// 调用方放弃（客户端断开或 notifications/cancelled）：任务归控制面继续跑，
			// 这里只是不再等它。
			return nil, false
		case ev, ok := <-sub.Events():
			if !ok {
				// 订阅通道关闭 = 任务已收尾。
				s.sealScanRun(run, s.snapshotOf(mgr, taskID))
				return run, true
			}
			foldScanEvent(run, ev)
			reportScanProgress(report, ev)
			reportScanLog(logf, ev)
		}
	}
}

// currentStatus 取任务当前的控制面状态串（含超时折判）；任务不在表里时按 queued 处理
// ——刚提交就查不到只会是极短的竞态窗口。
func (s *Server) currentStatus(mgr *scantask.Manager, taskID string) string {
	snap := s.snapshotOf(mgr, taskID)
	if snap == nil {
		return string(scantask.StatusQueued)
	}
	return s.scanStatus(taskID, snap.Status)
}

// foldScanEvent 把一条事件折叠进 scanRun。
func foldScanEvent(run *scanRun, ev *scanstream.Event) {
	switch ev.Type {
	case scanstream.TypeResult:
		if ev.Result == nil {
			return
		}
		run.Results = append(run.Results, resultFromStream(ev.Result))
	case scanstream.TypeDone:
		if ev.Done != nil && ev.Done.Summary != nil {
			run.Summary = ev.Done.Summary
		}
	case scanstream.TypeError:
		if ev.Error != nil {
			run.Error = ev.Error.Message
		}
	}
}

// snapshotOf 取任务当前快照；任务不在表里时返回 nil（正常不会发生）。
func (s *Server) snapshotOf(mgr *scantask.Manager, taskID string) *scantask.Snapshot {
	t, ok := mgr.Get(taskID)
	if !ok {
		return nil
	}
	return t.Snapshot()
}

// sealScanRun 用控制面快照补齐 scanRun 的终态。
func (s *Server) sealScanRun(run *scanRun, snap *scantask.Snapshot) {
	if snap == nil {
		run.Status = "failed"
		if run.Error == "" {
			run.Error = "task state is unavailable"
		}
		return
	}
	run.Status = s.scanStatus(snap.ID, snap.Status)
	if run.Error == "" {
		run.Error = snap.Error
	}
	if run.Summary == nil && snap.Summary != nil {
		run.Summary = &scanstream.Summary{
			Executed:   snap.Summary.Executed,
			Found:      snap.Summary.Found,
			BySeverity: snap.Summary.BySeverity,
			ElapsedMs:  snap.Summary.ElapsedMs,
		}
	}
}

// scanStatus 把控制面状态折成 MCP 对外的状态串。
//
// 两者取值一一对应，只有一处例外：因超时被看护取消的任务，对调用方来说是 timeout
// 而不是 cancelled——「跑太久了」和「人去取消的」是两件不同的事。
func (s *Server) scanStatus(taskID string, st scantask.Status) string {
	if st == scantask.StatusCancelled && s.timedOut(taskID) {
		return "timeout"
	}
	return string(st)
}

// reportScanProgress 把子进程的进度事件转成一条 MCP progress 通知。
//
// afrog 引擎在扫描过程中约每秒发一条 progress、阶段切换时发一条 phase（见
// pkg/jsonstream），这是「长任务还在跑、还是已经卡住」的唯一在线信号——否则调用方
// 只能干等整批扫描结束（实测一次关键词扫描约 200 秒）。report 为 nil（客户端未带
// progressToken、或当前传输不支持中途推送）时直接返回：进度是可选增强，缺了不影响
// 扫描结果。
func reportScanProgress(report ProgressFunc, ev *scanstream.Event) {
	if report == nil || ev == nil {
		return
	}
	switch ev.Type {
	case scanstream.TypeProgress:
		if ev.Progress == nil {
			return
		}
		p := ev.Progress
		report(float64(p.Percent), 100,
			fmt.Sprintf("扫描进度 %d%%（%d/%d）", p.Percent, p.Finished, p.Total))
	case scanstream.TypePhase:
		if ev.Phase == nil {
			return
		}
		ph := ev.Phase
		report(float64(ph.Percent), 100,
			fmt.Sprintf("阶段 %s/%s %d%%（%d/%d）", ph.Phase, ph.Status, ph.Percent, ph.Finished, ph.Total))
	}
}

// reportScanLog 把子进程的诊断日志转成一条 MCP 日志通知。
//
// 引擎在扫描过程中会发阶段运维行（[INF]/[WRN] + 阶段名 + 事实），这是「为什么这轮
// 扫描是这个结果」的现场记录；此前它被子进程 stdout 事件流吞掉，长任务出问题时
// 调用方只能靠猜。logf 为 nil（传输不支持中途推送）时直接返回。
func reportScanLog(logf logFunc, ev *scanstream.Event) {
	if logf == nil || ev == nil || ev.Log == nil {
		return
	}
	logf(engineLogLevel(ev.Log.Level), ev.Log.Text)
}

// engineLogLevel 把引擎的缩写级别（INF/WRN/ERR）映射到 MCP 规范的级别名；
// 未识别的级别回落到 info，避免把非规范级别名推给客户端。
func engineLogLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DBG", "DEBUG":
		return "debug"
	case "INF", "INFO":
		return "info"
	case "NOTICE":
		return "notice"
	case "WRN", "WARN", "WARNING":
		return "warning"
	case "ERR", "ERROR":
		return "error"
	case "CRIT", "CRITICAL":
		return "critical"
	default:
		return "info"
	}
}

// resultFromStream 把一条结果事件归一化，字段与旧 verify.* 的 results 保持同构，
// 并顺手把证据里的每次往返写进观测流。
//
// evidence / extractors 只在有值时写入：scan.start 的 outputSchema 把它们声明为
// object，nil 指针或 nil map 会序列化成 null，客户端按 schema 校验时会整批拒绝。
// 指纹/服务识别类结果本来就没有原生证据与提取器，省略这两个键才符合契约。
func resultFromStream(r *scanstream.ResultEvent) map[string]any {
	var native *evidence.Evidence
	if r.Evidence != nil {
		native = r.Evidence.Native
	}
	recordEvidenceObservations(native)

	item := map[string]any{
		"poc_id":   r.PocID,
		"poc_name": r.PocName,
		"severity": r.Severity,
		"target":   r.Target,
	}
	if native != nil {
		item["evidence"] = native
	}
	if r.Evidence != nil {
		if len(r.Evidence.Extractors) > 0 {
			item["extractors"] = r.Evidence.Extractors
		}
		item["exchanges"] = sanitizeStreamExchanges(r.Evidence.Exchanges)
	}
	return item
}

func sanitizeStreamExchanges(in []scanstream.Exchange) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, ex := range in {
		out = append(out, map[string]any{
			"matched":  ex.Matched,
			"request":  clampText(ex.Request, toolBodyLimit),
			"response": clampText(ex.Response, toolBodyLimit),
		})
	}
	return out
}

// recordEvidenceObservations 把原生命中证据里的每次请求/响应写进观测流。
//
// 只记 Agent 主动触发的动作（scan.start / verify.* / act.*）——它们量级可控；
// 全量扫描里每个 PoC 的请求不进流，其价值已由 evidence 覆盖。
func recordEvidenceObservations(ev *evidence.Evidence) {
	if ev == nil {
		return
	}
	for _, st := range ev.Steps {
		req := st.Request
		if strings.TrimSpace(req.URL) == "" {
			continue
		}
		recordHTTPObservation(ev.PocID, req.Method, req.URL, st.Response.Status, st.Matched,
			st.Response.LatencyMs, describeEvidenceRequest(req), st.Response.Body)
	}
}

func describeEvidenceRequest(req evidence.Request) string {
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = "GET"
	}
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(req.URL)
	if h := strings.TrimSpace(req.Headers); h != "" {
		sb.WriteByte('\n')
		sb.WriteString(h)
	}
	return sb.String()
}

// estimateKeywordReserve 估算「按关键词扫一批」需要预留多少请求额度。
//
// 口径：命中关键词的 PoC 数 × 单个 PoC 的保守请求数，落在
// [defaultVerifyReserve, maxVerifyReserve] 内。它只用于预算预留，不影响实际执行；
// 关键词为空时按「全库」估算——空 search 就是一次全量扫描，不能当成一次小检测预留。
func estimateKeywordReserve(search string) int {
	reserve := pocsrepo.CountMatched(search) * defaultVerifyReserve
	if reserve < defaultVerifyReserve {
		reserve = defaultVerifyReserve
	}
	if reserve > maxVerifyReserve {
		reserve = maxVerifyReserve
	}
	return reserve
}
