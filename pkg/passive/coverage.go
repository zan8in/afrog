package passive

import (
	"strings"
	"time"
)

// CoverageState 是「某个资产上某个检测器」的覆盖状态。
//
// 它回答的不是「有没有漏洞」，而是「这一块到底测没测、没测是为什么」。
// 与 TrafficEvent 的差别：TrafficEvent 描述一次请求的命运，覆盖度描述
// 一个资产在整段时间里的累计结论——前者用于排查单条流量，后者用于查漏。
type CoverageState string

const (
	// CoverageTested 表示检测器真的执行过，且没有确认命中。
	CoverageTested CoverageState = "tested"
	// CoverageHit 表示检测器执行过并确认命中（含被去重拦下的重复命中）。
	CoverageHit CoverageState = "hit"
	// CoverageSkipped 表示检测器没有执行，原因见 Reason。
	CoverageSkipped CoverageState = "skipped"
	// CoverageError 表示检测器执行时异常，结论未定。
	CoverageError CoverageState = "error"
)

// CoverageSignal 是一次覆盖度上报。
//
// Target 只取 authority（host[:port]），不区分 http/https：
// 覆盖度关心的是「这台资产测过没有」，把协议拆开只会让同一台机器出现两行。
type CoverageSignal struct {
	Target   string
	Detector string
	State    CoverageState
	// Reason 是跳过或异常的说明；命中/干净结论也可以带一句判据摘要。
	Reason string
	// Verdict 是产生该信号的那条流量的最终结论。
	Verdict TrafficVerdict
	At      time.Time
}

// emitCoverage 上报一次覆盖度信号。未配置回调时零开销。
func (e *Engine) emitCoverage(tx *CapturedTransaction, detector string, state CoverageState, reason string, verdict TrafficVerdict) {
	if e.opts.OnCoverage == nil || detector == "" {
		return
	}
	target := coverageTarget(tx)
	if target == "" {
		return
	}
	e.opts.OnCoverage(CoverageSignal{
		Target:   target,
		Detector: detector,
		State:    state,
		Reason:   reason,
		Verdict:  verdict,
		At:       time.Now(),
	})
}

// emitAllSkipped 把一个事务标记为「所有检测器都没跑」，用于入口队列满这类
// 连门控都没走到的情形。它只做事实陈述，不猜测哪些检测器本来会感兴趣。
func (e *Engine) emitAllSkipped(tx *CapturedTransaction, reason string, verdict TrafficVerdict) {
	if e.opts.OnCoverage == nil {
		return
	}
	for _, d := range e.networkDetectors {
		if d != nil {
			e.emitCoverage(tx, d.Name(), CoverageSkipped, reason, verdict)
		}
	}
	for _, d := range e.localDetectors {
		if d != nil {
			e.emitCoverage(tx, d.Name(), CoverageSkipped, reason, verdict)
		}
	}
	for _, x := range e.extractors {
		if x != nil {
			e.emitCoverage(tx, x.Name(), CoverageSkipped, reason, verdict)
		}
	}
}

// emitNetworkSkipped 把网络类检测器整体记成跳过。
//
// 用于「短路发生在检测之前」的分支（静态资源、注入点记忆、在途去重、队列满）：
// 这些情形下没有任何网络类检测器跑过，逐条上报比让台账缺行更诚实。
func (e *Engine) emitNetworkSkipped(tx *CapturedTransaction, reason string, verdict TrafficVerdict) {
	if e.opts.OnCoverage == nil {
		return
	}
	for _, d := range e.networkDetectors {
		if d != nil {
			e.emitCoverage(tx, d.Name(), CoverageSkipped, reason, verdict)
		}
	}
}

// coverageTarget 取事务的 authority 作为覆盖度聚合口径。
//
// MITM 隧道下 URL.Host 可能为空，必须回退读 Host 头——这与代理层判断扫描范围
// 用的是同一套回退逻辑，否则覆盖度会出现「有流量但没有资产」的空洞。
func coverageTarget(tx *CapturedTransaction) string {
	if tx == nil || tx.Request == nil {
		return ""
	}
	host := ""
	if tx.Request.URL != nil {
		host = tx.Request.URL.Host
	}
	if host == "" && tx.Request.Headers != nil {
		host = tx.Request.Headers.Get("Host")
	}
	return strings.ToLower(strings.TrimSpace(host))
}
