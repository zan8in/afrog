package passive

import "time"

// TrafficVerdict 是一条流量最终被如何处理的结论。
//
// 被动扫描最常见的困惑是「捕获在涨、检测不动」——这组枚举就是为了回答
// 「这条请求到底走到哪一步、为什么没进检测器」。
type TrafficVerdict string

const (
	// VerdictPending 已捕获响应，尚未完成检测判定。
	VerdictPending TrafficVerdict = "pending"
	// VerdictSkippedStatic 静态资源，代理层就直接放过了。
	VerdictSkippedStatic TrafficVerdict = "skipped-static"
	// VerdictSkippedMethod 请求方法不在检测范围内。
	VerdictSkippedMethod TrafficVerdict = "skipped-method"
	// VerdictSkippedPath 无法归一化出目标地址。
	VerdictSkippedPath TrafficVerdict = "skipped-path"
	// VerdictDropped 待检队列已满，被主动丢弃（保护用户网络）。
	VerdictDropped TrafficVerdict = "dropped-queue"
	// VerdictNoInterest 所有检测器都判定该请求不具备检测条件。
	VerdictNoInterest TrafficVerdict = "no-interest"
	// VerdictNoFinding 检测已执行，但没有发现确定成立的结论。
	VerdictNoFinding TrafficVerdict = "no-finding"
	// VerdictFinding 检出漏洞。
	VerdictFinding TrafficVerdict = "finding"
	// VerdictError 检测过程异常。
	VerdictError TrafficVerdict = "error"
)

// TrafficEvent 是一条流量的可观测记录。
//
// 只在内存中保留最近若干条，不落库：使用者选择的是「仅存命中」，
// 这里满足的是「看得见过程」，两者不冲突。
type TrafficEvent struct {
	ID       string        `json:"id"`
	Time     time.Time     `json:"time"`
	Method   string        `json:"method"`
	URL      string        `json:"url"`
	Status   int           `json:"status"`
	Duration time.Duration `json:"-"`
	// DurationMs 是毫秒耗时，前端直接可用。
	DurationMs int64 `json:"duration_ms"`
	// Bytes 是响应体大小。
	Bytes int `json:"bytes"`
	// Verdict / Reason 说明这条流量最终怎么处理、为什么。
	Verdict TrafficVerdict `json:"verdict"`
	Reason  string         `json:"reason,omitempty"`
	// Findings 是这条流量检出的命中数。
	Findings int `json:"findings"`
	// Error 是检测异常信息（仅 VerdictError 时有值）。
	Error string `json:"error,omitempty"`
	// Detectors 是本条流量实际执行过检测的检测器名。
	Detectors []string `json:"detectors,omitempty"`
}

// InterestReasoner 是检测器的可选扩展。
//
// 实现了它，调度层就能在「未检测」时给出具体原因，而不是笼统的「不感兴趣」。
// 未实现时调度层退回通用文案，不影响任何已有检测器。
type InterestReasoner interface {
	// InterestReason 返回该事务不满足检测条件的原因（仅在 Interest 为 false 时调用）。
	InterestReason(tx *CapturedTransaction) string
}
