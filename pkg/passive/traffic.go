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
	// VerdictSkippedScope 落在使用者设定的扫描范围之外。
	//
	// 与静态资源跳过不同：这些请求本身是可注入的，只是被范围规则（域名白名单 /
	// 路径排除）挡在了外面。单独成一类，使用者才能确认「是我不让它扫的」，
	// 而不是误以为工具漏扫了。
	VerdictSkippedScope TrafficVerdict = "skipped-scope"
	// VerdictDropped 待检队列已满，被主动丢弃（保护用户网络）。
	// 它发生在**门控入口**：这些请求连「要不要检测」都还没判断过。
	VerdictDropped TrafficVerdict = "dropped-queue"
	// VerdictDroppedDetect 检测队列已满，未能进入检测。
	//
	// 与 VerdictDropped 必须分开：前者是「入口就丢了，还没筛过」，这里是
	// 「已经确认需要检测，却因检测能力饱和而丢了」——后者是实打实的漏报风险，
	// 混在一起会让使用者低估损失。
	VerdictDroppedDetect TrafficVerdict = "dropped-detect"
	// VerdictNoInterest 所有检测器都判定该请求不具备检测条件。
	VerdictNoInterest TrafficVerdict = "no-interest"
	// VerdictInFlightDup 该请求的注入点已有事务正在检测队列中或检测中，本轮跳过并发重复投递。
	//
	// 与 VerdictKnownClean 必须分开：后者是「结论已落定（命中或短期判定无注入）」，
	// 这里结论尚未产生，只是同一注入点已被另一次检测覆盖。事后短路只有在检测跑完
	// （数十秒）后才生效，这个窗口内的并发重复请求正是靠它拦下，避免同一 URL 被
	// 多路并行全量重放。
	VerdictInFlightDup TrafficVerdict = "in-flight-dup"
	// VerdictKnownClean 该请求的注入点在短期内已被判定「无注入」，本轮跳过复测。
	//
	// 与 VerdictDuplicate 分开：后者是「已确认命中，不必重测」，这里是「已判定干净，
	// 不必重测」。两者都会省下昂贵的重放，但结论完全相反，混在一起会让使用者
	// 误以为某处被检出过。它也不是 VerdictNoInterest——那条请求确实具备检测条件，
	// 只是结论已被缓存。
	VerdictKnownClean TrafficVerdict = "known-clean"
	// VerdictNoFinding 检测已执行，但没有发现确定成立的结论。
	VerdictNoFinding TrafficVerdict = "no-finding"
	// VerdictFinding 检出漏洞。
	VerdictFinding TrafficVerdict = "finding"
	// VerdictDuplicate 检出了漏洞，但与已上报的命中重复，被去重拦下。
	//
	// 必须与 VerdictNoFinding 区分开：前者是「确实检出了」，后者是「没检出」。
	// 把去重混进 no-finding 会让界面显示「检测无结论」，抹掉真实结论。
	VerdictDuplicate TrafficVerdict = "dup-finding"
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
	// Duplicated 是这条流量检出但被判为重复（已在别处上报过）的命中数。
	Duplicated int `json:"duplicated,omitempty"`
	// Extractions 是这条流量中提取到的敏感信息条数（本地提取器产出，已过运行内去重）。
	// 与 Findings 不同：提取物不是漏洞，不进台账，但同样需要让使用者看得见。
	Extractions int `json:"extractions,omitempty"`
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
