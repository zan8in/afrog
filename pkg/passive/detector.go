// Package passive 提供内嵌 afrogweb 的被动流量检测框架。
//
// 分层：proxy（抓事务）→ engine（分发调度）→ detector（各类漏洞检测）→ 输出
// （复用 afrogweb 既有的台账 / 报告 / 事件流）。三者严格解耦：新增一类漏洞只需
// 实现 Detector 接口，代理层与调度层零改动。
//
// 两条贯穿全包的设计约束：
//  1. 准确率优先于覆盖率。只有 ConfidenceCertain 的 Finding 才会进入台账，
//     检测器宁可漏报也不得给出无法复现的结论。
//  2. 网络友好。检测器必须通过 Prober 发起重放，无法自建 http.Client，因此也
//     无法绕过调度层统一的并发与限速治理。
package passive

import "context"

// Detector 是每一类漏洞检测器必须实现的契约。
//
// 实现方只需关心「这条事务我能测什么、怎么判定」，不接触抓包与网络治理细节。
// 约定：
//   - Interest 是零流量门控，返回 false 的事务不会产生任何重放请求；
//   - Detect 的判定必须基于可复现的确定性证据，不得依赖单次观察；
//   - 不确定的结论应返回空切片，而不是拔高置信度。
type Detector interface {
	// Name 是检测器标识（如 "sqli" / "xss" / "shiro"），用于配置开关与结果归类。
	Name() string
	// Interest 是快速门控：判断该事务是否值得深测。
	Interest(tx *CapturedTransaction) bool
	// Detect 执行检测。返回空切片表示未发现；error 仅表示内部异常，
	// 不应被上层当作「疑似漏洞」信号。
	Detect(ctx context.Context, tx *CapturedTransaction, probe Prober) ([]Finding, error)
}

// Prober 是调度层注入给检测器的受控重放器。
//
// 检测器不得自行构造 http.Client：所有重放必须经由此接口，才能统一复用既有的
// 并发上限、超时与限速策略。这一约束是「被动扫描不打崩用户网络」的机制保障。
type Prober interface {
	// Replay 原样重放事务，用于建立稳定基线。
	Replay(ctx context.Context, tx *CapturedTransaction) (*CapturedResponse, error)
	// Mutate 在事务基础上替换指定注入点的值并重放。
	Mutate(ctx context.Context, tx *CapturedTransaction, m Mutation) (*CapturedResponse, error)
}

// Finding 是跨检测器同构的统一漏洞发现对象，直接对接 afrogweb 的台账与报告。
type Finding struct {
	// Detector 是产出该发现的检测器名（Detector.Name）。
	Detector string
	// VulnType 是漏洞类型标识（sqli / xss / ...）。
	VulnType string
	// Severity 是严重级别（high / medium / low）。
	Severity string
	// Confidence 只有 Certain 才会被调度层放行。
	Confidence Confidence
	Title      string
	// Target 是去掉参数后的目标地址，用于台账归并与去重。
	Target string
	// Location 精确定位到参数，如 "query:id" / "body:username"。
	Location string
	// Payload 是最终命中的注入值。
	Payload string
	// LatencyMs 是触发命中的那次请求的响应耗时（毫秒）。
	// 时间盲注的判断依据就是耗时，必须留档，否则无法复核。
	LatencyMs int64
	// Evidence 是可读的判定依据，供人工复核。
	Evidence string
	// Request / Response 是触发命中的请求与响应原文，仅在命中时落库。
	Request  []byte
	Response []byte
	// Traces 是支撑该结论的完整请求/响应证据链（基线、各轮对照与复现）。
	//
	// 以 SQL 注入为例，无论布尔差分还是时间盲注，单条请求都无法自证：必须有基线
	// 与反向载荷对照。只留一条「命中请求」等于把结论的推导过程丢掉了，人工复核
	// 时无从下手。因此证据链必须随发现一起留档。
	Traces []Trace
	// Extra 是检测器私有补充字段。
	Extra map[string]any
}

// Trace 是证据链中的一步：一次参与了判定的请求/响应。
type Trace struct {
	// Label 是这一步在证据链中的角色，如「基线 #1」「恒真 #1」「对照组」。
	Label string `json:"label"`
	// Payload 是该步在注入点上实际使用的值（基线即原始值）。
	Payload string `json:"payload"`
	// Status 是响应状态码。
	Status int `json:"status"`
	// LatencyMs 是本次请求的响应耗时（毫秒），时间盲注复核依赖它。
	LatencyMs int64 `json:"latency_ms"`
	// Note 是该步的判定说明，如「与基线相似度 0.993」。
	Note string `json:"note,omitempty"`
	// Request / Response 是 HTTP 原文。
	Request  string `json:"request"`
	Response string `json:"response"`
}
