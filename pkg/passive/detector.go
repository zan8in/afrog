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

// CostClass 是检测器的**代价类别**，决定它在调度层的执行位置与短路策略。
//
// 这是调度层最重要的一个分区维度：网络类与本地类的需求方向完全相反，
// 混在一处会让本地类（零流量）被网络类的注入点短路吞掉、被网络类的慢检测排队拖慢。
type CostClass int

const (
	// CostNetwork 是「会发起重放请求」的检测器（如 sqli）。
	//
	// 它走检测池，受注入点短路（命中/短期内已判定干净/在途重复）约束，
	// 静态资源对它无意义，理应跳过。这类检测昂贵且不可控，允许在队列饱和时被丢弃。
	CostNetwork CostClass = iota
	// CostLocal 是「零流量」检测器（如 misconfig、extract）。
	//
	// 它内联在门控池同步执行：不重放、不进检测池、不受任何注入点短路影响，
	// 也永远不因队列饱和而被丢弃。产物要么进漏洞台账，要么进提取面板。
	CostLocal
)

// Classified 是检测器的可选扩展：声明自己的代价类别。
//
// 未实现者一律按 CostNetwork 处理——这是偏保守的默认值：网络类会走既有的
// 短路与队列治理，不会因为一个「不知深浅」的新检测器而破坏现有行为。
type Classified interface {
	// CostClass 返回检测器的代价类别。
	CostClass() CostClass
}

// CostClassOf 读取检测器的代价类别；未声明时退回 CostNetwork。
func CostClassOf(d Detector) CostClass {
	if c, ok := d.(Classified); ok {
		return c.CostClass()
	}
	return CostNetwork
}

// Extractor 是「零流量敏感信息提取器」必须实现的契约。
//
// 它与 Detector 刻意分成两个接口，而不是给 Finding 加一个 kind 字段：
//   - 供给不同：提取器只读已捕获的事务，永远不重放，因此签名里没有 ctx 与 prober；
//   - 产物不同：提取物是「客观存在的字符串」（密钥、身份证号…），不是「漏洞判定」，
//     两者的落库表、去重口径、前端面板都完全独立；
//   - 归属不同：提取物永远不进漏洞台账，从类型上就杜绝了误入。
//
// 提取器天然是 CostLocal：它在门控池内联执行，不受注入点短路，也不进检测池。
type Extractor interface {
	// Name 是提取器标识，用于配置开关与结果归类。
	Name() string
	// Interest 是快速门控：判断该事务是否值得扫描。
	// 典型实现会对非文本响应、超大响应直接返回 false。
	Interest(tx *CapturedTransaction) bool
	// Extract 在事务上执行提取。返回空切片表示未提取到任何信息。
	Extract(tx *CapturedTransaction) []Extraction
}

// Extraction 是一条从流量中提取到的敏感信息，直接对接提取面板。
//
// 与 Finding 的关键差异：它不是「某处存在漏洞」，而是「某处存在某个字符串」。
// 因此字段以「值 + 出处 + 规则」为主，没有 Payload / Traces 这类漏洞证据链概念。
type Extraction struct {
	// Detector 是产出该提取物的提取器名（Extractor.Name）。
	Detector string `json:"detector"`
	// Rule 是命中的规则标识（如 "private-key" / "id-card-cn"）。
	Rule string `json:"rule"`
	// Category 是规则分类（credential / cloud-key / pii / network …），面板据此分组。
	Category string `json:"category"`
	// Title 是规则的人类可读名（如「RSA 私钥」）。
	Title string `json:"title"`
	// Severity 是该类信息泄露后的潜在影响等级（high / medium / low）。
	Severity string `json:"severity"`
	// Confidence 是命中的可信度。提取面板与漏洞台账不同：这里**不做** Certain 门控，
	// 但仍如实标注，让使用者据此决定要不要采信。
	Confidence Confidence `json:"confidence"`
	// Value 是提取到的原始值。
	Value string `json:"value"`
	// Target 是聚合口径（origin 或精确 URL），含义由规则决定。
	Target string `json:"target"`
	// Location 标明该值出现的具体位置，如 "response-body" / "response-header:Set-Cookie" / "url-query"。
	Location string `json:"location"`
	// LatencyMs 是来源响应的耗时（毫秒），供面板展示。
	LatencyMs int64 `json:"latency_ms"`
	// Evidence 是值周边的上下文片段，供人工复核（值是在什么语境下出现的）。
	Evidence string `json:"evidence"`
	// Request / Response 是来源的 HTTP 原文，面板可跳回查看。
	Request  []byte `json:"-"`
	Response []byte `json:"-"`
	// Extra 是提取器私有补充字段。
	Extra map[string]any `json:"extra,omitempty"`
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
