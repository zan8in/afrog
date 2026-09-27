// Package scanstream 定义 afrog 的 NDJSON 事件流格式。
//
// 该格式与 docs/plan/afrog-grpc-protocol.md 里的 ScanEvent 同构：
// 信封字段（v/node/task/seq/ts_ms/type）负责路由与可靠性，载荷放在与 type
// 同名的键下。字段名必须与协议文档及 proto 草案逐字对应，两者不得私自加字段。
package scanstream

// Version 是协议版本，节点与协议版本不匹配时应拒绝并提示升级。
const Version = "1"

// 事件类型判别符，同时作为载荷所在的 JSON 键名。
const (
	TypeStatus   = "status"
	TypeScanInfo = "scan_info"
	TypeProgress = "progress"
	TypePhase    = "phase"
	TypeResult   = "result"
	TypePort     = "port"
	TypeWebProbe = "webprobe"
	TypeHost     = "host"
	TypeLog      = "log"
	TypeDone     = "done"
	TypeError    = "error"
)

// Event 是一条事件：信封 + 各载荷指针字段。
// 未设置的载荷为 nil，借助 omitempty 从 JSON 中省略。
type Event struct {
	V    string `json:"v"`
	Node string `json:"node"`
	Task string `json:"task"`
	Seq  uint64 `json:"seq"`
	TsMs int64  `json:"ts_ms"`
	// Type 是载荷类型判别符，取值见 Type* 常量。
	Type string `json:"type"`

	Status   *StatusEvent   `json:"status,omitempty"`
	ScanInfo *ScanInfoEvent `json:"scan_info,omitempty"`
	Progress *ProgressEvent `json:"progress,omitempty"`
	Phase    *PhaseEvent    `json:"phase,omitempty"`
	Result   *ResultEvent   `json:"result,omitempty"`
	Port     *PortEvent     `json:"port,omitempty"`
	WebProbe *WebProbeEvent `json:"webprobe,omitempty"`
	Host     *HostEvent     `json:"host,omitempty"`
	Log      *LogEvent      `json:"log,omitempty"`
	Done     *DoneEvent     `json:"done,omitempty"`
	Error    *ErrorEvent    `json:"error,omitempty"`
}

// StatusEvent 描述任务状态变化。
// status 取值：queued/starting/running/paused/completed/failed/cancelled。
type StatusEvent struct {
	Status string `json:"status"`
}

// ScanInfoEvent 是任务的前置汇总，由引擎在真正开始执行前上报一次。
// total_scans 与命令行输出的 tasks= 同源（options.Count），total_pocs 为实际加载的
// PoC 数（含指纹 PoC），oob_status 为 OOB 可用性描述。
type ScanInfoEvent struct {
	TotalTargets int    `json:"total_targets"`
	TotalPocs    int    `json:"total_pocs"`
	TotalScans   int    `json:"total_scans"`
	OOBEnabled   bool   `json:"oob_enabled"`
	OOBStatus    string `json:"oob_status,omitempty"`
}

// ProgressEvent 是扫描级进度（约 1s 一次）。
// total 为引擎下发的任务数（与命令行 tasks= 同源），finished 为已完成数。
type ProgressEvent struct {
	Percent   int   `json:"percent"`
	Finished  int64 `json:"finished"`
	Total     int64 `json:"total"`
	Rate      int   `json:"rate"`
	ElapsedMs int64 `json:"elapsed_ms"`
}

// PhaseEvent 是阶段进度。phase 取值：host_discovery/portscan/webprobe/vuln。
type PhaseEvent struct {
	Phase    string `json:"phase"`
	Status   string `json:"status"`
	Finished int64  `json:"finished"`
	Total    int64  `json:"total"`
	Percent  int    `json:"percent"`
}

// ResultEvent 描述一次漏洞命中。evidence 供控制面落库。
type ResultEvent struct {
	Severity string    `json:"severity"`
	PocID    string    `json:"poc_id"`
	PocName  string    `json:"poc_name"`
	Target   string    `json:"target"`
	Evidence *Evidence `json:"evidence,omitempty"`
}

// PortEvent 描述一个开放端口。
type PortEvent struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// WebProbeEvent 描述一次 Web 探测。
type WebProbeEvent struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Title       string `json:"title"`
	Fingerprint string `json:"fingerprint"`
}

// HostEvent 描述资产发现阶段发现的一个存活主机。
// 协议文档第 5 节原表未列出该载荷，为与 Web 前端「资产发现」对齐而补充。
type HostEvent struct {
	Host string `json:"host"`
}

// LogEvent 是诊断日志。
type LogEvent struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// DoneEvent 表示任务结束，携带汇总。
type DoneEvent struct {
	Status  string   `json:"status"`
	Summary *Summary `json:"summary,omitempty"`
}

// ErrorEvent 是任务级错误。
type ErrorEvent struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Evidence 保存命中时的请求/响应交互与提取器结果。
type Evidence struct {
	Exchanges  []Exchange        `json:"exchanges,omitempty"`
	Extractors map[string]string `json:"extractors,omitempty"`
}

// Exchange 是一次请求/响应往返。
type Exchange struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Matched  bool   `json:"matched"`
}

// Summary 是任务汇总：executed 为实际执行数，found 为命中数，
// by_severity 为按严重级别的命中分布。
type Summary struct {
	Executed   int64            `json:"executed"`
	Found      int64            `json:"found"`
	BySeverity map[string]int64 `json:"by_severity,omitempty"`
	ElapsedMs  int64            `json:"elapsed_ms"`
}
