package web

// 登录请求结构
type LoginRequest struct {
	Password string `json:"password"`
}

// 登录响应结构
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// 通用API响应
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 报告列表 - 请求
type ReportListRequest struct {
	Keyword  string   `json:"keyword,omitempty"`
	Severity []string `json:"severity,omitempty"` // 多个值，如 ["high","critical"]
	Page     int      `json:"page"`               // 从1开始
	PageSize int      `json:"page_size"`          // 默认50，最大500
}

// 报告列表 - 单条记录
type ReportItem struct {
	ID         string `json:"id"`
	TaskID     string `json:"taskId"`
	VulID      string `json:"vulId"`
	VulName    string `json:"vulName"`
	Target     string `json:"target"`
	FullTarget string `json:"fullTarget,omitempty"`
	Severity   string `json:"severity"`
	Created    string `json:"created"`
	// Node 是命中产生地：本机扫描为空，远程派发回填的是执行节点展示名。
	Node        string      `json:"node,omitempty"`
	Fingerprint interface{} `json:"fingerprint,omitempty"`
	PocInfo     interface{} `json:"pocInfo,omitempty"`    // 展开后的 POC 信息（与前端展示一致）
	ResultList  interface{} `json:"resultList,omitempty"` // 解析后的请求响应列表
	Extractor   interface{} `json:"extractor,omitempty"`
	// Extractors 是抽取结果的精简形态（仅字符串值），与控制台命中行 [k="v"] 口径一致。
	// 列表接口始终返回它，历史任务的诊断视图才能还原抽取信息。
	Extractors map[string]string `json:"extractors,omitempty"`
	// LedgerStatus/LedgerNote 是台账里该命中的最新人工状态与备注（无记录时省略），
	// 供报告详情「处置」区块回填初值。
	LedgerStatus string `json:"ledger_status,omitempty"`
	LedgerNote   string `json:"ledger_note,omitempty"`
}

// 报告列表 - 响应
type ReportListResponse struct {
	Items      []ReportItem `json:"items"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	Total      int64        `json:"total"`
	TotalPages int          `json:"total_pages"`
	Keyword    string       `json:"keyword,omitempty"`
	Severity   []string     `json:"severity,omitempty"`
	// TaskID 是按任务筛选时回显给前端的过滤条件（计划扫描的「查看上次结果」用它）。
	TaskID string `json:"task_id,omitempty"`
}

// POC 列表 - 单条记录
type PocsListItem struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Author   []string `json:"author,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Source   string   `json:"source"` // builtin/curated/my/local
	Path     string   `json:"path,omitempty"`
	Created  string   `json:"created,omitempty"`

	// 漏洞介绍相关字段：供漏洞库列表与详情页直接渲染，无需再取 YAML。
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Affected    string   `json:"affected,omitempty"`
	Solutions   string   `json:"solutions,omitempty"`
	Verified    bool     `json:"verified,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	CvssMetrics string   `json:"cvss_metrics,omitempty"`
	CvssScore   float64  `json:"cvss_score,omitempty"`
	CveId       string   `json:"cve_id,omitempty"`
	CweId       string   `json:"cwe_id,omitempty"`
}

// POC 列表 - 响应
type PocsListResponse struct {
	Items      []PocsListItem `json:"items"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	Total      int            `json:"total"`
	TotalPages int            `json:"total_pages"`
	Source     string         `json:"source"`
	Severity   []string       `json:"severity,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Author     []string       `json:"author,omitempty"`
	Keyword    string         `json:"keyword,omitempty"`
}

type ScanCreateRequest struct {
	Targets         []string `json:"targets,omitempty"`
	ProjectID       string   `json:"project_id,omitempty"`
	PocFile         string   `json:"poc_file,omitempty"`
	PocSource       string   `json:"poc_source,omitempty"`
	PocIDs          []string `json:"poc_ids,omitempty"`
	Search          string   `json:"search,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Concurrency     int      `json:"concurrency,omitempty"`
	RateLimit       int      `json:"rate_limit,omitempty"`
	Timeout         int      `json:"timeout,omitempty"`
	Retries         int      `json:"retries,omitempty"`
	MaxHostError    int      `json:"max_host_error,omitempty"`
	Proxy           string   `json:"proxy,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	EnableOOB       bool     `json:"enable_oob,omitempty"`
	OOB             string   `json:"oob,omitempty"`
	OOBKey          string   `json:"oob_key,omitempty"`
	OOBDomain       string   `json:"oob_domain,omitempty"`
	OOBApiUrl       string   `json:"oob_api_url,omitempty"`
	OOBHttpUrl      string   `json:"oob_http_url,omitempty"`
	PortScan        bool     `json:"portscan,omitempty"`
	PortScanCompat  bool     `json:"port_scan,omitempty"`
	SkipHostDisc    bool     `json:"skip_host_discovery,omitempty"`
	Ports           string   `json:"ports,omitempty"`
	WebProbe        bool     `json:"webprobe,omitempty"`
	WebFingerprint  bool     `json:"web_fingerprint,omitempty"`
	Headers         []string `json:"headers,omitempty"`
	Sort            string   `json:"sort,omitempty"`
	// 请求节流：-rlt 与 auto/polite/balanced/aggressive 互斥，最多只有一个为真。
	ReqLimitPerTarget int  `json:"req_limit_per_target,omitempty"`
	AutoReqLimit      bool `json:"auto_req_limit,omitempty"`
	Polite            bool `json:"polite,omitempty"`
	Balanced          bool `json:"balanced,omitempty"`
	Aggressive        bool `json:"aggressive,omitempty"`
	// 任务级超时与失败保护
	TaskSmartTimeout bool `json:"task_smart_timeout,omitempty"`
	NoFingerprint    bool `json:"no_fingerprint,omitempty"`
	// BreakpointOnVuln 对应 -vsb：命中首个漏洞后立即停止扫描。
	BreakpointOnVuln bool `json:"breakpoint_on_vuln,omitempty"`
	MonitorTargets   bool `json:"monitor_targets,omitempty"`
	// OOB 调优：轮询/保留/收尾等待（FinalizeTimeout 允许 0 与 -1，故用指针区分未设置）
	OobRateLimit       int  `json:"oob_rate_limit,omitempty"`
	OobConcurrency     int  `json:"oob_concurrency,omitempty"`
	OobPollInterval    int  `json:"oob_poll_interval,omitempty"`
	OobHitRetention    int  `json:"oob_hit_retention,omitempty"`
	OobFinalizeTimeout *int `json:"oob_finalize_timeout,omitempty"`
	// 进阶：爆破上限与响应体上限（MB）
	BruteMaxRequests int `json:"brute_max_requests,omitempty"`
	MaxRespBodySize  int `json:"max_resp_body_size,omitempty"`

	TaskName     string   `json:"task_name,omitempty"`
	Labels       []string `json:"labels,omitempty"`
	EnableStream bool     `json:"enable_stream"`
	Smart        bool     `json:"smart,omitempty"`
}

type ScanProgressData struct {
	Percent   int   `json:"percent"`
	Finished  int   `json:"finished"`
	Total     int   `json:"total"`
	Rate      int   `json:"rate"`
	ElapsedMs int64 `json:"elapsedMs"`
}

type ScanStatusData struct {
	Status   string           `json:"status"`
	Progress ScanProgressData `json:"progress"`
	Stats    struct {
		CompletedScans int `json:"completedScans"`
		TotalScans     int `json:"totalScans"`
		FoundVulns     int `json:"foundVulns"`
	} `json:"stats"`
	// Error 是任务失败原因（如子进程拉不起来），正常任务为空。
	Error      string `json:"error,omitempty"`
	TaskID     string `json:"taskId,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
}

type ScanInitInfo struct {
	TotalTargets int      `json:"total_targets"`
	TotalPocs    int      `json:"total_pocs"`
	TotalScans   int      `json:"total_scans"`
	Targets      []string `json:"targets"`
	OOBEnabled   bool     `json:"oob_enabled"`
	OOBStatus    string   `json:"oob_status"`
}
