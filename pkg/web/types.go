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
	TaskName        string   `json:"task_name,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	EnableStream    bool     `json:"enable_stream"`
	Smart           bool     `json:"smart,omitempty"`
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
