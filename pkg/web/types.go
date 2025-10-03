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
	ID         string      `json:"id"`
	TaskID     string      `json:"taskId"`
	VulID      string      `json:"vulId"`
	VulName    string      `json:"vulName"`
	Target     string      `json:"target"`
	FullTarget string      `json:"fullTarget,omitempty"`
	Severity   string      `json:"severity"`
	Created    string      `json:"created"`
	PocInfo    interface{} `json:"pocInfo,omitempty"`    // 展开后的 POC 信息（与前端展示一致）
	ResultList interface{} `json:"resultList,omitempty"` // 解析后的请求响应列表
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
