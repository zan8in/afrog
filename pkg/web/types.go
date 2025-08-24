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