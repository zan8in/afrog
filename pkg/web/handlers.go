package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zan8in/gologger"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// 所有API返回JSON
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	// 验证Content-Type
	if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Content-Type必须为application/json"})
		return
	}

	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	if loginReq.Password != generatedPassword {
		gologger.Warning().Str("ip", getClientIP(r)).Msg("登录失败尝试")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "密码错误"})
		return
	}

	token, expires, err := generateJWTToken("admin")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "生成token失败"})
		return
	}

	gologger.Info().Str("ip", getClientIP(r)).Msg("用户登录成功")
	json.NewEncoder(w).Encode(LoginResponse{Success: true, Message: "登录成功", Token: token, Expires: expires})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	// JWT无状态，客户端删除即可，这里仅做审计
	userID := r.Header.Get("X-User-ID")
	if userID != "" {
		gologger.Info().Str("user_id", userID).Str("ip", getClientIP(r)).Msg("用户退出")
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "退出成功"})
}

func vulnsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID := r.Header.Get("X-User-ID")
	gologger.Info().Str("user_id", userID).Msg("访问漏洞列表")

	vulnData := map[string]interface{}{
		"total": 0,
		"vulns": []interface{}{},
		"page":  1,
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "获取成功", Data: vulnData})
}