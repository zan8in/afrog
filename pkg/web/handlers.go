package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"os"
	"sort"
	"time"

	"github.com/zan8in/gologger"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// 所有API返回JSON
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	// 限制请求体大小，防止大包体DoS
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB 上限

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

	// 常量时间比较，避免侧信道
	if subtle.ConstantTimeCompare([]byte(loginReq.Password), []byte(generatedPassword)) != 1 {
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
	userID := GetUserIDFromContext(r)
	if userID != "" {
		gologger.Info().Str("user_id", userID).Str("ip", getClientIP(r)).Msg("用户退出")
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "退出成功"})
}

func vulnsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID := GetUserIDFromContext(r)
	gologger.Info().Str("user_id", userID).Msg("访问漏洞列表")

	vulnData := map[string]interface{}{
		"total": 0,
		"vulns": []interface{}{},
		"page":  1,
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "获取成功", Data: vulnData})
}

type pocRecentItem struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Severity  string   `json:"severity"`
	UpdatedAt string   `json:"updated_at"`
	Tags      []string `json:"tags"`
}

func pocsStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 统计计数
	countBySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"other":    0,
	}

	type holder struct {
		id       string
		name     string
		path     string
		severity string
		created  time.Time
		tags     []string
	}

	var items []holder

	// 遍历内置（embed）PoC
	for _, ep := range pocs.EmbedFileList {
		pp, err := pocs.EmbedReadPocByPath(ep)
		if err != nil {
			continue
		}
		sv := normalizeSeverity(pp.Info.Severity)
		incrSeverity(countBySeverity, sv)
		cr := parseCreated(pp.Info.Created)
		tags := splitTags(pp.Info.Tags)
		items = append(items, holder{
			id:       pp.Id,
			name:     pp.Info.Name,
			path:     "embedded:" + ep,
			severity: sv,
			created:  cr,
			tags:     tags,
		})
	}

	// 遍历本地 ~/afrog-pocs
	localFiles, _ := poc.LocalWalkFiles(poc.LocalPocDirectory)
	homeDir, _ := os.UserHomeDir()
	for _, lp := range localFiles {
		pp, err := poc.LocalReadPocByPath(lp)
		if err != nil {
			continue
		}
		sv := normalizeSeverity(pp.Info.Severity)
		incrSeverity(countBySeverity, sv)
		cr := parseCreated(pp.Info.Created)
		tags := splitTags(pp.Info.Tags)
		items = append(items, holder{
			id:       pp.Id,
			name:     pp.Info.Name,
			path:     strings.Replace(lp, homeDir, "~", 1),
			severity: sv,
			created:  cr,
			tags:     tags,
		})
	}

	total := 0
	for _, v := range countBySeverity {
		total += v
	}

	// 最近更新 Top 5（按 created 降序）
	sort.Slice(items, func(i, j int) bool {
		return items[i].created.After(items[j].created)
	})

	top := 5
	if len(items) < top {
		top = len(items)
	}
	recent := make([]pocRecentItem, 0, top)
	for i := 0; i < top; i++ {
		it := items[i]
		recent = append(recent, pocRecentItem{
			ID:        it.id,
			Name:      it.name,
			Path:      it.path,
			Severity:  it.severity,
			UpdatedAt: it.created.UTC().Format(time.RFC3339),
			Tags:      it.tags,
		})
	}

	data := map[string]interface{}{
		"total": total,
		"by_severity": map[string]int{
			"critical": countBySeverity["critical"],
			"high":     countBySeverity["high"],
			"medium":   countBySeverity["medium"],
			"low":      countBySeverity["low"],
			"info":     countBySeverity["info"],
			"other":    countBySeverity["other"],
		},
		"updated_at":     time.Now().UTC().Format(time.RFC3339),
		"recent_updates": recent,
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    data,
	})
}

func normalizeSeverity(s string) string {
	sl := strings.ToLower(strings.TrimSpace(s))
	switch sl {
	case "critical", "high", "medium", "low", "info":
		return sl
	default:
		return "other"
	}
}

func incrSeverity(m map[string]int, sev string) {
	if _, ok := m[sev]; ok {
		m[sev]++
	} else {
		 // 兜底
		m["other"]++
	}
}

func splitTags(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseCreated(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	// 兼容多种常见时间格式
	layouts := []string{
		time.RFC3339,                // 2006-01-02T15:04:05Z07:00
		"2006-01-02 15:04:05",       // 2006-01-02 15:04:05
		"2006-01-02",                // 2006-01-02
		"2006/01/02 15:04:05",       // 2006/01/02 15:04:05
		"2006/01/02",                // 2006/01/02
		"2006-1-2",                  // 2006-1-2
		"2006/1/2",                  // 2006/1/2
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}