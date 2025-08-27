package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/gologger"
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
		time.RFC3339,          // 2006-01-02T15:04:05Z07:00
		"2006-01-02 15:04:05", // 2006-01-02 15:04:05
		"2006-01-02",          // 2006-01-02
		"2006/01/02 15:04:05", // 2006/01/02 15:04:05
		"2006/01/02",          // 2006/01/02
		"2006-1-2",            // 2006-1-2
		"2006/1/2",            // 2006/1/2
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func reportsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 支持 GET
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	q := r.URL.Query()
	keyword := strings.TrimSpace(q.Get("keyword"))
	severityRaw := strings.TrimSpace(q.Get("severity"))
	pageStr := strings.TrimSpace(q.Get("page"))
	pageSizeStr := strings.TrimSpace(q.Get("page_size"))
	expandRaw := strings.TrimSpace(q.Get("expand")) // 可选：pocInfo,resultList,all

	// 解析分页参数
	page := 1
	if pageStr != "" {
		if v, err := strconv.Atoi(pageStr); err == nil && v > 0 {
			page = v
		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "参数错误: page"})
			return
		}
	}
	pageSize := 50
	if pageSizeStr != "" {
		if v, err := strconv.Atoi(pageSizeStr); err == nil && v > 0 && v <= 500 {
			pageSize = v
		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "参数错误: page_size(1-500)"})
			return
		}
	}

	// severity 多值拆分并标准化为小写
	var severityList []string
	if severityRaw != "" {
		for _, s := range strings.Split(severityRaw, ",") {
			t := strings.ToLower(strings.TrimSpace(s))
			if t != "" {
				severityList = append(severityList, t)
			}
		}
	}
	severityParam := strings.Join(severityList, ",")

	// expand 解析（默认不展开任何大字段）
	var expandPoc, expandResult bool
	if expandRaw != "" {
		for _, e := range strings.Split(expandRaw, ",") {
			switch strings.ToLower(strings.TrimSpace(e)) {
			case "pocinfo":
				expandPoc = true
			case "resultlist":
				expandResult = true
			case "all":
				expandPoc = true
				expandResult = true
			}
		}
	}

	// 查询数据（分页），按需展开
	itemsRaw, err := sqlite.SelectPage(severityParam, keyword, page, pageSize, expandPoc, expandResult)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "查询失败: " + err.Error()})
		return
	}

	// 统计筛选后的总数
	total, err := sqlite.CountFiltered(severityParam, keyword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "统计失败: " + err.Error()})
		return
	}

	// 组装响应 items
	respItems := make([]ReportItem, 0, len(itemsRaw))
	for _, it := range itemsRaw {
		item := ReportItem{
			ID:         strconv.FormatInt(it.ID, 10),
			TaskID:     it.TaskID,
			VulID:      it.VulID,
			VulName:    it.VulName,
			Target:     it.Target,
			FullTarget: it.FullTarget,
			Severity:   it.Severity, // 已在底层转大写
			Created:    it.Created,
		}
		if expandPoc {
			item.PocInfo = it.PocInfo
		}
		if expandResult {
			item.ResultList = it.ResultList
		}
		respItems = append(respItems, item)
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	data := ReportListResponse{
		Items:      respItems,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Keyword:    keyword,
		Severity:   severityList,
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    data,
	})
}

// 新增：报告详情接口 GET /api/reports/{id}?expand=all|pocInfo|resultList
func reportsDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	// 从路径中提取 id
	path := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	if path == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少报告ID"})
		return
	}
	// id, err := strconv.ParseInt(path, 10, 64)
	id := path
	if len(id) <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的报告ID"})
		return
	}

	// expand 解析（详情默认全展开）
	expandRaw := strings.TrimSpace(r.URL.Query().Get("expand"))
	expandPoc, expandResult := true, true
	if expandRaw != "" {
		expandPoc, expandResult = false, false
		for _, e := range strings.Split(expandRaw, ",") {
			switch strings.ToLower(strings.TrimSpace(e)) {
			case "pocinfo":
				expandPoc = true
			case "resultlist":
				expandResult = true
			case "all":
				expandPoc = true
				expandResult = true
			}
		}
	}

	row, err := sqlite.GetByID(id, expandPoc, expandResult)
	if err != nil {
		// 未找到或数据库错误
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "未找到报告"})
		return
	}

	item := ReportItem{
		ID:         strconv.FormatInt(row.ID, 10),
		TaskID:     row.TaskID,
		VulID:      row.VulID,
		VulName:    row.VulName,
		Target:     row.Target,
		FullTarget: row.FullTarget,
		Severity:   row.Severity,
		Created:    row.Created,
	}
	if expandPoc {
		item.PocInfo = row.PocInfo
	}
	if expandResult {
		item.ResultList = row.ResultList
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    item,
	})
}
