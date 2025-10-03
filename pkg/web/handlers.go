package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
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

	// 统一使用仓库层，整合所有来源并按 ID 去重
	items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "统计数据加载失败"})
		return
	}

	// 总数
	total := len(items)

	// 按来源统计（仅输出 builtin/curated/my）
	bySource := map[string]int{
		"builtin": 0,
		"curated": 0,
		"my":      0,
	}
	for _, it := range items {
		switch it.Source {
		case pocsrepo.SourceBuiltin:
			bySource["builtin"]++
		case pocsrepo.SourceCurated:
			bySource["curated"]++
		case pocsrepo.SourceMy:
			bySource["my"]++
		}
	}

	// 按严重等级统计
	bySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, it := range items {
		s := strings.ToLower(strings.TrimSpace(it.Severity))
		if _, ok := bySeverity[s]; ok {
			bySeverity[s]++
		} else {
			// 未知等级不计（仓库层已标准化为上述五类之一）
		}
	}

	// 标签与作者计数
	tagCount := make(map[string]int, 1024)
	authorCount := make(map[string]int, 1024)
	for _, it := range items {
		for _, t := range it.Tags {
			tt := strings.TrimSpace(t)
			if tt != "" {
				tagCount[tt]++
			}
		}
		for _, a := range it.Author {
			aa := strings.TrimSpace(a)
			if aa != "" {
				authorCount[aa]++
			}
		}
	}

	// 替换原来的泛型闭包：topN := func[K comparable](...) { ... }
	type tagItem struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	}
	type authorItem struct {
		Author string `json:"author"`
		Count  int    `json:"count"`
	}

	buildTopTags := func(m map[string]int, limit int) []tagItem {
		out := make([]tagItem, 0, len(m))
		for k, v := range m {
			out = append(out, tagItem{Tag: k, Count: v})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return strings.ToLower(out[i].Tag) < strings.ToLower(out[j].Tag)
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return out
	}

	buildTopAuthors := func(m map[string]int, limit int) []authorItem {
		out := make([]authorItem, 0, len(m))
		for k, v := range m {
			out = append(out, authorItem{Author: k, Count: v})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return strings.ToLower(out[i].Author) < strings.ToLower(out[j].Author)
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return out
	}

	topTags := buildTopTags(tagCount, 20)
	topAuthors := buildTopAuthors(authorCount, 20)

	data := map[string]interface{}{
		"total":       total,
		"by_source":   bySource,
		"by_severity": bySeverity,
		"top_tags":    topTags,
		"top_authors": topAuthors,
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "success",
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

// 顶层函数：统一委托到仓库层，避免重复实现
func splitTags(tags string) []string {
	return pocsrepo.SplitTags(tags)
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

func reportsDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	// 从路径变量中获取 id（路由：/api/reports/detail/{id}）
	vars := mux.Vars(r)
	id := strings.TrimSpace(vars["id"])
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少报告ID"})
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

func pocDetailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从URL路径中提取report ID - 适配新的路由 /reports/poc/{id}
	// path := strings.TrimPrefix(r.URL.Path, "/reports/poc/")
	// if path == "" || path == r.URL.Path {
	// 	http.Error(w, "Invalid report ID", http.StatusBadRequest)
	// 	return
	// }

	// 清理路径，获取 report ID
	// reportId := strings.TrimSpace(strings.Split(path, "?")[0])
	// reportId = strings.Trim(reportId, "/")

	// 从路由变量中提取 report ID（路由：/api/reports/poc/{id}）
	vars := mux.Vars(r)
	reportId := strings.TrimSpace(vars["id"])
	if reportId == "" {
		http.Error(w, "Invalid report ID", http.StatusBadRequest)
		return
	}
	// 从数据库查询report记录，获取pocInfo.Id
	report, err := sqlite.GetByID(reportId, true, false)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	pocId := report.PocInfo.Id
	if pocId == "" {
		http.Error(w, "POC ID not found in report", http.StatusNotFound)
		return
	}

	// 通过POC ID查找原始YAML内容
	yamlContent, err := poc.FindPocYamlById(pocId)
	if err != nil {
		http.Error(w, fmt.Sprintf("POC YAML not found: %v", err), http.StatusNotFound)
		return
	}

	// 返回YAML内容
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s.yaml\"", pocId))
	w.WriteHeader(http.StatusOK)
	w.Write(yamlContent)
}

func pocsListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	q := r.URL.Query()
	source := strings.ToLower(strings.TrimSpace(q.Get("source")))
	if source == "" {
		source = "all"
	}
	switch source {
	case "builtin", "curated", "my", "all":
	default:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "参数错误: source（允许 builtin|curated|my|all）"})
		return
	}

	sevRaw := strings.TrimSpace(q.Get("severity"))
	tagRaw := strings.TrimSpace(q.Get("tags"))
	authRaw := strings.TrimSpace(q.Get("author"))
	keyword := strings.TrimSpace(q.Get("q"))
	pageStr := strings.TrimSpace(q.Get("page"))
	pageSizeStr := strings.TrimSpace(q.Get("page_size"))

	// 解析分页参数
	page := 1
	if pageStr != "" {
		if v, err := strconv.Atoi(pageStr); err == nil && v > 0 {
			page = v
		} else {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "参数错误: page"})
			return
		}
	}
	pageSize := 50
	if pageSizeStr != "" {
		if v, err := strconv.Atoi(pageSizeStr); err == nil && v > 0 && v <= 500 {
			pageSize = v
		} else {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "参数错误: page_size(1-500)"})
			return
		}
	}

	// 解析多值筛选
	parseCSV := func(s string, toLower bool) []string {
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if toLower {
				t = strings.ToLower(t)
			}
			if t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	severityList := parseCSV(sevRaw, true)
	tagsList := parseCSV(tagRaw, false)
	authorList := parseCSV(authRaw, false)

	// 使用统一仓库层
	opts := pocsrepo.ListOptions{
		Source:   source,
		Severity: severityList,
		Tags:     tagsList,
		Authors:  authorList,
		Q:        keyword,
	}
	items, err := pocsrepo.ListMeta(opts)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "POC 列表加载失败"})
		return
	}

	// 新增：按 created 从新到旧排序；没有 created 的排后面（稳定排序）
	sort.SliceStable(items, func(i, j int) bool {
		ti := parseCreated(items[i].Created)
		tj := parseCreated(items[j].Created)
		iz := ti.IsZero()
		jz := tj.IsZero()
		if iz && jz {
			// 两者都没有创建时间，保持原有（severity->name）的相对顺序
			return false
		}
		if iz != jz {
			// 有创建时间的排前面
			return !iz && jz
		}
		// 都有创建时间，越新越靠前
		return ti.After(tj)
	})

	// 分页
	total := len(items)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := items[start:end]

	// 转为 API 输出结构，新增 created 字段
	respItems := make([]PocsListItem, 0, len(pageItems))
	for _, it := range pageItems {
		respItems = append(respItems, PocsListItem{
			ID:       it.ID,
			Name:     it.Name,
			Severity: it.Severity,
			Author:   it.Author,
			Tags:     it.Tags,
			Source:   string(it.Source),
			Path:     it.Path,
			Created:  it.Created,
		})
	}

	// 返回
	w.WriteHeader(http.StatusOK)
	totalPages := int((total + pageSize - 1) / pageSize)
	data := PocsListResponse{
		Items:      respItems,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Source:     source,
		Severity:   severityList,
		Tags:       tagsList,
		Author:     authorList,
		Keyword:    keyword,
	}
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "OK",
		Data:    data,
	})
}
