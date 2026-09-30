package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/gologger"
)

// -----------------------
// 资产（目标唯一真源）
// -----------------------
//
// 与旧的「资产集文件」不同：资产进库、地址归一化后唯一、标签即分组。
// 目标进入资产表只有两个入口：
//   1. 扫描起跑时沉淀（recordScanTargets，见下）
//   2. 用户在资产页手工新增 / 导入（assetsCreateHandler）
// 项目、任务、后续的计划任务都只「引用」资产，不再各自存一份目标。

// classifyAddress 判定归一化后地址的类型，供列表分组与图标展示。
func classifyAddress(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i > 0 {
		return "url"
	}
	if ip := net.ParseIP(s); ip != nil {
		return "ip"
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return "cidr"
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return "hostport"
	}
	return "domain"
}

// buildAssetInputs 把原始行整理成可入库的目标，返回整理后的输入与被忽略的条数。
// 同一批内的重复只在入库时合并计数，不在这里丢弃统计。
func buildAssetInputs(raw []string) ([]sqlite.AssetInput, int) {
	inputs := make([]sqlite.AssetInput, 0, len(raw))
	invalid := 0
	for _, line := range raw {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if !isValidAddress(t) {
			invalid++
			continue
		}
		addr := normalizeAddress(t)
		if addr == "" {
			invalid++
			continue
		}
		inputs = append(inputs, sqlite.AssetInput{Address: addr, Type: classifyAddress(addr)})
	}
	return inputs, invalid
}

// recordScanTargets 把一次扫描的目标沉淀进资产表，并记录该任务扫过哪些目标。
// 这是「资产自动沉淀」的唯一入口：失败只记日志，绝不影响扫描本身。
func recordScanTargets(taskID, projectID string, targets []string) {
	if strings.TrimSpace(taskID) == "" || len(targets) == 0 {
		return
	}
	inputs, _ := buildAssetInputs(targets)
	if len(inputs) == 0 {
		return
	}

	source, ref := "scan", ""
	if p := strings.TrimSpace(projectID); p != "" {
		source, ref = "project", p
	}
	if _, err := sqlite.SinkAssets(taskID, source, ref, inputs); err != nil {
		gologger.Warning().Msgf("asset sink failed for task %s: %v", taskID, err)
	}
}

// assetsListHandler 返回资产列表（支持筛选/分页）与各视图数量。
func assetsListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	q := r.URL.Query()
	filter := sqlite.AssetFilter{
		View:     strings.TrimSpace(q.Get("view")),
		Keyword:  strings.TrimSpace(q.Get("q")),
		Tags:     q["tag"],
		Type:     strings.TrimSpace(q.Get("type")),
		Source:   strings.TrimSpace(q.Get("source")),
		Page:     atoiDefault(q.Get("page"), 1),
		PageSize: atoiDefault(q.Get("page_size"), 50),
	}
	if v := strings.TrimSpace(q.Get("stale_days")); v != "" {
		filter.StaleDays = atoiDefault(v, 0)
	}
	filter.IncludeArchived = q.Get("include_archived") == "1" || q.Get("include_archived") == "true"

	page, err := sqlite.ListAssets(filter)
	if err != nil {
		gologger.Warning().Msgf("list assets failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取资产失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: page})
}

// assetsCreateHandler 手工新增/导入资产（粘贴文本或直接给条目数组）。
func assetsCreateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req struct {
		Content string          `json:"content"`
		Items   []string        `json:"items"`
		Tags    json.RawMessage `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	raw := make([]string, 0, len(req.Items)+32)
	raw = append(raw, req.Items...)
	if strings.TrimSpace(req.Content) != "" {
		raw = append(raw, strings.Split(req.Content, "\n")...)
	}

	inputs, invalid := buildAssetInputs(raw)
	res, err := sqlite.CreateAssets("manual", "", parseStringList(req.Tags), inputs)
	if err != nil {
		gologger.Warning().Msgf("create assets failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入资产失败"})
		return
	}
	res.Invalid += invalid
	// 附带入库后的 id（= 归一化地址），项目选择器可以据此直接把新地址加进引用。
	ids := make([]string, 0, len(inputs))
	for _, in := range inputs {
		ids = append(ids, in.Address)
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: map[string]any{
		"added":    res.Added,
		"existing": res.Existing,
		"invalid":  res.Invalid,
		"ids":      ids,
	}})
}

// assetsUpdateHandler 批量改标签 / 收藏 / 归档 / 备注。
func assetsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req struct {
		IDs        []string        `json:"ids"`
		AddTags    json.RawMessage `json:"add_tags"`
		RemoveTags json.RawMessage `json:"remove_tags"`
		Starred    *bool           `json:"starred"`
		Archived   *bool           `json:"archived"`
		Note       *string         `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if len(req.IDs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少ids"})
		return
	}

	updated, err := sqlite.UpdateAssets(req.IDs, parseStringList(req.AddTags), parseStringList(req.RemoveTags), req.Starred, req.Archived, req.Note)
	if err != nil {
		gologger.Warning().Msgf("update assets failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "更新资产失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: map[string]any{"updated": updated}})
}

// assetsDeleteHandler 批量删除资产。
func assetsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if len(req.IDs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少ids"})
		return
	}

	deleted, err := sqlite.DeleteAssets(req.IDs)
	if err != nil {
		gologger.Warning().Msgf("delete assets failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "删除资产失败"})
		return
	}
	// project_asset 的成员行由 sqlite.DeleteAssets 在同一事务里级联清理。
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: map[string]any{"deleted": deleted}})
}

// assetsFacetsHandler 返回筛选器可选项（标签 / 类型 / 来源及数量）。
func assetsFacetsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	facets, err := sqlite.LoadAssetFacets()
	if err != nil {
		gologger.Warning().Msgf("load asset facets failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取筛选项失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: facets})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// parseStringList 容忍两种写法：["a","b"] 或 "a,b"。
// 前端的标签输入框天然给的是逗号分隔字符串，不必强制它先拆成数组。
func parseStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.Split(s, ",")
	}
	return nil
}
