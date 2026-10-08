package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// 台账状态：待确认 / 已确认 / 误报 / 已修复
var ledgerStatusSet = map[string]bool{
	"pending":        true,
	"confirmed":      true,
	"false_positive": true,
	"fixed":          true,
}

// splitCSVParam 把 "a,b,c" 解析为切片，空项丢弃。
func splitCSVParam(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func atoiParam(v string, def int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// ledgerListHandler 返回台账分页数据（含各状态分布）。会员专属。
func ledgerListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	q := r.URL.Query()
	page, err := sqlite.SelectLedgerPage(sqlite.LedgerFilter{
		Status:   splitCSVParam(q.Get("status")),
		Severity: splitCSVParam(q.Get("severity")),
		Project:  strings.TrimSpace(q.Get("project")),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     atoiParam(q.Get("page"), 1),
		PageSize: atoiParam(q.Get("page_size"), 50),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "台账查询失败"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: page})
}

type ledgerUpdateRequest struct {
	VulID      string `json:"vulid"`
	Target     string `json:"target"`
	FullTarget string `json:"fulltarget"`
	Status     string `json:"status"`
	// Note 为 nil 表示「只改状态」，保留台账里已有的备注；显式传值（含空串）则覆盖。
	Note *string `json:"note"`
}

// ledgerUpdateHandler 更新台账的状态 / 备注 / 所属项目。会员专属。
func ledgerUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req ledgerUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	vulid := strings.TrimSpace(req.VulID)
	if vulid == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "vulid 不能为空"})
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if !ledgerStatusSet[status] {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "status 取值非法"})
		return
	}

	// 只有客户端显式带了 note 才覆盖备注；缺省（nil）表示只改状态，保留原备注。
	var note *string
	if req.Note != nil {
		trimmed := strings.TrimSpace(*req.Note)
		note = &trimmed
	}

	if err := sqlite.UpsertLedgerStatus(
		vulid,
		strings.TrimSpace(req.Target),
		strings.TrimSpace(req.FullTarget),
		status,
		note,
	); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "台账更新失败"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已更新"})
}
