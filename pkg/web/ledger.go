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

// ledgerBatchRequest 是台账批量流转的请求体：每一行用 (vulid, target, fulltarget)
// 定位，整批置为同一个状态，与台账的分组口径一致。
type ledgerBatchRequest struct {
	Status string `json:"status"`
	Items  []struct {
		VulID      string `json:"vulid"`
		Target     string `json:"target"`
		FullTarget string `json:"fulltarget"`
	} `json:"items"`
}

// ledgerBatchUpdateHandler 把选中的命中批量置为同一台账状态。
//
// 与单条「只改状态」语义一致：只覆盖 status，不动各条已有的备注。会员专属。
func ledgerBatchUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req ledgerBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if len(req.Items) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少要处理的记录"})
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if !ledgerStatusSet[status] {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "status 取值非法"})
		return
	}

	keys := make([]sqlite.ResultKey, 0, len(req.Items))
	for _, it := range req.Items {
		keys = append(keys, sqlite.ResultKey{
			VulID:      it.VulID,
			Target:     it.Target,
			FullTarget: it.FullTarget,
		})
	}

	updated, err := sqlite.UpsertLedgerStatusBatch(keys, status)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "批量更新台账失败"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "已更新",
		Data:    map[string]any{"updated": updated},
	})
}

// ledgerDeleteRequest 是台账批量删除的请求体：每一行用 (vulid, target, fulltarget) 定位，
// 与台账的分组口径一致。
type ledgerDeleteRequest struct {
	Items []struct {
		VulID      string `json:"vulid"`
		Target     string `json:"target"`
		FullTarget string `json:"fulltarget"`
	} `json:"items"`
}

// ledgerDeleteHandler 批量删除台账选中的命中记录。
//
// 台账是 result 表按 (PoC, 目标) 聚合出的视图，删除即连同底层命中一起移除，
// 并清掉对应的人工状态/备注，保证台账与漏洞报告两侧同时消失。会员专属。
func ledgerDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req ledgerDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if len(req.Items) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少要删除的记录"})
		return
	}

	keys := make([]sqlite.ResultKey, 0, len(req.Items))
	for _, it := range req.Items {
		keys = append(keys, sqlite.ResultKey{
			VulID:      it.VulID,
			Target:     it.Target,
			FullTarget: it.FullTarget,
		})
	}

	deleted, err := sqlite.DeleteResultsByKeys(keys)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "删除失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{"deleted": deleted}})
}
