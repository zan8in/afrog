package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/drafter"
	"github.com/zan8in/afrog/v3/pkg/learner"
)

// 人审流水线控制台：把 Drafter / Learner 的待审队列搬到 Web，替代 `afrog poc`
// 与 `afrog learn` 的 CLI 终审。
//
// 边界与 CLI 完全一致——这里只是同源 API 的展示层：草稿与建议都是「模型提议、
// 人拍板」。approve 才会把候选写入 ~/.config/afrog/pocs-my；learn 的 accept 只
// 记录人工决策，afrog 绝不解析、不自动应用建议里的 diff。

// 草稿 YAML 回显上限：控制台只需要看结构，不需要把超长草稿整段塞进响应。
const agentDraftYAMLMaxLen = 256 * 1024

// --- 候选 PoC 待审队列（poc_draft） ---

// agentDraftsListHandler 列出候选草稿，?status=pending|approved|rejected（留空为全部）。
// 与 `afrog poc list` 同源。
func agentDraftsListHandler(w http.ResponseWriter, r *http.Request) {
	status, ok := agentDraftStatusParam(r.URL.Query().Get("status"))
	if !ok {
		agentReviewFail(w, http.StatusBadRequest, "status 取值非法")
		return
	}
	items, err := drafter.List(status)
	if err != nil {
		agentReviewInternal(w, err)
		return
	}
	agentReviewOK(w, "ok", items)
}

// agentDraftsStatsHandler 返回流水线指标（含自动入库率），与 `afrog poc stats` 同源。
func agentDraftsStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := drafter.GetStats()
	if err != nil {
		agentReviewInternal(w, err)
		return
	}
	agentReviewOK(w, "ok", stats)
}

// agentDraftShowHandler 取一条候选详情：状态机记录 + 草稿 YAML 原文 + 历史决议流水。
//
// YAML 读不到时不整体失败——状态机记录本身仍要能看，只把 yaml 留空并给出提示。
func agentDraftShowHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	rec, err := drafter.Show(id)
	if err != nil {
		agentReviewInternal(w, err)
		return
	}
	if rec == nil {
		agentReviewFail(w, http.StatusNotFound, "候选不存在")
		return
	}

	reviews, err := sqlite.SelectPocReviews(rec.ID, 50)
	if err != nil {
		agentReviewInternal(w, err)
		return
	}

	agentReviewOK(w, "ok", map[string]any{
		"draft":   rec,
		"yaml":    readTextFileCapped(rec.Path, agentDraftYAMLMaxLen),
		"reviews": reviews,
	})
}

// agentDraftApproveHandler 批准一条候选并入库到 pocs-my，与 `afrog poc approve` 同源。
func agentDraftApproveHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	res, err := drafter.Approve(id)
	if err != nil {
		agentReviewError(w, err)
		return
	}
	agentReviewOK(w, "已入库", res)
}

// agentDraftRejectHandler 驳回一条候选并保留原因，与 `afrog poc reject` 同源。
func agentDraftRejectHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	note, ok := agentReviewNote(w, r)
	if !ok {
		return
	}
	if err := drafter.Reject(id, note); err != nil {
		agentReviewError(w, err)
		return
	}
	agentReviewOK(w, "已驳回", map[string]any{"id": id, "note": note})
}

// --- 调优建议队列（learn_suggestion） ---

// agentSuggestionsListHandler 列出调优建议，?status=pending|accepted|rejected（留空为全部）。
func agentSuggestionsListHandler(w http.ResponseWriter, r *http.Request) {
	status, ok := agentSuggestionStatusParam(r.URL.Query().Get("status"))
	if !ok {
		agentReviewFail(w, http.StatusBadRequest, "status 取值非法")
		return
	}
	items, err := learner.List(status)
	if err != nil {
		agentReviewInternal(w, err)
		return
	}
	agentReviewOK(w, "ok", items)
}

// agentSuggestionShowHandler 取一条建议详情（含完整 diff 文本）。
func agentSuggestionShowHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	rec, err := learner.Show(id)
	if err != nil {
		agentReviewInternal(w, err)
		return
	}
	if rec == nil {
		agentReviewFail(w, http.StatusNotFound, "建议不存在")
		return
	}
	agentReviewOK(w, "ok", rec)
}

// agentSuggestionAcceptHandler 记录「已采纳」决策。注意：不会自动应用 diff。
func agentSuggestionAcceptHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	note, ok := agentReviewNote(w, r)
	if !ok {
		return
	}
	if err := learner.Accept(id, note); err != nil {
		agentReviewError(w, err)
		return
	}
	agentReviewOK(w, "已采纳（仅记录决策，未自动应用 diff）", map[string]any{"id": id, "note": note})
}

// agentSuggestionRejectHandler 记录「已驳回」决策。
func agentSuggestionRejectHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		agentReviewFail(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	note, ok := agentReviewNote(w, r)
	if !ok {
		return
	}
	if err := learner.Reject(id, note); err != nil {
		agentReviewError(w, err)
		return
	}
	agentReviewOK(w, "已驳回", map[string]any{"id": id, "note": note})
}

// --- 辅助 ---

// agentReviewNote 解析可选的 {note} 请求体。空 body 视为不带备注。
func agentReviewNote(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", true
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		// 空 body 的 EOF 属于「没带备注」，不算错误；其它解码失败才拒绝。
		if strings.Contains(err.Error(), "EOF") {
			return "", true
		}
		agentReviewFail(w, http.StatusBadRequest, "无效的JSON格式")
		return "", false
	}
	return strings.TrimSpace(req.Note), true
}

// agentDraftStatusParam 校验候选状态过滤值；空串表示全部。
func agentDraftStatusParam(v string) (string, bool) {
	switch s := strings.ToLower(strings.TrimSpace(v)); s {
	case "", sqlite.PocDraftPending, sqlite.PocDraftApproved, sqlite.PocDraftRejected:
		return s, true
	default:
		return "", false
	}
}

// agentSuggestionStatusParam 校验建议状态过滤值；空串表示全部。
func agentSuggestionStatusParam(v string) (string, bool) {
	switch s := strings.ToLower(strings.TrimSpace(v)); s {
	case "", sqlite.LearnSuggestionPending, sqlite.LearnSuggestionAccepted, sqlite.LearnSuggestionRejected:
		return s, true
	default:
		return "", false
	}
}

// readTextFileCapped 读一个文本文件并在超限时截断；任何读取失败都返回空串
// （调用方通常只是「有则展示」）。
func readTextFileCapped(path string, limit int) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if limit > 0 && len(data) > limit {
		return string(data[:limit]) + "\n...[truncated]"
	}
	return string(data)
}

// agentReviewError 把 drafter/learner 的错误映射成合适的 HTTP 状态：
// 未找到 404，id 冲突 409，参数/校验问题 400，其余（读写失败等）500。
func agentReviewError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		agentReviewFail(w, http.StatusNotFound, msg)
	case strings.Contains(msg, "already provided by"):
		agentReviewFail(w, http.StatusConflict, msg)
	case strings.Contains(msg, "required"), strings.Contains(msg, "invalid"),
		strings.Contains(msg, "not valid"), strings.Contains(msg, "has no rules"):
		agentReviewFail(w, http.StatusBadRequest, msg)
	default:
		agentReviewInternal(w, err)
	}
}

func agentReviewOK(w http.ResponseWriter, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: message, Data: data})
}

func agentReviewFail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: message})
}

func agentReviewInternal(w http.ResponseWriter, err error) {
	agentReviewFail(w, http.StatusInternalServerError, "操作失败："+err.Error())
}
