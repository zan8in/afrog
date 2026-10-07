package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/webreport"
)

// exportBrandSite 是报告水印里的站点标识。
//
// 留空：此前写死的域名并不正确，打在报告水印里会误导阅读者。水印只保留产品名，
// 见 webreport.brandLine：Site 为空时只输出产品名（不带 " · " 分隔）。
const exportBrandSite = ""

// exportFormat 是报告导出格式。
type exportFormat string

const (
	formatHTML     exportFormat = "html"
	formatXLSX     exportFormat = "xlsx"
	formatMarkdown exportFormat = "md"
)

func parseExportFormat(raw string) (exportFormat, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(formatHTML):
		return formatHTML, true
	case string(formatXLSX):
		return formatXLSX, true
	case string(formatMarkdown):
		return formatMarkdown, true
	default:
		return "", false
	}
}

// exportFormatAllowed 落实 PRD 的权益边界：免费用户只能导出 Markdown，
// HTML / Excel（以及由 HTML 打印得到的 PDF）为 Curated 会员能力。
func exportFormatAllowed(f exportFormat) bool {
	if f == formatMarkdown {
		return true
	}
	return curatedRole() == "curated"
}

func exportContentType(f exportFormat) string {
	switch f {
	case formatXLSX:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case formatMarkdown:
		return "text/markdown; charset=utf-8"
	default:
		return "text/html; charset=utf-8"
	}
}

func exportExtension(f exportFormat) string {
	switch f {
	case formatXLSX:
		return "xlsx"
	case formatMarkdown:
		return "md"
	default:
		return "html"
	}
}

func writeExportError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: message})
}

// renderExport 是三个导出入口共用的落盘逻辑：鉴权后的格式校验 → 渲染 → 写响应。
func renderExport(w http.ResponseWriter, r *http.Request, meta webreport.Meta, rows []db.ResultData) {
	format, ok := parseExportFormat(r.URL.Query().Get("format"))
	if !ok {
		writeExportError(w, http.StatusBadRequest, "format 仅支持 html / xlsx / md")
		return
	}
	if !exportFormatAllowed(format) {
		writeExportError(w, http.StatusForbidden, "HTML / Excel 报告导出为 Curated 会员专属，免费版可导出 Markdown")
		return
	}

	isCurated := curatedRole() == "curated"
	brand := webreport.Brand{
		Product:   "afrog",
		Version:   config.Version,
		Site:      exportBrandSite,
		Watermark: isCurated,
	}
	doc := webreport.Build(meta, brand, rows, len(rows) >= sqlite.ExportRowLimit)

	var (
		body        []byte
		err         error
		disposition = "attachment"
	)
	switch format {
	case formatXLSX:
		body, err = webreport.RenderXLSX(doc)
	case formatMarkdown:
		body = webreport.RenderMarkdown(doc)
	default:
		autoPrint := r.URL.Query().Get("print") == "1"
		if autoPrint {
			// 打印视图在标签页里直接打开，不应触发下载。
			disposition = "inline"
		}
		body, err = webreport.RenderHTML(doc, webreport.HTMLOptions{AutoPrint: autoPrint})
	}
	if err != nil {
		writeExportError(w, http.StatusInternalServerError, "报告生成失败")
		return
	}

	filename := webreport.FileName(meta, exportExtension(format))
	w.Header().Set("Content-Type", exportContentType(format))
	w.Header().Set("Content-Disposition", contentDisposition(disposition, filename))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// contentDisposition 同时给出 ASCII 回退名与 RFC 5987 的 UTF-8 文件名，
// 保证中文报告名在各浏览器下都能正确落地。
func contentDisposition(disposition, filename string) string {
	ascii := make([]rune, 0, len(filename))
	for _, r := range filename {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			ascii = append(ascii, '_')
			continue
		}
		ascii = append(ascii, r)
	}
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`,
		disposition, string(ascii), url.PathEscape(filename))
}

// distinctTargets 从结果行里提取去重后的目标列表（保持出现顺序），
// 用于报告头部描述扫描范围；历史任务没有任务快照时也能拿到。
func distinctTargets(rows []db.ResultData) []string {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	for _, row := range rows {
		t := strings.TrimSpace(row.Target)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// taskDisplayName 优先用任务管理里的任务名，取不到时回退为任务 ID。
func taskDisplayName(taskID string) string {
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t != nil && strings.TrimSpace(t.Name) != "" {
		return t.Name
	}
	return taskID
}

// exportTaskHandler 导出单次扫描任务的报告。
// GET /exports/task/{taskId}?format=html|xlsx|md&print=1&severity=high,critical
func exportTaskHandler(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if taskID == "" {
		writeExportError(w, http.StatusBadRequest, "缺少任务ID")
		return
	}

	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	rows, err := sqlite.SelectAllByTask(taskID, severity, true, true)
	if err != nil {
		writeExportError(w, http.StatusInternalServerError, "读取扫描结果失败")
		return
	}

	m := getTaskManager()
	m.mu.Lock()
	_, known := m.tasks[taskID]
	m.mu.Unlock()
	if !known && len(rows) == 0 {
		writeExportError(w, http.StatusNotFound, "任务不存在或没有可导出的结果")
		return
	}

	meta := webreport.Meta{
		Title:       "扫描报告",
		Subject:     taskDisplayName(taskID),
		TaskIDs:     []string{taskID},
		Targets:     distinctTargets(rows),
		Severities:  splitCSVParam(severity),
		GeneratedAt: time.Now(),
	}
	if projectID, err := sqlite.SelectTaskProject(taskID); err == nil && projectID != "" {
		if p, ok := findProject(projectID); ok {
			meta.ProjectName = p.Name
		}
	}

	renderExport(w, r, meta, rows)
}

// exportReportsHandler 导出漏洞报告页当前筛选结果。
// GET /exports/reports?format=...&severity=high&keyword=ftp&task_id=<id>
// task_id 非空时只导出该任务，与页面上「按任务筛选」的范围保持一致。
func exportReportsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	severity := strings.TrimSpace(q.Get("severity"))
	keyword := strings.TrimSpace(q.Get("keyword"))
	taskID := strings.TrimSpace(q.Get("task_id"))

	rows, err := sqlite.SelectAllFiltered(taskID, severity, keyword, true, true)
	if err != nil {
		writeExportError(w, http.StatusInternalServerError, "读取报告数据失败")
		return
	}

	subject := "筛选结果"
	if taskID != "" {
		subject = taskDisplayName(taskID)
	}
	meta := webreport.Meta{
		Title:       "漏洞报告",
		Subject:     subject,
		Targets:     distinctTargets(rows),
		Severities:  splitCSVParam(severity),
		Keyword:     keyword,
		ScopeNote:   "仅包含当前筛选条件命中的记录",
		GeneratedAt: time.Now(),
	}
	renderExport(w, r, meta, rows)
}

// exportProjectHandler 导出某个项目下全部扫描任务的汇总报告。
// GET /exports/project/{projectId}?format=...&severity=...
func exportProjectHandler(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(mux.Vars(r)["projectId"])
	if projectID == "" {
		writeExportError(w, http.StatusBadRequest, "缺少项目ID")
		return
	}
	project, ok := findProject(projectID)
	if !ok {
		writeExportError(w, http.StatusNotFound, "项目不存在")
		return
	}

	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	rows, err := sqlite.SelectAllByProject(projectID, severity, true, true)
	if err != nil {
		writeExportError(w, http.StatusInternalServerError, "读取项目结果失败")
		return
	}

	taskIDs, err := sqlite.SelectProjectTaskIDs(projectID)
	if err != nil {
		writeExportError(w, http.StatusInternalServerError, "读取项目任务失败")
		return
	}

	meta := webreport.Meta{
		Title:       "项目报告",
		Subject:     project.Name,
		ProjectName: project.Name,
		TaskIDs:     taskIDs,
		Targets:     resolveProjectTargets(projectID),
		Severities:  splitCSVParam(severity),
		ScopeNote:   "汇总项目下全部扫描任务的命中记录",
		GeneratedAt: time.Now(),
	}
	renderExport(w, r, meta, rows)
}
