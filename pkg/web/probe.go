package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/gologger"
)

// -----------------------
// 资产发现明细（端口 / Web 探测）
// -----------------------
//
// 扫描时这些结果只走事件流，服务重启或换浏览器后详情页就再也看不到。这里在事件产生时
// 顺手落库（失败只记日志，绝不影响扫描），让历史任务也能回看，并支持把选中的
// IP:端口 / URL 手动加入资产、归属到项目。

// recordProbe 把一条资产发现事件落库。data 与推送给前端的事件载荷同构，
// 保证「在线渲染」与「历史回看」用同一份结构。
func recordProbe(taskID, kind string, ts int64, target string, port, status int, title string, data map[string]interface{}) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	if err := sqlite.InsertProbeEvent(sqlite.ProbeEvent{
		TaskID: taskID,
		Kind:   kind,
		TS:     ts,
		Target: target,
		Port:   port,
		Status: status,
		Title:  title,
		Data:   json.RawMessage(raw),
	}); err != nil {
		gologger.Debug().Msgf("记录资产发现失败: task=%s kind=%s err=%v", taskID, kind, err)
	}
}

// scanProbesListHandler 返回某次扫描已落库的资产发现明细（可按 kind 过滤）。
func scanProbesListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}

	items, err := sqlite.SelectProbeEvents(taskID, strings.TrimSpace(r.URL.Query().Get("kind")))
	if err != nil {
		gologger.Warning().Msgf("读取资产发现明细失败: task=%s err=%v", taskID, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取资产发现明细失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items": items,
		"total": len(items),
	}})
}

// probeAddress 把一条资产发现记录转成可入库的资产地址：
// 端口取 host:port，Web 探测取 URL。IPv6 用 JoinHostPort 保证方括号正确。
func probeAddress(ev sqlite.ProbeEvent) string {
	if strings.EqualFold(ev.Kind, "port") {
		host := strings.TrimSpace(ev.Target)
		if host == "" || ev.Port <= 0 {
			return ""
		}
		return net.JoinHostPort(host, strconv.Itoa(ev.Port))
	}
	return strings.TrimSpace(ev.Target)
}

// scanProbesPromoteHandler 把选中的资产发现条目加入资产库，可选归属到某个项目。
//
// 只创建/引用资产，不修改项目已有成员（增量追加），因此不会像「保存项目」那样
// 把项目成员整体替换掉。
func scanProbesPromoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}

	var req struct {
		IDs       []int64 `json:"ids"`
		ProjectID string  `json:"project_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if len(req.IDs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "请先选择要加入的条目"})
		return
	}

	projectID := strings.TrimSpace(req.ProjectID)
	if projectID != "" {
		if _, ok := findProject(projectID); !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目不存在"})
			return
		}
	}

	probes, err := sqlite.ProbeByID(taskID, req.IDs)
	if err != nil {
		gologger.Warning().Msgf("读取待加入资产失败: task=%s err=%v", taskID, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取待加入资产失败"})
		return
	}
	if len(probes) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "选中的条目已不在保留范围内"})
		return
	}

	addresses := make([]string, 0, len(probes))
	for _, ev := range probes {
		if addr := probeAddress(ev); addr != "" {
			addresses = append(addresses, addr)
		}
	}

	inputs, invalid := buildAssetInputs(addresses)
	source, ref := "scan", taskID
	if projectID != "" {
		source, ref = "project", projectID
	}
	res, err := sqlite.CreateAssets(source, ref, nil, inputs)
	if err != nil {
		gologger.Warning().Msgf("加入资产失败: task=%s err=%v", taskID, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入资产失败"})
		return
	}
	res.Invalid += invalid

	linked := int64(0)
	if projectID != "" && len(inputs) > 0 {
		ids := make([]string, 0, len(inputs))
		for _, in := range inputs {
			ids = append(ids, in.Address)
		}
		if linked, err = sqlite.AppendProjectAssets(projectID, ids); err != nil {
			gologger.Warning().Msgf("关联项目资产失败: project=%s err=%v", projectID, err)
		}
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"added":    res.Added,
		"existing": res.Existing,
		"invalid":  res.Invalid,
		"linked":   linked,
	}})
}
