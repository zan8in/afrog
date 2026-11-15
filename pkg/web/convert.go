package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/nuclei2afrog"
	"github.com/zan8in/afrog/v3/pkg/validator"
)

// pocsConvertNucleiHandler 把一段 nuclei 模板转换成 afrog PoC。
//
// 转换器（pkg/nuclei2afrog）内部已有三重闸门：结构分档 → 语义翻译 → afrog CEL
// 编译自校验，任一步做不到「忠实转换」都会降级为 C 类且不产出 YAML。
// 因此本接口只做输入输出搬运，不做二次判定；分档结论与缺口原因原样透传给前端。
//
// 回应里的 usable 表示「yaml 是否为可直接扫描的 PoC」（仅 A/B 为 true）；
// C 类会额外返回 skeleton（结构骨架 + TODO），它是给人/AI 补全的草稿，不可直接使用。
//
// 只转换、不落盘：是否保存由调用方在确认结果后再走 /api/pocs/create。
func pocsConvertNucleiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req struct {
		YamlContent string `json:"yaml_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if strings.TrimSpace(req.YamlContent) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "yaml_content 不能为空"})
		return
	}
	// 先挡掉「不是 nuclei 模板」的输入，避免把 afrog 自身的 PoC 也拿去转换后得到误导性分档。
	if !validator.LooksLikeNucleiTemplate(req.YamlContent) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "内容不是 nuclei 模板（未发现 http/requests 或 matchers 协议段）",
		})
		return
	}

	res, err := nuclei2afrog.Convert([]byte(req.YamlContent))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	// nil 切片会序列化成 null，前端按数组消费，这里统一成空数组。
	warnings := res.Warnings
	if warnings == nil {
		warnings = []nuclei2afrog.Warning{}
	}
	gaps := res.Gaps
	if gaps == nil {
		gaps = []string{}
	}

	data := map[string]any{
		"class": string(res.Class),
		// convertible 为兼容旧前端保留，与 usable 同义：仅 A/B 为 true。
		"convertible": res.Usable,
		// usable=false 时 yaml 必为空；此时若为 C 类，skeleton 给出「骨架 + TODO」草稿，
		// 仅供人工/AI 补全，禁止直接保存为可用 PoC。
		"usable":   res.Usable,
		"yaml":     string(res.YAML),
		"skeleton": string(res.Skeleton),
		"warnings": warnings,
		"gaps":     gaps,
		"report":   res.Report,
	}
	if len(res.Pocs) > 0 {
		p := res.Pocs[0]
		data["poc_id"] = p.Id
		data["poc_name"] = p.Info.Name
		data["severity"] = p.Info.Severity
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: data})
}
