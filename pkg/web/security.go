package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/guard"
	"github.com/zan8in/gologger"
)

// SetSecurityConfig 注入高危动作闸门配置，由 cmd 层在启动 Web 服务前调用。
func SetSecurityConfig(cfg config.Security) {
	guard.Configure(cfg.Actions, cfg.AllowTargets)
	if len(cfg.AllowTargets) > 0 {
		gologger.Info().Msgf("安全闸门已启用: 目标白名单 %d 条", len(cfg.AllowTargets))
	}
}

// securityPolicyHandler 返回当前闸门策略与最近的裁决记录（只读）。
//
// 只读是有意为之：改策略必须改配置文件，避免「点一下就把自己扫描器的边界关了」。
func securityPolicyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: guard.Snapshot()})
}

// checkDispatchGuard 校验一次集群派发的目标是否被允许。
//
// 返回非空字符串表示拒绝原因。目标为空时按「空目标」裁决：一旦配置了白名单，
// 无法校验的派发一律拒绝——这是刻意偏安全的一侧。
func checkDispatchGuard(req ScanCreateRequest) string {
	targets := req.Targets
	if len(targets) == 0 && strings.TrimSpace(req.ProjectID) != "" {
		// 只给了项目时，按住项目成员逐个校验；否则白名单形同虚设。
		targets = resolveProjectTargets(req.ProjectID)
	}
	if len(targets) == 0 {
		if d := guard.Check(guard.ActionClusterDispatch, ""); !d.Allowed {
			return d.Describe()
		}
		return ""
	}
	for _, t := range targets {
		if d := guard.Check(guard.ActionClusterDispatch, t); !d.Allowed {
			return d.Describe()
		}
	}
	return ""
}
