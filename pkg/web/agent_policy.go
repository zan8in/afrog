package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"gopkg.in/yaml.v2"
)

// Agent 写动作面的「策略 / 预算 / 审计」控制台。
//
// 这里暴露的是与 MCP、`afrog mcp` 完全同一份门控（pkg/policy.Gate）的状态：控制台
// 只做展示与写文件，判定仍然只发生在 Gate 内部。保存策略即写回 policy YAML 与
// afrog-config.yaml 的 agent 段，并丢弃旧门控，下一次调用按新策略生效。

// --- 策略与预算状态 ---

type agentScopeState struct {
	AllowHosts []string `json:"allow_hosts"`
	DenyHosts  []string `json:"deny_hosts"`
	DenyPaths  []string `json:"deny_paths"`
}

type agentBudgetState struct {
	// Requests 是策略里配置的会话请求额度，空闲超时后自动补满；
	// Remaining 是本进程当前会话还剩多少。
	Requests int `json:"requests"`
	// Duration 是策略里配置的空闲窗口。
	Duration  string `json:"duration"`
	Remaining int    `json:"remaining"`
	Unlimited bool   `json:"unlimited"`
	// Deadline 是空闲窗口的到期时间（RFC3339）；无时间限制时为空。
	// 有消耗额度的调用成功即顺延，超过它就意味着下一次调用会开新会话。
	Deadline string `json:"deadline,omitempty"`
}

type agentPolicyState struct {
	Mode string `json:"mode"`
	// MaxCapability 是当前档位可达的最高 PoC 能力等级（只读→declarative，
	// safe→network，full→exec），给使用者一个「现在能跑到哪一档」的直观印象。
	MaxCapability string           `json:"max_capability"`
	Allow         []string         `json:"allow"`
	Deny          []string         `json:"deny"`
	Destructive   bool             `json:"destructive"`
	Audit         bool             `json:"audit"`
	Scope         agentScopeState  `json:"scope"`
	Budget        agentBudgetState `json:"budget"`
	// PolicyPath / AuditPath 是当前生效的策略与审计文件路径（留空=只读默认/不记录）。
	PolicyPath string `json:"policy_path"`
	AuditPath  string `json:"audit_path"`
	OOB        string `json:"oob"`
	ConfigPath string `json:"config_path"`
	// LoadError 非空表示策略文件加载失败（此时展示的是只读默认策略）。
	LoadError string `json:"load_error,omitempty"`
}

func agentBudgetStateFrom(g *policy.Gate) agentBudgetState {
	p := g.Policy()
	st := agentBudgetState{Requests: p.Limits.Requests, Duration: p.Limits.Duration.Duration().String()}
	if b := g.Budget(); b != nil {
		st.Remaining = b.Remaining()
		st.Unlimited = st.Remaining < 0
		if d := b.Deadline(); !d.IsZero() {
			st.Deadline = d.Format(time.RFC3339)
		}
	} else {
		st.Remaining = -1
		st.Unlimited = true
	}
	return st
}

func agentModeCapability(m policy.Mode) string {
	switch m {
	case policy.ModeFull:
		return capability.Exec.String()
	case policy.ModeSafe:
		return capability.Network.String()
	default:
		return capability.Declarative.String()
	}
}

func agentPolicyStateFrom(g *policy.Gate, loadErr error) agentPolicyState {
	p := g.Policy()
	st := agentPolicyState{
		Mode:          string(p.Mode),
		MaxCapability: agentModeCapability(p.Mode),
		Allow:         orEmptyStrings(p.Allow),
		Deny:          orEmptyStrings(p.Deny),
		Destructive:   p.Destructive,
		Audit:         p.Audit,
		Scope: agentScopeState{
			AllowHosts: orEmptyStrings(p.Scope.AllowHosts),
			DenyHosts:  orEmptyStrings(p.Scope.DenyHosts),
			DenyPaths:  orEmptyStrings(p.Scope.DenyPaths),
		},
		Budget:     agentBudgetStateFrom(g),
		PolicyPath: agentPolicyPath,
		AuditPath:  agentAuditPath,
		OOB:        agentOOBAdapter,
		ConfigPath: resolveClusterConfigPath(agentConfigPath),
	}
	if loadErr != nil {
		st.LoadError = loadErr.Error()
	}
	return st
}

// agentPolicyGetHandler 返回当前生效的策略、预算余量与相关路径。
//
// 策略文件加载失败时不算致命：回显只读默认策略并带上 load_error，界面据此提示
// 「文件有问题」，而不是整页空白——否则用户没有入口去修它。
func agentPolicyGetHandler(w http.ResponseWriter, r *http.Request) {
	srv, err := agentTools()
	if err != nil {
		agentReviewOK(w, "策略文件加载失败，当前为只读默认", agentPolicyStateFrom(policy.NewGate(policy.Default(), nil, nil), err))
		return
	}
	agentReviewOK(w, "ok", agentPolicyStateFrom(srv.Gate(), nil))
}

// agentPolicyUpdateRequest 是保存策略的入参；语义与 policy YAML 一一对应。
type agentPolicyUpdateRequest struct {
	Mode        string   `json:"mode"`
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	Destructive bool     `json:"destructive"`
	Audit       bool     `json:"audit"`
	Budget      struct {
		Requests int    `json:"requests"`
		Duration string `json:"duration"`
	} `json:"budget"`
	Scope struct {
		AllowHosts []string `json:"allow_hosts"`
		DenyHosts  []string `json:"deny_hosts"`
		DenyPaths  []string `json:"deny_paths"`
	} `json:"scope"`
	// PolicyPath / AuditPath 可选：留空表示沿用当前值（都为空时落到默认位置）。
	PolicyPath string `json:"policy_path"`
	AuditPath  string `json:"audit_path"`
}

// agentPolicyPutHandler 保存策略：写 policy YAML + 回写 afrog-config.yaml 的 agent 段，
// 随后丢弃旧门控，下一次工具调用按新策略生效（预算随之重置）。
func agentPolicyPutHandler(w http.ResponseWriter, r *http.Request) {
	var req agentPolicyUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		agentReviewFail(w, http.StatusBadRequest, "无效的JSON格式")
		return
	}

	mode := policy.Mode(strings.ToLower(strings.TrimSpace(req.Mode)))
	switch mode {
	case policy.ModeReadOnly, policy.ModeSafe, policy.ModeFull:
	default:
		agentReviewFail(w, http.StatusBadRequest, "mode 只能是 readonly / safe / full")
		return
	}

	requests := req.Budget.Requests
	if requests <= 0 {
		requests = policy.DefaultRequests
	}
	dur := policy.Duration(policy.DefaultDuration)
	if s := strings.TrimSpace(req.Budget.Duration); s != "" {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			agentReviewFail(w, http.StatusBadRequest, "budget.duration 非法："+err.Error())
			return
		}
		dur = policy.Duration(parsed)
	}

	next := &policy.Policy{
		Mode:  mode,
		Allow: cleanStringList(req.Allow),
		Deny:  cleanStringList(req.Deny),
		Scope: policy.Scope{
			AllowHosts: cleanStringList(req.Scope.AllowHosts),
			DenyHosts:  cleanStringList(req.Scope.DenyHosts),
			DenyPaths:  cleanStringList(req.Scope.DenyPaths),
		},
		Limits:      policy.Limits{Requests: requests, Duration: dur},
		Destructive: req.Destructive,
		Audit:       req.Audit,
	}

	policyPath := firstNonEmpty(firstNonEmpty(req.PolicyPath, agentPolicyPath), defaultAgentPolicyPath())
	auditPath := strings.TrimSpace(req.AuditPath)
	if auditPath == "" {
		auditPath = agentAuditPath
	}
	if auditPath == "" && next.Audit {
		auditPath = defaultAgentAuditPath()
	}

	if !writePolicyFile(policyPath, next, w) {
		return
	}

	// 回写 afrog-config.yaml 的 agent 段，让重启后仍指向同一份策略与审计文件。
	// 段是整块替换，必须把当前 mcp 子段一并带上，否则保存策略会静默抹掉 MCP 接入配置。
	if err := config.UpdateAgentSection(resolveClusterConfigPath(agentConfigPath), config.Agent{
		Policy: policyPath,
		Audit:  auditPath,
		OOB:    agentOOBAdapter,
		MCP:    agentMCP,
	}); err != nil {
		agentReviewFail(w, http.StatusInternalServerError, "写入配置文件失败："+err.Error())
		return
	}

	agentPolicyPath = policyPath
	agentAuditPath = auditPath
	resetAgentTools()

	agentReviewOK(w, "已保存，立即生效（会话预算随之重置）",
		agentPolicyStateFrom(policy.NewGate(next, nil, nil), nil))
}

// writePolicyFile 把策略写成 YAML 并原子落盘；失败时已写好错误响应并返回 false。
func writePolicyFile(path string, p *policy.Policy, w http.ResponseWriter) bool {
	data, err := yaml.Marshal(p)
	if err != nil {
		agentReviewFail(w, http.StatusInternalServerError, "序列化策略失败："+err.Error())
		return false
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			agentReviewFail(w, http.StatusInternalServerError, "创建策略目录失败："+err.Error())
			return false
		}
	}
	if err := utils.WriteFileAtomic(path, data, 0o600); err != nil {
		agentReviewFail(w, http.StatusInternalServerError, "写入策略文件失败："+err.Error())
		return false
	}
	return true
}

// --- 审计日志 ---

// agentAuditHandler 读取策略判定审计（JSONL），返回最近 limit 条（新的在前）。
func agentAuditHandler(w http.ResponseWriter, r *http.Request) {
	limit := atoiParam(r.URL.Query().Get("limit"), 200)
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	records, note := readAuditRecords(agentAuditPath, limit)
	agentReviewOK(w, "ok", map[string]any{
		"path":    agentAuditPath,
		"records": records,
		"note":    note,
	})
}

// readAuditRecords 从末尾读最近的审计记录（新→旧）。路径为空、文件不存在或损坏
// 行都只返回空结果与一句说明，不让日志缺失影响整个面板。
func readAuditRecords(path string, limit int) ([]policy.Record, string) {
	p := strings.TrimSpace(path)
	if p == "" {
		return []policy.Record{}, "未配置审计路径：设置 agent.audit 后才能记录判定流水"
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []policy.Record{}, "审计文件尚不存在：开启审计后产生第一次判定即会创建"
		}
		return []policy.Record{}, "读取审计文件失败：" + err.Error()
	}

	lines := strings.Split(string(data), "\n")
	out := make([]policy.Record, 0, limit)
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var rec policy.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, ""
}

// --- 工具目录 ---

type agentToolCatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"input_schema"`
	Capability  string `json:"capability"`
	Destructive bool   `json:"destructive"`
	// Allowed / Rule 是在当前策略下对该工具的静态判定（target 为空，不含范围判定），
	// 让目录页能标出「这个工具现在能不能用、被哪条规则拦住」。
	Allowed bool   `json:"allowed"`
	Rule    string `json:"rule"`
	Reason  string `json:"reason,omitempty"`
}

type agentToolCatalog struct {
	Mode   string                  `json:"mode"`
	Tools  []agentToolCatalogEntry `json:"tools"`
	Budget agentBudgetState        `json:"budget"`
}

// agentToolsCatalogHandler 对应 GET /api/v1/tools：列出全部 MCP 工具及其能力等级、
// 破坏性标记与在当前策略下的可用性。它是工具台与接入向导的唯一数据来源。
func agentToolsCatalogHandler(w http.ResponseWriter, r *http.Request) {
	srv, err := agentTools()
	if err != nil {
		agentJSON(w, http.StatusInternalServerError, map[string]any{"error": "策略文件加载失败：" + err.Error()})
		return
	}

	g := srv.Gate()
	p := g.Policy()
	specs := srv.Specs()
	tools := make([]agentToolCatalogEntry, 0, len(specs))
	for _, t := range specs {
		v := p.Evaluate(policy.Action{Name: t.Name, Capability: t.Capability, Destructive: t.Destructive})
		tools = append(tools, agentToolCatalogEntry{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
			Capability:  t.Capability.String(),
			Destructive: t.Destructive,
			Allowed:     v.Allow,
			Rule:        v.Rule,
			Reason:      v.Reason,
		})
	}

	agentJSON(w, http.StatusOK, agentToolCatalog{
		Mode:   string(p.Mode),
		Tools:  tools,
		Budget: agentBudgetStateFrom(g),
	})
}

// --- 辅助 ---

// defaultAgentPolicyPath / defaultAgentAuditPath 是「未在 afrog-config.yaml 配置
// agent.policy/audit」时的落点；保存后会把路径回写进 agent 段。
func defaultAgentPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "agent-policy.yaml"
	}
	return filepath.Join(home, ".config", "afrog", "agent-policy.yaml")
}

func defaultAgentAuditPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "agent-audit.jsonl"
	}
	return filepath.Join(home, ".config", "afrog", "agent-audit.jsonl")
}

// cleanStringList 去掉空白项并 trim，保持 nil（而不是空切片）以便 JSON 输出为 []。
func cleanStringList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func orEmptyStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	return in
}
