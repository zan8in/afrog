// Package guard 提供高危动作的统一处置闸门与审计。
//
// 设计取舍：
//  1. 默认 allow —— 安全能力是显式开启的，升级工具不应悄悄改变既有行为。
//  2. allow_targets 是硬边界：非空时，白名单外的目标一律拒绝，与 mode 无关。
//     这防的是「集群密钥泄露后，本机被当成跳板扫描任意目标」。
//  3. ask 在无人值守的服务端没有交互对象，因此等价于「拒绝并记为待确认」，
//     绝不静默放行。宁可让动作失败，也不让未确认的高危动作穿透。
package guard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Action 是需要闸门裁决的动作标识。
type Action string

const (
	// ActionClusterDispatch 是集群远程派发：外部实例要求本机执行一次扫描。
	ActionClusterDispatch Action = "cluster-dispatch"
	// ActionExposureProbe 是被动扫描的敏感路径主动探测：每个 origin 一轮探针，
	// 会主动发请求，因此受 allow/deny/ask 约束（由 exposure 检测器在门控阶段裁决）。
	ActionExposureProbe Action = "exposure-probe"
)

// Mode 是某个动作的处置方式。
type Mode string

const (
	ModeAllow Mode = "allow"
	ModeDeny  Mode = "deny"
	ModeAsk   Mode = "ask"
)

// NormalizeMode 把配置里的字符串归一化成 Mode；未知值按 allow 处理并返回 false。
func NormalizeMode(v string) (Mode, bool) {
	switch Mode(strings.ToLower(strings.TrimSpace(v))) {
	case ModeAllow:
		return ModeAllow, true
	case ModeDeny:
		return ModeDeny, true
	case ModeAsk:
		return ModeAsk, true
	}
	return ModeAllow, false
}

// Decision 是一次裁决结果。
type Decision struct {
	// Allowed 为 false 时调用方必须拒绝执行。
	Allowed bool
	Mode    Mode
	Action  Action
	Target  string
	Reason  string
}

// Entry 是一条审计记录。
type Entry struct {
	Time    time.Time `json:"time"`
	Action  Action    `json:"action"`
	Target  string    `json:"target"`
	Mode    Mode      `json:"mode"`
	Allowed bool      `json:"allowed"`
	Reason  string    `json:"reason,omitempty"`
}

// View 是策略与最近审计的对外快照，供界面展示当前闸门状态。
type View struct {
	Actions      map[string]string `json:"actions"`
	AllowTargets []string          `json:"allow_targets"`
	Audit        []Entry           `json:"audit"`
}

const auditLimit = 200

// targetRule 是一条白名单规则：精确 host、通配后缀或 CIDR。
type targetRule struct {
	raw    string
	suffix string
	ipnet  *net.IPNet
}

// Policy 是线程安全的闸门策略。
type Policy struct {
	mu           sync.Mutex
	modes        map[Action]Mode
	allowTargets []string
	rules        []targetRule
	audit        []Entry
}

// NewPolicy 构建策略。actions 的 key 是动作名，value 是 allow/deny/ask。
func NewPolicy(actions map[string]string, allowTargets []string) *Policy {
	p := &Policy{modes: make(map[Action]Mode)}
	p.configure(actions, allowTargets)
	return p
}

func (p *Policy) configure(actions map[string]string, allowTargets []string) {
	modes := make(map[Action]Mode, len(actions))
	for k, v := range actions {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" {
			continue
		}
		mode, ok := NormalizeMode(v)
		if !ok {
			continue
		}
		modes[Action(name)] = mode
	}

	targets := make([]string, 0, len(allowTargets))
	rules := make([]targetRule, 0, len(allowTargets))
	for _, t := range allowTargets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		targets = append(targets, t)
		rules = append(rules, parseRule(t))
	}
	p.modes = modes
	p.allowTargets = targets
	p.rules = rules
}

// Check 裁决一次动作。target 可以是 URL、host:port、IP 或 CIDR 内的具体地址。
func (p *Policy) Check(action Action, target string) Decision {
	p.mu.Lock()

	mode := p.modes[action]
	if mode == "" {
		mode = ModeAllow
	}
	d := Decision{Action: action, Target: target, Mode: mode}

	switch {
	case len(p.rules) > 0 && !p.matchAny(target):
		// 白名单一旦配置就是硬边界：宁可拒绝，也不因为 mode=allow 而穿透。
		d.Mode = ModeDeny
		d.Reason = "目标不在安全白名单内"
	case mode == ModeDeny:
		d.Reason = "该动作已被安全策略拒绝"
	case mode == ModeAsk:
		d.Reason = "该动作需要人工确认（无人值守时不自动放行）"
	default:
		d.Allowed = true
	}

	entry := p.recordLocked(d)
	p.mu.Unlock()

	// 回调放在锁外：落盘可能涉及文件或数据库，不能让它持有策略锁。
	if sink := decisionSink(); sink != nil {
		sink(entry)
	}
	return d
}

// matchAny 判断目标是否命中任一白名单规则。
func (p *Policy) matchAny(target string) bool {
	host := hostOf(target)
	if host == "" {
		return false
	}
	bare := stripPort(host)
	ip := net.ParseIP(bare)
	for _, r := range p.rules {
		if r.ipnet != nil {
			if ip != nil && r.ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if r.suffix != "" {
			if bare == r.suffix || strings.HasSuffix(bare, "."+r.suffix) {
				return true
			}
			continue
		}
		if strings.EqualFold(host, r.raw) || strings.EqualFold(bare, r.raw) {
			return true
		}
	}
	return false
}

func (p *Policy) recordLocked(d Decision) Entry {
	entry := Entry{
		Time: time.Now(), Action: d.Action, Target: d.Target,
		Mode: d.Mode, Allowed: d.Allowed, Reason: d.Reason,
	}
	p.audit = append(p.audit, entry)
	if len(p.audit) > auditLimit {
		p.audit = p.audit[len(p.audit)-auditLimit:]
	}
	return entry
}

// Snapshot 返回当前策略与最近审计（最新的在前）。
func (p *Policy) Snapshot() View {
	p.mu.Lock()
	defer p.mu.Unlock()

	actions := make(map[string]string, len(p.modes)+2)
	// 未显式配置的动作也要展示出来，避免使用者以为「没显示 = 没生效」。
	for _, a := range []Action{ActionClusterDispatch, ActionExposureProbe} {
		mode := p.modes[a]
		if mode == "" {
			mode = ModeAllow
		}
		actions[string(a)] = string(mode)
	}
	for a, m := range p.modes {
		actions[string(a)] = string(m)
	}

	audit := make([]Entry, len(p.audit))
	for i := range p.audit {
		audit[len(p.audit)-1-i] = p.audit[i]
	}
	// 空白名单必须序列化成 []，不能是 null：前者是「没有规则」，
	// 后者会让消费方在读 .length 时直接炸掉。
	targets := make([]string, 0, len(p.allowTargets))
	targets = append(targets, p.allowTargets...)
	return View{
		Actions:      actions,
		AllowTargets: targets,
		Audit:        audit,
	}
}

// ActionSummary 是单个动作的概览，不含审计明细。
type ActionSummary struct {
	Mode    string `json:"mode"`
	Blocked int    `json:"blocked"`
}

// SummaryView 是给总览页用的紧凑状态：策略 + 最近拦截次数。
type SummaryView struct {
	Actions      map[string]ActionSummary `json:"actions"`
	AllowTargets []string                 `json:"allow_targets"`
	Blocked      int                      `json:"blocked"`
}

// Summary 返回紧凑概览。
func (p *Policy) Summary() SummaryView {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := SummaryView{Actions: make(map[string]ActionSummary, len(p.modes)+2)}
	for a, m := range p.modes {
		out.Actions[string(a)] = ActionSummary{Mode: string(m)}
	}
	for _, a := range []Action{ActionClusterDispatch, ActionExposureProbe} {
		if _, ok := out.Actions[string(a)]; !ok {
			out.Actions[string(a)] = ActionSummary{Mode: string(ModeAllow)}
		}
	}
	for _, e := range p.audit {
		if e.Allowed {
			continue
		}
		out.Blocked++
		s := out.Actions[string(e.Action)]
		s.Mode = string(e.Mode)
		s.Blocked++
		out.Actions[string(e.Action)] = s
	}
	out.AllowTargets = make([]string, 0, len(p.allowTargets))
	out.AllowTargets = append(out.AllowTargets, p.allowTargets...)
	return out
}

// parseRule 解析一条白名单规则。
func parseRule(raw string) targetRule {
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		return targetRule{raw: raw, ipnet: ipnet}
	}
	if strings.HasPrefix(raw, "*.") {
		return targetRule{raw: raw, suffix: strings.ToLower(strings.TrimPrefix(raw, "*."))}
	}
	return targetRule{raw: strings.ToLower(raw)}
}

// hostOf 从各种写法里取出 host（去掉 scheme、路径与端口）。
func hostOf(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return strings.ToLower(u.Host)
		}
	}
	// 去掉可能的路径与查询串。
	if i := strings.IndexAny(target, "/?#"); i >= 0 {
		target = target[:i]
	}
	return strings.ToLower(target)
}

// stripPort 去掉 host 上的端口；IPv6 的 [::1]:80 也能正确处理。
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

// -----------------------
// 全局策略
// -----------------------

var (
	globalMu     sync.RWMutex
	globalPolicy = NewPolicy(nil, nil)

	sinkMu     sync.RWMutex
	globalSink func(Entry)
)

// SetSink 设置裁决回调（传 nil 关闭）。
//
// 回调在策略锁外同步执行，用于把裁决写到文件或数据库；它位于动作执行路径上，
// 实现方必须保持轻量，不能在里面做重活或回调 guard 本身。
func SetSink(fn func(Entry)) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	globalSink = fn
}

func decisionSink() func(Entry) {
	sinkMu.RLock()
	defer sinkMu.RUnlock()
	return globalSink
}

// Configure 用配置重建全局策略。并发安全，可在运行时重复调用。
func Configure(actions map[string]string, allowTargets []string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalPolicy = NewPolicy(actions, allowTargets)
}

// Check 用全局策略裁决一次动作。
func Check(action Action, target string) Decision {
	globalMu.RLock()
	p := globalPolicy
	globalMu.RUnlock()
	return p.Check(action, target)
}

// Snapshot 返回全局策略快照。
func Snapshot() View {
	globalMu.RLock()
	p := globalPolicy
	globalMu.RUnlock()
	return p.Snapshot()
}

// Summary 返回全局策略的紧凑概览。
func Summary() SummaryView {
	globalMu.RLock()
	p := globalPolicy
	globalMu.RUnlock()
	return p.Summary()
}

// Describe 生成一条人类可读的裁决描述，供日志与接口错误信息复用。
func (d Decision) Describe() string {
	if d.Allowed {
		return fmt.Sprintf("%s 允许执行（mode=%s）", d.Action, d.Mode)
	}
	if d.Reason != "" {
		return fmt.Sprintf("%s 被拒绝：%s（target=%s, mode=%s）", d.Action, d.Reason, d.Target, d.Mode)
	}
	return fmt.Sprintf("%s 被拒绝（target=%s, mode=%s）", d.Action, d.Target, d.Mode)
}
