// Package policy 定义 afrog 动作执行前的统一策略门控。
//
// 设计约束：策略判定发生在执行面之前，且拒绝必须给出结构化原因——工具不能被
// 静默跳过，否则使用者无法判断「没扫到」还是「没被允许扫」。
package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"gopkg.in/yaml.v2"
)

// Mode 是策略档位，映射到 PoC 能力等级。
type Mode string

const (
	// ModeReadOnly 只允许读状态与查证据，不发任何新请求。
	ModeReadOnly Mode = "readonly"
	// ModeSafe 允许探测与验证，禁止 act.* 与破坏性动作。
	ModeSafe Mode = "safe"
	// ModeFull 除显式 deny 外全部允许。
	ModeFull Mode = "full"
)

const (
	// DefaultMode 默认只读：一个刚被拉起的 MCP 服务不应该自动获得发包能力。
	DefaultMode = ModeReadOnly
	// DefaultRequests 是单次会话默认的请求预算。
	DefaultRequests = 5000
	// DefaultDuration 是单次会话默认的时间预算。
	DefaultDuration = 10 * time.Minute
)

// Duration 让 YAML 支持 "10m" 这类人类可读写法。
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case nil:
		*d = 0
	case string:
		if strings.TrimSpace(v) == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("policy: invalid duration %q: %w", v, err)
		}
		*d = Duration(parsed)
	case int:
		*d = Duration(time.Duration(v) * time.Second)
	default:
		return fmt.Errorf("policy: invalid duration %v", raw)
	}
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// Duration 返回标准库时长。
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Limits 是单次会话的资源预算。
type Limits struct {
	Requests int      `yaml:"requests"`
	Duration Duration `yaml:"duration"`
	// Tokens 预留给后续 AI 规划器，P1 阶段不参与判定。
	Tokens int `yaml:"tokens"`
}

// Scope 限定可触达的目标范围。deny 优先于 allow。
type Scope struct {
	AllowHosts []string `yaml:"allow_hosts"`
	DenyHosts  []string `yaml:"deny_hosts"`
	DenyPaths  []string `yaml:"deny_paths"`
}

// Policy 是一份可加载的策略。
type Policy struct {
	Mode   Mode     `yaml:"mode"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
	Scope  Scope    `yaml:"scope"`
	Limits Limits   `yaml:"budget"`
	// Destructive 为 false 时禁止可能改变目标状态的动作（典型是暴力破解）。
	Destructive bool `yaml:"destructive"`
	// Audit 为 true 时把每次判定写入审计流。
	Audit bool `yaml:"audit"`
}

// Default 返回默认策略：只读、带请求与时间预算、不做破坏性动作。
func Default() *Policy {
	return (&Policy{Mode: DefaultMode}).withDefaults()
}

// Load 从文件读取策略。
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse 接受两种写法：顶层直接是策略字段，或包在 `policy:` 键下。
func Parse(data []byte) (*Policy, error) {
	var wrapper struct {
		Policy *Policy `yaml:"policy"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err == nil && wrapper.Policy != nil {
		return wrapper.Policy.withDefaults(), nil
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return p.withDefaults(), nil
}

func (p *Policy) withDefaults() *Policy {
	if p == nil {
		return Default()
	}
	switch p.Mode {
	case ModeReadOnly, ModeSafe, ModeFull:
	default:
		p.Mode = DefaultMode
	}
	if p.Limits.Requests == 0 {
		p.Limits.Requests = DefaultRequests
	}
	if p.Limits.Duration == 0 {
		p.Limits.Duration = Duration(DefaultDuration)
	}
	return p
}

// Action 是一次待判定的动作。
type Action struct {
	// Name 形如 observe.evidence / probe.http / verify.poc / act.brute。
	Name string
	// Target 是动作触达的目标，可为空（纯本地查询）。
	Target string
	// Capability 是该动作所需的 PoC 能力等级。
	Capability capability.Level
	// Destructive 标记可能改变目标状态的动作。
	Destructive bool
}

// Verdict 是判定结论。
type Verdict struct {
	Allow  bool
	Rule   string
	Reason string
}

// Evaluate 按固定顺序判定：deny → allowlist → mode → destructive → scope。
func (p *Policy) Evaluate(a Action) Verdict {
	if p == nil {
		p = Default()
	}

	name := strings.TrimSpace(a.Name)
	if name == "" {
		return Verdict{Rule: "invalid", Reason: "action name is empty"}
	}
	if patternMatchAny(p.Deny, name) {
		return Verdict{Rule: "deny", Reason: "explicitly denied"}
	}
	if len(p.Allow) > 0 && !patternMatchAny(p.Allow, name) {
		return Verdict{Rule: "allowlist", Reason: "not in allow list"}
	}
	if rule, ok := p.modeAllows(name); !ok {
		return Verdict{Rule: rule, Reason: "blocked by mode " + string(p.Mode)}
	}
	if (a.Destructive || a.Capability == capability.Exec) && !p.Destructive {
		return Verdict{Rule: "destructive", Reason: "destructive actions are disabled"}
	}
	if !p.scopeAllows(a.Target) {
		return Verdict{Rule: "scope", Reason: "target is out of scope"}
	}
	return Verdict{Allow: true, Rule: "allow", Reason: "allowed"}
}

func (p *Policy) modeAllows(name string) (string, bool) {
	switch p.Mode {
	case ModeFull:
		return "full", true
	case ModeSafe:
		if strings.HasPrefix(name, "act.") {
			return "safe", false
		}
		return "safe", true
	default:
		if isReadOnly(name) {
			return "readonly", true
		}
		return "readonly", false
	}
}

// isReadOnly 判断一个动作是否「不对外发包」。judge.* 与 learn.* 只读写本机 advisory
// 数据（研判意见、调优建议），与 poc.draft 的落盘同源，因此也归入只读档。
func isReadOnly(name string) bool {
	return strings.HasPrefix(name, "observe.") || strings.HasPrefix(name, "plan.") ||
		strings.HasPrefix(name, "judge.") || strings.HasPrefix(name, "learn.") ||
		name == "poc.search" || name == "poc.draft"
}

func (p *Policy) scopeAllows(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return true
	}
	host, path := splitTarget(target)
	if host == "" {
		return true
	}

	for _, pat := range p.Scope.DenyHosts {
		if hostMatch(pat, host) {
			return false
		}
	}
	if len(p.Scope.AllowHosts) > 0 {
		ok := false
		for _, pat := range p.Scope.AllowHosts {
			if hostMatch(pat, host) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, pat := range p.Scope.DenyPaths {
		if pathMatch(pat, path) {
			return false
		}
	}
	return true
}

// splitTarget 从 URL 或 host[:port] 中拆出主机与路径。
func splitTarget(target string) (host, path string) {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname()), u.EscapedPath()
	}
	h := target
	if i := strings.IndexByte(h, '/'); i >= 0 {
		path = h[i:]
		h = h[:i]
	}
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	return strings.ToLower(strings.Trim(h, "[]")), path
}

func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if _, ipnet, err := net.ParseCIDR(pattern); err == nil {
		ip := net.ParseIP(host)
		return ip != nil && ipnet.Contains(ip)
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
}

func pathMatch(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	path = strings.TrimSpace(path)
	if pattern == "" || path == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	pattern = strings.TrimRight(pattern, "/")
	if pattern == "" {
		// 规则写成 "/" 等价于拒绝所有路径。
		return true
	}
	// 精确命中、作为前缀目录命中，或作为更深层的路径段命中。
	// 因为 pattern 一定以 "/" 开头，后缀匹配天然落在路径段边界上。
	return path == pattern || strings.HasPrefix(path, pattern+"/") || strings.HasSuffix(path, pattern)
}

func patternMatchAny(patterns []string, name string) bool {
	for _, pat := range patterns {
		if patternMatch(pat, name) {
			return true
		}
	}
	return false
}

func patternMatch(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
