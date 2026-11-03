package passive

import "strings"

// Scope 是「哪些流量该被扫描」的裁剪规则。
//
// 被动扫描挂在真实业务流量上，一次浏览会话会碰到大量与目标无关的第三方域名
// （统计、地图、CDN）以及不该被重放的敏感路径（登录、支付、注销）。这些流量若
// 放行到调度层，每条都要付一次昂贵的重放：既无价值，又可能带来副作用。
// 在代理层把它们裁掉，是从源头省流量的第一道闸。
//
// 匹配规则（HostDeny / HostAllow / PathDeny 共用）：
//   - 含 `*` 时按通配匹配，`*` 可匹配任意字符（含 `/`）；
//   - 不含 `*` 时按「包含」匹配；
//   - 一律不区分大小写。
//
// 之所以对「不含 `*`」采用包含而非精确匹配，是为了贴合直觉：写 `logout` 就能排除
// 所有含 logout 的路径，写 `example.com` 也能覆盖 `www.example.com`。
type Scope struct {
	// HostAllow 是扫描范围白名单：非空时，只有匹配的 Host 才会被扫描。
	HostAllow []string
	// HostDeny 是永不扫描的 Host，优先级高于 HostAllow。
	HostDeny []string
	// PathDeny 是永不扫描的路径。
	PathDeny []string
}

// Empty 报告该 Scope 是否不做任何裁剪。
//
// 全空时所有匹配函数都直接放行，调用方可据此跳过判断。
func (s Scope) Empty() bool {
	return len(s.HostAllow) == 0 && len(s.HostDeny) == 0 && len(s.PathDeny) == 0
}

// AllowsHost 报告某个 Host 是否在扫描范围内。
//
// 空 Host 一律放行：拿不到主机名时不该误伤，交给后续环节给出更准确的结论。
func (s Scope) AllowsHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return true
	}
	for _, p := range s.HostDeny {
		if matchScope(p, h) {
			return false
		}
	}
	if len(s.HostAllow) == 0 {
		return true
	}
	for _, p := range s.HostAllow {
		if matchScope(p, h) {
			return true
		}
	}
	return false
}

// AllowsPath 报告某个路径是否在扫描范围内。
func (s Scope) AllowsPath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return true
	}
	for _, pat := range s.PathDeny {
		if matchScope(pat, p) {
			return false
		}
	}
	return true
}

// matchScope 按 Scope 的规则判断 s 是否命中 pattern。
//
// 空 pattern 视为不命中：配置里的空行不该变成「排除一切」。
func matchScope(pattern, s string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	if pat == "" || s == "" {
		return false
	}
	if !strings.Contains(pat, "*") {
		return strings.Contains(s, pat)
	}

	// 含通配：按顺序匹配各固定片段。首片段必须落在开头（除非模式以 * 起头），
	// 末片段必须贴住结尾（除非模式以 * 收尾），中间片段只需按序出现。
	parts := strings.Split(pat, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		j := strings.Index(s[pos:], part)
		if j < 0 {
			return false
		}
		if i == 0 && j != 0 {
			return false
		}
		pos += j + len(part)
	}
	if !strings.HasSuffix(pat, "*") {
		last := parts[len(parts)-1]
		if last != "" && !strings.HasSuffix(s, last) {
			return false
		}
	}
	return true
}
