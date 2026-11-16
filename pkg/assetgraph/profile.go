package assetgraph

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

// ServiceFact 是端口指纹（pkg/portscan）给出的一条服务事实。
type ServiceFact struct {
	Port    int
	Service string
	Product string
	Version string
	// Confidence 是端口指纹的可信度标签（certain/probable/port/unknown）。
	// 只有 Certain 级事实才允许参与否定证据（见 pkg/gating）。
	Confidence string
}

// TechFact 是 Web 指纹（pkg/webscan）给出的一条技术栈事实。
type TechFact struct {
	Name     string
	RuleID   string
	Category string
	Version  string
	// Confidence 是 Web 指纹的可信度标签（certain/probable/port/unknown）。
	Confidence string
}

// HitFact 是指纹 PoC（pkg/fingerprint）给出的一条命中事实。
type HitFact struct {
	ID   string
	Name string
	// Tags 是指纹 PoC 的标签，已按逗号拆开；空标签与 "fingerprint" 由画像侧丢弃。
	Tags []string
}

// TargetProfile 是单个目标的资产画像：把三套指纹源的事实收敛到一处。
//
// 三源各自有各自的键（端口按 host、Web 按站点、指纹 PoC 按目标），画像负责把
// 「同一目标看到的全部事实」汇总成一份可查询视图，作为 requires 门控与后续
// 适用性决策的唯一口径（取代引擎里散落的 fingerRequiresByKey / fingerTagsByKey）。
type TargetProfile struct {
	// Target 是画像对应的目标标识，与门控查表口径一致（host:port，或 URL 归一后的 host:port/path）。
	Target   string
	Services []ServiceFact
	Web      []TechFact
	Fingers  []HitFact
}

// Profiles 是一次扫描里全部目标的画像集合，按目标标识索引。
//
// 它是三源事实的唯一出口：门控（当前在 engine，P3 迁往 pkg/gating）只通过这里
// 查询"这个目标看到了什么"，不再各自拼装词表。除画像本身外，它把事实推导成两个
// 派生视图，让门控查询为 O(1)：
//   - requires：目标可命中的标识词 → 版本（供 requires 门控）
//   - tags：目标命中的指纹标签（供指纹过滤门控）
//
// 非并发安全：由扫描调度协程单线程写入与查询。
type Profiles struct {
	profiles map[string]*TargetProfile

	built      bool
	requires   map[string]map[string]string
	tags       map[string]map[string]struct{}
	globalTags map[string]struct{}
	// certain 是「高置信识别到」的标识词视图，只服务否定证据：按设计，只有 Certain 级
	// 证据（端口/Web 指纹 certain，或指纹 PoC 命中）才允许产生否定跳过。
	certain map[string]map[string]struct{}
}

// NewProfiles 返回一个空的画像集合。
func NewProfiles() *Profiles {
	return &Profiles{profiles: make(map[string]*TargetProfile)}
}

// profile 返回目标对应的画像，不存在时新建。target 为空则返回 nil。
func (ps *Profiles) profile(target string) *TargetProfile {
	if ps == nil || target == "" {
		return nil
	}
	p, ok := ps.profiles[target]
	if !ok {
		p = &TargetProfile{Target: target}
		ps.profiles[target] = p
	}
	return p
}

// AddService 记入一条端口指纹事实。同一目标可多次调用。
func (ps *Profiles) AddService(target string, f ServiceFact) {
	if p := ps.profile(target); p != nil {
		p.Services = append(p.Services, f)
	}
}

// AddTech 记入一条 Web 技术栈事实。同一目标可多次调用。
func (ps *Profiles) AddTech(target string, f TechFact) {
	if p := ps.profile(target); p != nil {
		p.Web = append(p.Web, f)
	}
}

// AddHit 记入一条指纹 PoC 命中事实。同一目标可多次调用。
func (ps *Profiles) AddHit(target string, f HitFact) {
	if p := ps.profile(target); p != nil {
		p.Fingers = append(p.Fingers, f)
	}
}

// build 把画像事实推导出门控视图，进程内只算一次。
func (ps *Profiles) build() {
	if ps == nil || ps.built {
		return
	}
	ps.built = true
	ps.requires = make(map[string]map[string]string, len(ps.profiles))
	ps.tags = make(map[string]map[string]struct{})
	ps.globalTags = make(map[string]struct{})
	ps.certain = make(map[string]map[string]struct{})
	for target, p := range ps.profiles {
		setToken := func(tok, version string) {
			if tok == "" {
				return
			}
			set := ps.requires[target]
			if set == nil {
				set = make(map[string]string)
				ps.requires[target] = set
			}
			// 已解析出的版本优先，别被后到的空串覆盖（同一标识词可能由多条事实产出）。
			if cur, ok := set[tok]; ok && cur != "" {
				return
			}
			set[tok] = version
		}
		setCertain := func(tok string) {
			if tok == "" {
				return
			}
			set := ps.certain[target]
			if set == nil {
				set = make(map[string]struct{})
				ps.certain[target] = set
			}
			set[tok] = struct{}{}
		}
		for _, s := range p.Services {
			version := strings.TrimSpace(s.Version)
			certain := strings.EqualFold(s.Confidence, "certain")
			for _, tok := range portscan.MatchTokens(s.Service, s.Product) {
				setToken(tok, version)
				if certain {
					setCertain(tok)
				}
			}
		}
		for _, w := range p.Web {
			version := strings.TrimSpace(w.Version)
			certain := strings.EqualFold(w.Confidence, "certain")
			// 与 webscan.MatchTokens 同口径：ruleID / name / category 都作为标识词。
			for _, tok := range portscan.NormTokens(w.RuleID, w.Name, w.Category) {
				setToken(tok, version)
				if certain {
					setCertain(tok)
				}
			}
		}
		for _, f := range p.Fingers {
			// 指纹 PoC 是主动命中，本身即高置信证据。
			if id := strings.ToLower(strings.TrimSpace(f.ID)); id != "" {
				setToken(id, "")
				setCertain(id)
			}
			for _, tag := range normalizeHitTags(f.Tags) {
				setToken(tag, "")
				setCertain(tag)
				ps.globalTags[tag] = struct{}{}
				if ps.tags[target] == nil {
					ps.tags[target] = make(map[string]struct{})
				}
				ps.tags[target][tag] = struct{}{}
			}
		}
	}
}

// normalizeHitTags 归一指纹 PoC 的标签：小写、去空白，丢弃空标签与 "fingerprint"。
func normalizeHitTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || t == "fingerprint" {
			continue
		}
		out = append(out, t)
	}
	return out
}

// Len 返回画像数量。
func (ps *Profiles) Len() int {
	if ps == nil {
		return 0
	}
	return len(ps.profiles)
}

// HasRequires 报告是否存在任何可门控的标识词。
//
// 没有任何标识词时，requires 门控会退回「strict 全跳过 / opportunistic 全放行」的
// 旧行为；据此判断可避免无谓的逐目标查表。
func (ps *Profiles) HasRequires() bool {
	if ps == nil {
		return false
	}
	ps.build()
	return len(ps.requires) > 0
}

// RequiresTokens 返回目标可命中的标识词 → 版本（版本未知记空串）；目标无标识词时返回 nil。
func (ps *Profiles) RequiresTokens(target string) map[string]string {
	if ps == nil {
		return nil
	}
	ps.build()
	return ps.requires[target]
}

// Tags 返回目标命中的指纹标签集合；无标签时返回 nil。
func (ps *Profiles) Tags(target string) map[string]struct{} {
	if ps == nil {
		return nil
	}
	ps.build()
	return ps.tags[target]
}

// CertainTokens 返回目标上「高置信识别到」的标识词集合：端口/Web 指纹为 certain 级，
// 以及指纹 PoC 主动命中。无高置信事实时返回 nil。
//
// 它只服务否定证据（见 pkg/gating）：按设计，只有 Certain 级证据才允许产生否定跳过，
// probable / port 级的弱判据一律不参与。
func (ps *Profiles) CertainTokens(target string) map[string]struct{} {
	if ps == nil {
		return nil
	}
	ps.build()
	return ps.certain[target]
}

// GlobalTags 返回本次扫描出现过的全部指纹标签，供指纹过滤门控判定 PoC 是否"应用特定"。
func (ps *Profiles) GlobalTags() map[string]struct{} {
	if ps == nil {
		return nil
	}
	ps.build()
	return ps.globalTags
}
