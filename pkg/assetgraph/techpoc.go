package assetgraph

import (
	"sort"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// maxCandidatesPerTech 限制单个技术栈挂出的候选 PoC 数量。
//
// 候选是给人/Agent 缩小范围用的，不是穷举清单；挂几十条上去只会把图变成噪声源。
const maxCandidatesPerTech = 20

// TechRef 是参与候选关联的一条技术栈事实。
type TechRef struct {
	Name     string
	RuleID   string
	Category string
	// Version 是识别到的版本（可能为空）。带版本时，候选 PoC 的 requires 版本约束
	// （如 jquery<3.5）会据此过滤：识别到的版本不落在受影响区间就不挂候选。
	Version string
}

// techCandidate 是索引里的一条「候选 PoC + 其版本约束」。
//
// ID 之外单独存版本约束：requires 的索引键只取技术标识（jquery），但候选是否成立
// 还要看版本（jquery<3.5）——把约束带到检索期才能做版本级过滤。
type techCandidate struct {
	ID      string
	Version *poc.RequireVersion
}

var (
	requiresOnce  sync.Once
	requiresIndex map[string][]techCandidate
)

// requiresIndexByTech 用 PoC 的 info.requires 建「技术标识 → PoC」索引。
//
// 不另造模糊匹配：requires 本来就是扫描器的准入条件（`requires: [thinkphp]` 表示
// 只有识别到 ThinkPHP 才会跑），拿它做候选关系与真正的执行口径完全同源。
// 索引进程内只建一次——PoC 元信息要从磁盘读几千个 YAML，不能按 URL 重复付这笔钱。
func requiresIndexByTech() map[string][]techCandidate {
	requiresOnce.Do(func() {
		items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"})
		if err != nil {
			requiresIndex = map[string][]techCandidate{}
			return
		}
		idx := make(map[string][]techCandidate, len(items))
		seen := make(map[string]map[string]struct{}, len(items))
		for _, it := range items {
			id := strings.TrimSpace(it.ID)
			if id == "" {
				continue
			}
			for _, r := range it.Requires {
				// requires 词条可能是带版本约束的（jquery<3.5）：索引键只取技术标识，
				// 版本约束随候选一起保存，留给检索期按识别到的版本过滤。
				tech, rv := poc.ParseRequire(r)
				key := normalizeTechKey(tech)
				if key == "" {
					continue
				}
				if seen[key] == nil {
					seen[key] = make(map[string]struct{})
				}
				if _, ok := seen[key][id]; ok {
					continue
				}
				seen[key][id] = struct{}{}
				idx[key] = append(idx[key], techCandidate{ID: id, Version: rv})
			}
		}
		for k, cands := range idx {
			sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
			if len(cands) > maxCandidatesPerTech {
				cands = cands[:maxCandidatesPerTech]
			}
			idx[k] = cands
		}
		requiresIndex = idx
	})
	return requiresIndex
}

// normalizeTechKey 把技术标识归一化成索引键：小写、折叠空白。
func normalizeTechKey(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// techKeys 返回一条技术栈可能被 requires 引用的全部标识。
//
// 三种写法都要试：规则 id（ajp-protocol-detect）、完整名字（ThinkPHP 6）、
// 首个词（ThinkPHP）。少试一种就会漏掉一整类 PoC。
func techKeys(t TechRef) []string {
	keys := make([]string, 0, 3)
	add := func(v string) {
		k := normalizeTechKey(v)
		if k == "" {
			return
		}
		for _, existing := range keys {
			if existing == k {
				return
			}
		}
		keys = append(keys, k)
	}
	add(t.RuleID)
	add(t.Name)
	if fields := strings.Fields(t.Name); len(fields) > 0 {
		add(fields[0])
	}
	return keys
}

// candidatesFor 按索引算出某个技术栈的候选 PoC id（已排序、已截断）。
//
// WAF/CDN 不参与：它们是站点前面的拦截层，不是可被 PoC 验证的产品。
// 带版本约束的候选（jquery<3.5）按识别到的版本过滤：版本已知且不满足就剔除，
// 版本未知时保留——识别到产品、版本无从判定，不该因此丢掉候选。
func candidatesFor(index map[string][]techCandidate, t TechRef) []string {
	if isFrontLayer(t.Category) {
		return nil
	}
	set := make(map[string]struct{})
	for _, key := range techKeys(t) {
		for _, cand := range index[key] {
			if cand.Version != nil && !cand.Version.Satisfied(t.Version) {
				continue
			}
			set[cand.ID] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxCandidatesPerTech {
		out = out[:maxCandidatesPerTech]
	}
	return out
}

func isFrontLayer(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "waf", "cdn":
		return true
	}
	return false
}

// LinkTechCandidates 把一次识别到的技术栈落成图上的推导边。
//
// 端点 → 技术栈（tech）是观测事实，技术栈 → 候选 PoC（candidate）来自
// info.requires。只写边不写资产行：这两类节点不该计入「资产总数」。
func LinkTechCandidates(endpoint string, techs []TechRef) error {
	if strings.TrimSpace(endpoint) == "" || len(techs) == 0 {
		return nil
	}
	index := requiresIndexByTech()
	names := make([]string, 0, len(techs))
	candidates := make(map[string][]string, len(techs))
	for _, t := range techs {
		name := strings.TrimSpace(t.Name)
		if name == "" || isFrontLayer(t.Category) {
			continue
		}
		// 技术栈本身也要入图：即便暂时没有候选 PoC，它也是推理链上的一环。
		names = append(names, name)
		if ids := candidatesFor(index, t); len(ids) > 0 {
			candidates[name] = ids
		}
	}
	if len(names) == 0 {
		return nil
	}
	return sqlite.EnsureTechGraph(endpoint, names, candidates)
}
