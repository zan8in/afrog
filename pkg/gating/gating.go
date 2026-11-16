// Package gating 是 PoC 门控的唯一决策层：给定一份目标资产画像与一条 PoC，
// 回答「跑还是不跑、为什么」。
//
// 它不碰网络、不碰存储、不新增探测能力，只消费 pkg/assetgraph 的画像与 pkg/poc 的
// 适用性声明，因此 CLI / MCP / Web 三端共享同一份决策与归因，逻辑只实现一次。
//
// 决策采用三态模型：
//
//  1. requires 命中画像        -> 跑   (source=requires)
//  2. 存在高置信「否定证据」    -> 跳过 (source=negative)
//  3. 其余（无证据 / 弱证据）   -> 兜底跑 (source=fallback)
//
// 三条不可动摇的规则：
//   - 只有 Certain 级证据才能产生「否定」（见 negative.go）；
//   - 「没识别到」永远不等于「不存在」，画像缺失一律走第 3 态放行；
//   - applies-to 只做减法，永不单独触发「跑」。
package gating

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

// Source 是决策来源，写进归因统计与事件流，让「为什么跳过 / 为什么跑」可追溯。
type Source string

const (
	// SourceRequires 表示 requires 硬依赖命中画像，肯定放行。
	SourceRequires Source = "requires"
	// SourceNegative 表示依据否定证据跳过。
	SourceNegative Source = "negative"
	// SourceFallback 表示无裁剪证据，兜底放行。
	SourceFallback Source = "fallback"
)

// Decision 是对一个 (目标, PoC) 组合的门控决策。
type Decision struct {
	// Run 为 true 表示应当执行；false 表示被门控跳过。
	Run bool
	// Source 是决策来源，见 Source 常量。
	Source Source
	// Reason 是人可读的归因：命中了哪条证据、触发了哪条规则。
	Reason string
}

// Level 是门控档位，从最保守到最激进，决定「允许哪些跳过依据生效」。
//
// 档位只控制「减法」（跳过），不放宽任何「加法」；逐档放开时唯一新增的是否定依据，
// 因此最坏后果只是「该跑的漏跑了没有、不该跳的跳了」这类可回退的裁剪，绝不改变
// 「命中即跑 / 无证据兜底跑」的兜底放行。
type Level string

const (
	// LevelOff 关闭全部门控：requires 硬依赖、指纹过滤、推断式否定一律不生效，
	// 退回「全量 PoC × 目标」的原始行为，是随时可用的回退档。
	LevelOff Level = "off"
	// LevelSafe 只保留既有裁决（requires 硬依赖 + 指纹过滤），不启用新增的推断式否定，
	// 等价于引入本设计前的线上行为。默认档。
	LevelSafe Level = "safe"
	// LevelBalanced 在 safe 之上启用「语言层」推断式否定：站点明确是 PHP/ASP.NET 时，
	// 排除 Java 中间件/框架类 PoC（见 negative.go）。
	LevelBalanced Level = "balanced"
	// LevelAggressive 在 balanced 之上再启用「CMS 家族」推断式否定：明确 WordPress 时
	// 排除 Drupal/Joomla 家族 PoC。更高维度的弱否定留待数据积累后接入。
	LevelAggressive Level = "aggressive"
)

// normalizeLevel 归一档位：空或非法一律归 safe（保守默认，行为等价现状）。
func normalizeLevel(l Level) Level {
	switch Level(strings.ToLower(strings.TrimSpace(string(l)))) {
	case LevelOff:
		return LevelOff
	case LevelBalanced:
		return LevelBalanced
	case LevelAggressive:
		return LevelAggressive
	default:
		return LevelSafe
	}
}

// Options 是决策层的运行开关。
type Options struct {
	// TestMode 为 -T 测试模式：一律放行，不做任何门控。
	TestMode bool
	// Level 是门控档位，见 Level 常量；空值等价 safe。
	Level Level
	// FingerprintFilterMode 是既有的指纹过滤门控档位：strict / opportunistic。
	// 仅在 Level != off 时生效。
	FingerprintFilterMode string
}

// Decide 对一个 (目标, PoC) 组合给出门控决策。
//
// key 是目标的画像键（host:port，或 URL 归一后的 host:port/path），由调用方按各端
// 一致的归一规则算好；netOnly 标记网络型 PoC，网络型 PoC 不做 Web 指纹过滤。
// profiles 为 nil 或键解析失败时一律放行——无画像即无裁剪，符合「没识别到不等于不存在」。
func Decide(key string, p poc.Poc, netOnly bool, profiles *assetgraph.Profiles, opts Options) Decision {
	if opts.TestMode {
		return Decision{Run: true, Source: SourceFallback, Reason: "test mode: no gating"}
	}

	level := normalizeLevel(opts.Level)

	// off 档：门控全关，退回全量扫描，是随时可用的一键回退。
	if level == LevelOff {
		return Decision{Run: true, Source: SourceFallback, Reason: "门控关闭(off): 全量放行"}
	}

	// 状态 1：requires 硬依赖。命中即肯定放行；strict 且未命中即为否定。
	req := evalRequires(key, p, profiles)
	if req.skip {
		return Decision{Run: false, Source: SourceNegative, Reason: req.reason}
	}

	// 既有指纹过滤门控（网络型 PoC 不适用）。
	if !netOnly {
		if reason, skip := evalFingerprintFilter(key, p, profiles, opts.FingerprintFilterMode); skip {
			return Decision{Run: false, Source: SourceNegative, Reason: reason}
		}
	}

	// requires 是正向证据，压过推断式否定：命中即放行。
	if req.run {
		return Decision{Run: true, Source: SourceRequires, Reason: req.reason}
	}

	// 状态 2：推断式否定（applies-to + 互斥矩阵），按档位逐档放开。
	// balanced 起启用「语言层」，aggressive 起追加「CMS 家族」。放在 requires 之后，
	// 确保正向证据优先。
	if level == LevelBalanced || level == LevelAggressive {
		if reason, skip := evalInferredNegative(key, p, profiles, level == LevelAggressive); skip {
			return Decision{Run: false, Source: SourceNegative, Reason: reason}
		}
	}

	// 状态 3：无裁剪证据，兜底放行。
	return Decision{Run: true, Source: SourceFallback, Reason: "no裁剪证据，兜底放行"}
}

// requiresEval 是 requires 门控的评估结果。
//
// run 与 skip 至多其一为真：run 表示命中画像（肯定放行）；skip 表示 strict 模式且未
// 命中（否定）；两者皆假表示「无意见」（无 requires、或 opportunistic 且未命中）。
type requiresEval struct {
	run    bool
	skip   bool
	reason string
}

// evalRequires 评估 requires 硬依赖。
//
// 值为该标识对应的识别版本（未知记空串），供 requires 里的版本约束（如 jquery<3.5）判定：
// 版本未知时放行，避免因为拿不到版本而漏报。
func evalRequires(key string, p poc.Poc, profiles *assetgraph.Profiles) requiresEval {
	if len(p.Info.Requires) == 0 {
		return requiresEval{}
	}
	type requirement struct {
		tech string
		rv   *poc.RequireVersion
	}
	reqs := make([]requirement, 0, len(p.Info.Requires))
	for _, r := range p.Info.Requires {
		tech, rv := poc.ParseRequire(r)
		if tech == "" {
			continue
		}
		reqs = append(reqs, requirement{tech: tech, rv: rv})
	}
	if len(reqs) == 0 {
		return requiresEval{}
	}

	if profiles != nil && key != "" && profiles.HasRequires() {
		tts := profiles.RequiresTokens(key)
		for _, req := range reqs {
			version, ok := tts[req.tech]
			if !ok {
				continue
			}
			if req.rv.Satisfied(version) {
				return requiresEval{run: true, reason: "requires 命中: " + req.tech}
			}
		}
	}

	if normalizeMode(p.Info.RequiresMode) == "opportunistic" {
		return requiresEval{}
	}
	return requiresEval{skip: true, reason: "requires 未命中(strict): " + strings.Join(p.Info.Requires, ",")}
}

// evalFingerprintFilter 评估既有指纹过滤门控：PoC 的 tags 与目标已识别的指纹标签是否匹配。
//
// 只有「应用特定型」PoC（tags 与本次扫描出现过的指纹标签有交集）才参与过滤，避免把
// generic 的 PoC（tags 只有 rce/cve 这类）误伤。
func evalFingerprintFilter(key string, p poc.Poc, profiles *assetgraph.Profiles, mode string) (string, bool) {
	if profiles == nil {
		return "", false
	}
	globalTags := profiles.GlobalTags()
	if len(globalTags) == 0 {
		return "", false
	}
	pocTags := normalizeTags(p.Info.Tags)
	if len(pocTags) == 0 {
		return "", false
	}
	appSpecific := false
	for t := range pocTags {
		if _, ok := globalTags[t]; ok {
			appSpecific = true
			break
		}
	}
	if !appSpecific {
		return "", false
	}
	if key == "" {
		return "", false
	}
	targetTags := profiles.Tags(key)
	if len(targetTags) == 0 {
		if normalizeMode(mode) == "strict" {
			return "指纹过滤: 目标未命中任何指纹标签", true
		}
		return "", false
	}
	for t := range pocTags {
		if _, ok := targetTags[t]; ok {
			return "", false
		}
	}
	return "指纹过滤: 目标指纹标签与 PoC 标签不匹配", true
}

// normalizeTags 把 PoC 的 tags 字符串拆成小写标签集合，丢弃空项与 "fingerprint"
// （指纹类是通用标签，不构成「应用特定」的依据）。
func normalizeTags(tags string) map[string]struct{} {
	tags = strings.TrimSpace(tags)
	if tags == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, t := range strings.Split(strings.ToLower(tags), ",") {
		tt := strings.TrimSpace(t)
		if tt == "" || tt == "fingerprint" {
			continue
		}
		out[tt] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeMode 归一档位：空或非法一律归 strict（保守）。
func normalizeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "strict" && mode != "opportunistic" {
		return "strict"
	}
	return mode
}
