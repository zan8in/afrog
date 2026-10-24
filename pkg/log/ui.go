package log

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// 统一 UI 基元层。
//
// 所有面向用户的扫描输出都从这里渲染，业务代码不再自行拼装转义字符、分隔符或括号。
// 视觉语言参考 nuclei，整屏只有两类行，靠「首列」和「分隔语言」区分：
//
//	结果行  序号 [徽标] 目标 [属性] · [属性]      端口 / Web / 漏洞共用
//	运维行  [LEV] 阶段 事实 · 事实
//
// 两类行都从第 0 列起排，token 之间一律单个空格——不做定宽补齐，也不留占位缩进，
// 避免出现「为了对齐而存在的空白」；可观感上的整齐交给方括号与 ` · ` 这类结构符号。
//
// 结果行的元数据一律用方括号圈出，目标永远裸奔——与 nuclei 的
// `[template-id] [protocol] host` 同一口径，也便于 `grep -o '\[[^]]*\]'` 抽取。
// 运维行不参与方括号语言，只用 ` · ` 连接事实，这样日志与结果不会互相误认。
//
// 徽标 / 级别标签承载类别与严重度色；结果行的「主值」（服务名、站点标题、PoC ID）
// 用低饱和的绿色强调，目标保持中性，其余属性统一暗灰。
// 序号固定 3 位（afrog 的历史特征），便于口头引用，也让「最后一行的序号＝该阶段结果数」。
// -no-color / -silent 时 LogColor 全部返回原文，颜色自动消失，不会留下半截转义。

// 运维日志级别标签。
const (
	LevelInfo = "INF"
	LevelWarn = "WRN"
	LevelErr  = "ERR"
)

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Dim 把次要文本渲染为暗灰；无颜色时原样返回。
func Dim(s string) string { return LogColor.DarkGray(s) }

// Facts 用 ` · ` 连接若干属性，跳过空项（含只由 ANSI 转义构成的项）。运维行使用。
func Facts(items ...string) string {
	return strings.Join(keptFacts(items...), LogColor.DarkGray(" · "))
}

// Attrs 把若干已渲染好的片段各自圈上暗灰方括号再用 ` · ` 连接，供结果行使用。
//
// 方括号的作用是把「元数据」与「目标」切开：目标永远不加括号（nuclei 同款），
// 所以只要看到方括号就知道那是描述目标的属性，而不是目标本身。
func Attrs(items ...string) string {
	kept := keptFacts(items...)
	bracketed := make([]string, 0, len(kept))
	for _, it := range kept {
		bracketed = append(bracketed, LogColor.DarkGray("[")+it+LogColor.DarkGray("]"))
	}
	return strings.Join(bracketed, LogColor.DarkGray(" · "))
}

func keptFacts(items ...string) []string {
	kept := make([]string, 0, len(items))
	for _, it := range items {
		if hasVisibleText(it) {
			kept = append(kept, it)
		}
	}
	return kept
}

func hasVisibleText(s string) bool {
	return strings.TrimSpace(ansiPattern.ReplaceAllString(s, "")) != ""
}

// Op 渲染一条运维/阶段日志：`[LEV] 阶段 事实 · 事实`。
//
// 运维行的事实都是元数据，统一降为暗灰；调用方传纯文本即可，已有的转义序列会被剥离，
// 避免出现叠加的多层颜色。与结果行一样从第 0 列起排，不做缩进补齐。
func Op(level, stage string, facts ...string) string {
	clean := make([]string, 0, len(facts))
	for _, f := range facts {
		clean = append(clean, LogColor.DarkGray(ansiPattern.ReplaceAllString(f, "")))
	}
	line := levelTag(level) + " " + stage
	if f := Facts(clean...); f != "" {
		line += " " + f
	}
	return line
}

// Res 渲染一条结果行：`[徽标] 目标 [属性] · [属性]`。
// badge 已含语义与颜色，target 保持中性（不加括号），attrs 为已渲染好的片段（可为空）。
func Res(badge, target string, attrs ...string) string {
	line := badge + " " + target
	if a := Attrs(attrs...); a != "" {
		line += " " + a
	}
	return line
}

// Index 渲染结果行的序号前缀，固定 3 位零填充（001）。超过 999 条时自然变宽，
// 不做截断——到这个量级还硬凑对齐只会误导读者。
func Index(n int) string {
	return LogColor.DarkGray(fmt.Sprintf("%03d", n))
}

// ResNum 渲染带序号的结果行：`序号 [徽标] 目标 [属性] · [属性]`。
//
// 序号是「这是本轮第几条结果」，不表示先后与优先级（并发下到达顺序本就随机），
// 它的用处是让人立刻知道该阶段累积了多少条，并能稳定引用（"第 3 条"）。
// 端口 / Web / 漏洞各自独立编号，靠徽标（[open] / [web] / [严重度]）消歧。
// n <= 0 时退化为不带序号的普通结果行。
func ResNum(n int, badge, target string, attrs ...string) string {
	if n <= 0 {
		return Res(badge, target, attrs...)
	}
	return Index(n) + " " + Res(badge, target, attrs...)
}

func levelTag(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case LevelWarn:
		return LogColor.Midium("[" + LevelWarn + "]")
	case LevelErr:
		return LogColor.Red("[" + LevelErr + "]")
	default:
		return LogColor.Info("[" + LevelInfo + "]")
	}
}

// badge 给文本套上暗灰方括号，并让内文着色，括号本身不抢色。
func badge(text string, colorFn func(a ...any) string) string {
	return LogColor.DarkGray("[") + colorFn(text) + LogColor.DarkGray("]")
}

// SeverityBadge 返回按严重度着色的结果徽标（如 `[critical]`）。
// 空值/未知严重度按 info 处理。不做定宽补齐：整行 token 之间一律单个空格。
func SeverityBadge(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "" {
		s = "info"
	}
	switch utils.SeverityMap[s] {
	case utils.CRITICAL:
		return badge(s, LogColor.Critical)
	case utils.HIGH:
		return badge(s, LogColor.High)
	case utils.MEDIUM:
		return badge(s, LogColor.Midium)
	case utils.LOW:
		return badge(s, LogColor.Low)
	default:
		return badge(s, LogColor.Info)
	}
}

// KindBadge 返回固定语义徽标：端口开放（open）/ Web 资产（web）。
func KindBadge(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "open":
		return badge("open", LogColor.Green)
	case "web":
		return badge("web", LogColor.Info)
	default:
		return badge(kind, LogColor.DarkGray)
	}
}
