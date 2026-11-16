package gating

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

// mutexExcludes 是「高置信否定」的显式互斥表：键是画像里被 Certain 级证据识别到的
// 标识词（如 php、wordpress），值是被它明确排除的 applies-to 标识词（如 weblogic、drupal）。
//
// 纪律：
//   - 白名单式显式声明，不做「同类自动互斥」的泛化推理——技术名会随 PoC 库增长，
//     泛化推理必错，显式表可控可解释；
//   - 每条规则都能回答「为什么可以排除」，命中时以 Evidence 形式写进 Decision.Reason；
//   - 只有 Certain 级证据才参与（见 evalInferredNegative）——probable / port 一律不否定。
//
// 表按档位分两级接入：语言层随 balanced 起生效，CMS 家族随 aggressive 起生效。
// 更弱的维度（Web 服务器、端口/服务）需要更强的前提，留待数据积累后再接入。

// mutexExcludes 是语言层互斥（balanced 档起生效）：站点明确是 PHP / ASP.NET 时，
// 排除 Java 中间件与框架类 PoC。一个站点在同一主机上不可能既是 PHP 又是
// weblogic/tomcat 这类 Java 应用，因此这条否定最稳。
var mutexExcludes = map[string][]string{
	"php":     {"weblogic", "struts", "spring", "shiro", "apache-shiro", "tomcat", "jenkins", "nacos", "solr"},
	"asp.net": {"weblogic", "struts", "spring", "shiro", "apache-shiro", "tomcat", "jenkins", "nacos", "solr"},
	"asp":     {"weblogic", "struts", "spring", "shiro", "apache-shiro", "tomcat", "jenkins"},
}

// mutexExcludesExtended 是 CMS 家族互斥（aggressive 档起生效）：明确 WordPress / Drupal /
// Joomla 时，排除同为一站式 CMS 的其它家族。相比语言层略弱（同主机理论上可挂两个 CMS），
// 因此放在更高的档位。
var mutexExcludesExtended = map[string][]string{
	"wordpress": {"drupal", "joomla"},
	"drupal":    {"wordpress", "joomla"},
	"joomla":    {"wordpress", "drupal"},
}

// evalInferredNegative 判断 PoC 的软适用性（applies-to）是否被画像里的高置信否定证据排除。
//
// 规则：
//   - 只在画像存在 Certain 级标识词、且 PoC 声明了 applies-to 时才有资格产生否定；
//   - applies-to 只做减法，永不参与肯定放行；
//   - 命中互斥表任一「特定 → 排除」对即跳过；
//   - extended 为真时（aggressive 档）在语言层之外追加 CMS 家族互斥。
func evalInferredNegative(key string, p poc.Poc, profiles *assetgraph.Profiles, extended bool) (string, bool) {
	if profiles == nil || key == "" || len(p.Info.AppliesTo) == 0 {
		return "", false
	}
	certain := profiles.CertainTokens(key)
	if len(certain) == 0 {
		return "", false
	}
	applies := make(map[string]struct{}, len(p.Info.AppliesTo))
	for _, a := range p.Info.AppliesTo {
		applies[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}

	tables := []map[string][]string{mutexExcludes}
	if extended {
		tables = append(tables, mutexExcludesExtended)
	}
	for _, table := range tables {
		for tok := range certain {
			excludes, ok := table[tok]
			if !ok {
				continue
			}
			for _, ex := range excludes {
				if _, hit := applies[ex]; hit {
					return "互斥否定: 画像高置信识别为 " + tok + "，排除 " + ex, true
				}
			}
		}
	}
	return "", false
}
