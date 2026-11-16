package poc

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

// appliesToNonTechWords 是「不是技术标识」的词表：漏洞类别、验证/利用方式、元信息与泛化角色词。
//
// applies-to 只在「出现反面证据才跳过」这一态参与判断，因此它只该装技术标识
// （weblogic、redis、thinkphp）：rce/sqli 这类漏洞类别既不会被任何指纹识别到，
// 拿它做否定判断也没有意义。
//
// 用黑名单而不是白名单：技术名会随 PoC 库增长，白名单必漏新出现的产品；黑名单只挡掉
// 已知的「非技术」词，漏网的至多是少量泛化词，而 applies-to 只做减法（P3 只在显式互斥
// 规则下才跳过），代价可控。
const appliesToNonTechWords = `
cve cnvd edb kev packetstorm poc vuln vulnerability exploit verify detect fingerprint tech oast intrusive enum
rce remote-code-execution code-execution command-execution command-injection cmd-injection
sqli sql sql-injection sqlinject injection xss csrf ssrf xxe ssti lfi rfi
fileread file-read readfile read-file filedownload file-download download
fileupload file-upload upload filewrite file-write filedelete file-delete
traversal directory-traversal path-traversal arbitrary-file-read arbitrary-file-upload
deserialization deserialize jndi ldap bypass auth-bypass unauthorized unauth
weak-login default-login default-password defaultpassword login brute-force bruteforce
dos redirect open-redirect crlf
disclosure info-leak info-leakage information-disclosure leak leak-password password password-disclosure
credential credentials exposure exposed sensitive misconfig debug backdoor webshell shell getshell
web http https httpd server service app api config configuration file files
db database oa erp crm cms panel router firewall vpn nas dvr iot network
cloud mobile admin user guest remote code execution arbitrary information data
console default test demo system sec security scanner scan tool
`

var appliesToNonTechTags = func() map[string]struct{} {
	m := make(map[string]struct{}, 128)
	for _, w := range strings.Fields(appliesToNonTechWords) {
		m[w] = struct{}{}
	}
	return m
}()

// cveLikeTokenRe 匹配 cve/cnvd/edb 加上可选年份的纯编号标签（cve、cve2024、cnvd2021）。
var cveLikeTokenRe = regexp.MustCompile(`^(cve|cnvd|edb)\d*$`)

// InferAppliesTo 依据 PoC 的软信号推断 applies-to：tags、PoC 文件名、info.name。
//
// 三处信号按可信度递减取用：tags 是作者核定的技术标签，最可信；文件名首段是产品/厂商线索；
// info.name 是自由叙述，噪声最大，只有在前面都拿不到标识时才兜底。
// 返回值统一走 portscan.NormTokens 归一，与 requires 门控共用同一份口径，
// 保证推断出的标识一定能和指纹识别结果对上号。
//
// 这是纯推断（软证据），调用方不得据此做「肯定放行」——按设计纪律，applies-to 只做减法。
func InferAppliesTo(pocPath string, info Info) []string {
	cands := make([]string, 0, 8)
	cands = append(cands, techTags(info.Tags)...)
	if tok := leadingAppliesToken(fileStem(pocPath)); tok != "" {
		cands = append(cands, tok)
	}
	if len(cands) == 0 {
		if tok := leadingAppliesToken(info.Name); tok != "" {
			cands = append(cands, tok)
		}
	}
	return portscan.NormTokens(cands...)
}

// FillAppliesTo 在 Info 未显式声明 applies-to 时，用软信号推断补齐。加载期调用一次即可。
//
// 显式声明优先：PoC 作者写下的 applies-to 是人工判断，比推断可信，推断只做兜底。
func (i *Info) FillAppliesTo(pocPath string) {
	if i == nil || len(i.AppliesTo) > 0 {
		return
	}
	i.AppliesTo = InferAppliesTo(pocPath, *i)
}

// techTags 把逗号分隔的 tags 拆开，留下技术标识，丢掉漏洞类别/元信息。
func techTags(tags string) []string {
	out := make([]string, 0, 4)
	for _, raw := range strings.Split(tags, ",") {
		t := strings.ToLower(strings.TrimSpace(raw))
		if isNonTechToken(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// leadingAppliesToken 取文件名/名称的第一段作为技术标识候选。
//
// 只取第一段：afrog PoC 的命名习惯是「产品-漏洞类别」（weblogic-weak-login、thinkphp-detect），
// 第一段即产品/厂商；把后续词一并收进来会把 remotestreaming、anyfileread 这类描述词
// 当成技术名，噪声远大于收益。
func leadingAppliesToken(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' ' || r == '\t'
	})
	if len(fields) == 0 {
		return ""
	}
	first := strings.ToLower(fields[0])
	if isNonTechToken(first) {
		return ""
	}
	return first
}

// fileStem 取路径的文件名并去掉扩展名（weblogic-weak-login.yaml -> weblogic-weak-login）。
func fileStem(p string) string {
	base := filepath.Base(strings.TrimSpace(p))
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

// isNonTechToken 判断一个词是否不可能是技术标识。
func isNonTechToken(t string) bool {
	if len(t) < 2 {
		return true
	}
	if _, ok := appliesToNonTechTags[t]; ok {
		return true
	}
	if cveLikeTokenRe.MatchString(t) {
		return true
	}
	return isAllDigits(t)
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}
