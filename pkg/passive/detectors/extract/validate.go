package extract

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

// 本文件是「银行卡号」专属的判定逻辑。通用校验器（占位值 / Luhn / 身份证 / JWT /
// 通用密钥）已迁到 rulekit；这里只保留卡号特有的发卡行白名单与语境佐证——
// 它们与卡号这一具体业务绑定，不属于通用能力。

// bankCardValid 校验银行卡号：13–19 位、通过 Luhn、落在发卡行 BIN 号段内，
// 且不是连续序列 / 身份证号之类的数字噪声。
func bankCardValid(s string) bool {
	digits := stripGrouping(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	if rulekit.PlainSequence(digits) {
		return false
	}
	// 一个 18 位、能通过身份证校验位的字符串是身份证而不是银行卡。
	if len(digits) == 18 && rulekit.CNIDCard(digits) {
		return false
	}
	if !bankCardIssuer(digits) {
		return false
	}
	return rulekit.Luhn(digits)
}

// stripGrouping 去掉印刷体卡号里的空格与连字符，还原成纯数字。
func stripGrouping(s string) string {
	if !strings.ContainsAny(s, " -") {
		return s
	}
	return strings.NewReplacer(" ", "", "-", "").Replace(s)
}

// bankCardIssuer 用发卡行识别号（IIN/BIN）白名单收口。
//
// 这是 gitleaks / trufflehog 等成熟扫描器的通行做法：卡号前缀由支付网络统一分配，
// 只在固定号段内出现。加这一层之后，Luhn 那 1/10 的偶然通过率不再是漏网的理由——
// 一个业务编号要同时「满足 Luhn」且「落在真实 BIN 号段」，概率低到可以忽略。
func bankCardIssuer(s string) bool {
	n := len(s)
	switch {
	case strings.HasPrefix(s, "4"): // Visa：13 / 16 / 19 位
		return n == 13 || n == 16 || n == 19
	case numPrefixIn(s, 2, 51, 55): // Mastercard 5 系
		return n == 16
	case numPrefixIn(s, 4, 2221, 2720): // Mastercard 2 系
		return n == 16
	case strings.HasPrefix(s, "34"), strings.HasPrefix(s, "37"): // American Express
		return n == 15
	case strings.HasPrefix(s, "6011"), strings.HasPrefix(s, "65"), numPrefixIn(s, 3, 644, 649): // Discover
		return n == 16 || n == 19
	case numPrefixIn(s, 4, 3528, 3589): // JCB
		return n >= 16 && n <= 19
	case numPrefixIn(s, 3, 300, 305), strings.HasPrefix(s, "36"),
		strings.HasPrefix(s, "38"), strings.HasPrefix(s, "39"): // Diners Club
		return n == 14 || n == 16 || n == 19
	case strings.HasPrefix(s, "62"): // UnionPay
		return n >= 16 && n <= 19
	}
	return false
}

// numPrefixIn 判断 s 的前 digits 位数字是否落在闭区间 [lo, hi] 内。
func numPrefixIn(s string, digits, lo, hi int) bool {
	if len(s) < digits {
		return false
	}
	n, err := strconv.Atoi(s[:digits])
	if err != nil {
		return false
	}
	return n >= lo && n <= hi
}

// bankContextWords 是银行卡语境的佐证词（全小写，中文原样）。
//
// 刻意不收 pan：它作为子串会命中 company / japan / panel 等大量无关词。
// creditcard / debitcard 是为 camelCase 字段名（creditCard / debitCard）准备的：
// 它们里的 card 前面是字母，单靠 card 一词（要求前界非字母数字）会被漏掉。
var bankContextWords = []string{"card", "creditcard", "debitcard", "ccnum", "bankcard", "卡号", "银行卡", "信用卡", "储蓄卡"}

// bankCardContext 实现 rulekit.Rule.Context。
//
// 印刷体卡号（带空格/连字符分组）自带书写信号，直接放行；裸数字串则要求近旁出现
// 卡片语境词——否则任何 16–19 位、恰巧满足 Luhn 的雪花 ID 都会被当成卡号（实测
// traceId / faviconId / id 这类字段在真实 JSON 响应里天天命中）。
func bankCardContext(content []byte, start, end int) bool {
	if hasGrouping(content[start:end]) {
		return true
	}
	return nearbyAny(content, start, end, bankContextWords)
}

// hasGrouping 判断一段命中是否自带分组分隔符（空格或连字符）。
func hasGrouping(m []byte) bool {
	for _, c := range m {
		if c == ' ' || c == '-' {
			return true
		}
	}
	return false
}

// nearbyAny 判断命中值近旁（前后各 contextPad 字节）是否出现任一语境词。
//
// 语境词要求「前界不是字母/数字」：这样 card 能命中 cardNo / card_number / cardHolder，
// 却不会命中 discard / postcard 这类把 card 当后缀的无关单词，否则闸门形同虚设。
func nearbyAny(content []byte, start, end int, words []string) bool {
	const contextPad = 64
	// 多取左边界 1 字节，保证 at==0 只可能是「真的在内容开头」，而不是被窗口截断。
	from := start - contextPad - 1
	if from < 0 {
		from = 0
	}
	to := end + contextPad
	if to > len(content) {
		to = len(content)
	}
	window := bytes.ToLower(content[from:to])
	for _, w := range words {
		needle := []byte(w)
		for idx := 0; ; {
			i := bytes.Index(window[idx:], needle)
			if i < 0 {
				break
			}
			at := idx + i
			if at == 0 || !isWordByte(window[at-1]) {
				return true
			}
			idx = at + 1
		}
	}
	return false
}

// isWordByte 判定字节是否属于「词内字符」。中文等多字节字符的首字节 >= 0x80，
// 不在此列，因此「银行卡号」里的「卡号」不会被误判成需要前界。
func isWordByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return false
}

// secretAssignmentKeywords 是「可疑的密钥赋值」的键名关键字（小写）。
// 用于识别「值本身就是键名/变量名」的自引用误报，例如 `password: password123`。
var secretAssignmentKeywords = []string{
	"password", "passwd", "pwd", "passphrase",
	"secret", "apikey", "api_key", "accesskey", "access_key",
	"privatekey", "private_key", "clientsecret", "client_secret",
	"token",
}

// looseSecret 是「可疑的密钥赋值」专用校验：在通用强度门槛之上，再剔除「值其实是
// 一段代码引用，而不是字面量」的高频误报。
//
// 该规则没有固定前缀，只靠「键名像密钥 + 值像密钥」推断，因此在 JS bundle / 前端源码
// 里极易把成员表达式当成密钥：
//
//	password: this.formData.passwordSj
//	password: Object.assign({}, i)
//	apiKey:   process.env.API_KEY
//
// 字面量密钥的字符集（base64 / hex / 前缀式）都不含点号，JWT 另有独立规则识别，
// 因此含点号的一律判为代码引用；值里再出现键名关键字的，判为自引用或变量命名。
func looseSecret(v string) bool {
	if !rulekit.GenericSecret(v) {
		return false
	}
	if strings.Contains(v, ".") {
		return false
	}
	lv := strings.ToLower(v)
	for _, kw := range secretAssignmentKeywords {
		if strings.Contains(lv, kw) {
			return false
		}
	}
	return true
}
