package rulekit

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// 本文件是各提取器共用的「取值校验器」：它们与业务无关，只回答「这段文本是不是
// 真的像一个高价值产物」。放在 rulekit 是为了让新增提取器直接复用，而不必各自
// 抄一份——准确率优先的实现细节（占位值识别、Luhn、身份证校验位 …）只应有一处。

// placeholderHints 是「几乎必然是示例/占位」的子串（小写匹配）。
//
// 文档与示例代码里的密钥几乎都带这些标记，例如 AWS 文档里最经典的
// AKIAIOSFODNN7EXAMPLE。把它们挡在门外，是「宁愿提取不到也不误报」的第一道闸。
var placeholderHints = []string{
	"example", "sample", "placeholder", "changeme", "your_", "your-",
	"xxxx", "dummy", "redacted", "foobar", "abcdef", "1234567890",
}

// IsPlaceholder 判定一个值是否应被丢弃。
func IsPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, h := range placeholderHints {
		if strings.Contains(lv, h) {
			return true
		}
	}
	// 全同字符（aaaa… / 1111…）：既是占位写法，也常常是 Luhn 的漏网之鱼。
	return allSameRune(v)
}

// allSameRune 判定字符串是否由同一个字符重复构成（长度需 >= 4）。
func allSameRune(s string) bool {
	if len(s) < 4 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// PlainSequence 判定字符串是否为逐个递增/递减的连续序列（1234… / 9876…）。
func PlainSequence(s string) bool {
	if len(s) < 4 {
		return false
	}
	diff := int(s[1]) - int(s[0])
	if diff != 1 && diff != -1 {
		return false
	}
	for i := 2; i < len(s); i++ {
		if int(s[i])-int(s[i-1]) != diff {
			return false
		}
	}
	return true
}

// Luhn 校验（银行卡号的核心判据）。
func Luhn(s string) bool {
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// CNIDCard 校验 18 位中国大陆身份证号（GB 11643-1999 的 ISO 7064:1983 MOD 11-2）。
func CNIDCard(s string) bool {
	if len(s) != 18 {
		return false
	}
	weights := [18]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	codes := "10X98765432"
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * weights[i]
	}
	last := s[17]
	if last == 'x' {
		last = 'X'
	}
	return last == codes[sum%11]
}

// JWTValid 校验 JWT：三段点分，前两段能 base64url 解码成 JSON 对象。
//
// 只校验结构而不校验签名——因为目的正是「发现一个已签发但可能泄露的令牌」，
// 签名是否有效不影响它是否是敏感信息。
func JWTValid(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return false
		}
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			return false
		}
	}
	return true
}

// GenericSecret 是「可疑密钥赋值」规则的校验器：先排除占位值，再要求值具备
// 一定的随机性特征（长度足够，或同时含数字与字母），避免把 `password: "admin"`
// 这类可读单词也铺进面板。
func GenericSecret(v string) bool {
	if IsPlaceholder(v) {
		return false
	}
	hasDigit, hasAlpha := false, false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlpha = true
		}
	}
	if len(v) >= 12 {
		return true
	}
	return hasDigit && hasAlpha
}
