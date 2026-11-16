package poc

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// RequireVersion 是一条 requires 上的版本约束，即 jquery<3.5 里的「<3.5」。
//
// requires 原本只是「技术标识」的精确匹配；加上版本约束后，门控可以在
// 「识别到这个产品」的基础上再收敛到「识别到的版本落在受影响区间」，让 PoC 作者能表达
// `requires: [jquery<3.5]` 这类只在旧版本才成立的依赖。
type RequireVersion struct {
	Tech  string // 归一化（小写、去首尾空白）后的技术标识
	Op    string // 比较符：< <= > >= ==
	Value string // 期望版本，如 3.5
}

// requireOperators 是支持的比较符。长的排在前面，确保 <= 先于 < 被匹配。
var requireOperators = []string{"<=", ">=", "==", "<", ">", "="}

// ParseRequire 把一条 requires 词条拆成「技术标识 + 可选版本约束」。
//
// 支持 jquery<3.5、thinkphp>=6.0、nginx<=1.24 这类写法；不含比较符时返回 (词条, nil)，
// 与加入版本约束之前的行为完全一致。技术标识统一小写、去首尾空白，比较符前后允许空格
// （jquery < 3.5 与 jquery<3.5 等价）。
func ParseRequire(entry string) (string, *RequireVersion) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return "", nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '<' && s[i] != '>' && s[i] != '=' {
			continue
		}
		rest := s[i:]
		var op string
		for _, cand := range requireOperators {
			if strings.HasPrefix(rest, cand) {
				op = cand
				break
			}
		}
		if op == "" {
			continue
		}
		tech := strings.ToLower(strings.TrimSpace(s[:i]))
		value := strings.TrimSpace(rest[len(op):])
		if tech == "" || value == "" {
			// 形状不合法（如只有比较符、没有版本号）：退回无条件约束，保持旧行为。
			return strings.ToLower(s), nil
		}
		if op == "=" {
			op = "=="
		}
		return tech, &RequireVersion{Tech: tech, Op: op, Value: value}
	}
	return strings.ToLower(s), nil
}

// Satisfied 判断「识别到该技术、版本为 version」是否满足这条版本约束。
//
// version 为空（命中产品但没解析出具体版本）时返回 true：产品已经对上号，只是版本无从
// 判定，此时放行以免漏报——门控的目的是把 PoC 收敛到正确的产品/版本，而不是否认已有证据。
// 调用方需先自行确认技术标识本身已命中。
func (r *RequireVersion) Satisfied(version string) bool {
	if r == nil {
		return true
	}
	if strings.TrimSpace(version) == "" {
		return true
	}
	return utils.Compare(version, r.Op, r.Value)
}
