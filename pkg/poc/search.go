package poc

import "strings"

// SplitSearchKeywords 把逗号分隔的检索词拆成非空、小写、去空白的关键词切片。
//
// afrog -s、afrog -p（列表）、poc.search（MCP / Web）三端检索共用这一份拆分口径：
// 逗号分隔即多关键词 OR，空词丢弃。三端各自实现会让同一个关键词在不同入口命中不同
// 结果（曾出现过 "a,b" 被当整串字面量、poc.search 返回 0 而扫描却命中一堆的问题）。
func SplitSearchKeywords(raw string) []string {
	out := make([]string, 0)
	for _, v := range strings.Split(raw, ",") {
		if k := strings.ToLower(strings.TrimSpace(v)); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// SearchTerms 是一条 PoC 参与关键词检索的字段集合。
type SearchTerms struct {
	ID       string
	Name     string
	Tags     []string
	Requires []string
}

// MatchSearchKeywords 判断一条 PoC 是否命中任一关键词：任一字段子串包含任一关键词即算命中
// （OR 语义）。keywords 需先用 SplitSearchKeywords 归一化；为空时返回 true（不设关键词即全放行）。
//
// 检索范围刻意包含 Requires：requires 是「先识别、再验证」的依赖声明（如 jquery<3.5），
// 纳入检索后「识别到某技术栈 → 检索依赖它的 PoC」才成立；requires 词条里的版本约束
// （<、>= 等连同比对值）也随之可被搜到，让版本依据在检索侧同样可见。
func MatchSearchKeywords(terms SearchTerms, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	hay := make([]string, 0, len(terms.Tags)+len(terms.Requires)+2)
	hay = append(hay, strings.ToLower(terms.ID), strings.ToLower(terms.Name))
	for _, t := range terms.Tags {
		hay = append(hay, strings.ToLower(t))
	}
	for _, r := range terms.Requires {
		hay = append(hay, strings.ToLower(r))
	}
	for _, h := range hay {
		for _, k := range keywords {
			if strings.Contains(h, k) {
				return true
			}
		}
	}
	return false
}
