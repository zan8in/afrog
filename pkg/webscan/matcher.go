package webscan

import (
	"encoding/base64"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/spaolacci/murmur3"
)

const (
	// matchTimeout 限制单条正则的匹配耗时，防止灾难性回溯拖慢扫描。
	matchTimeout = 200 * time.Millisecond

	// maxBodyBytes 是参与匹配的正文长度上限，避免超大响应拖慢匹配。
	maxBodyBytes = 512 * 1024
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Matcher 在一份规则集上执行 Web 指纹匹配。
type Matcher struct {
	db *DB
}

// NewMatcher 基于规则集构造匹配器，db 为 nil 时返回一个空匹配器。
func NewMatcher(db *DB) *Matcher {
	if db == nil {
		db = &DB{}
	}
	return &Matcher{db: db}
}

// LoadMatcher 加载内置规则（并可选合并外置目录）后构造匹配器。
func LoadMatcher(dir string) (*Matcher, error) {
	db, err := LoadDB(dir)
	if err != nil {
		return nil, err
	}
	return NewMatcher(db), nil
}

// HasFavicon 报告外置规则集里是否有 favicon 规则。
//
// 调用方据此决定要不要额外抓取 /favicon.ico：内置规则虽然带了 favicon 规则，但抓取与否
// 仍以 -w-favicon 开关为准；而用户在外置目录里写 favicon 规则，本身就说明他要抓 favicon，
// 因此这里返回 true 时调用方应自动开启抓取、不必再要求开关。
func (m *Matcher) HasFavicon() bool {
	return m != nil && m.db != nil && m.db.hasFavicon
}

// Match 对一次 HTTP 响应做规则匹配，返回按可信度排序的技术栈。
func (m *Matcher) Match(resp Response) Result {
	var res Result
	if m == nil || m.db == nil {
		return res
	}

	mat := newMaterial(resp)
	res.FaviconHash = mat.faviconHash

	// 同名同版本只保留可信度最高的一条：key 为 name\x00version。
	seen := make(map[string]int, 8)
	for _, rule := range m.db.Rules {
		tech, ok := m.matchRule(rule, mat)
		if !ok {
			continue
		}
		if tech.Confidence > res.Confidence {
			res.Confidence = tech.Confidence
		}
		key := tech.Name + "\x00" + tech.Version
		if idx, dup := seen[key]; dup {
			if tech.Confidence > res.Technologies[idx].Confidence {
				res.Technologies[idx] = tech
			}
			continue
		}
		seen[key] = len(res.Technologies)
		res.Technologies = append(res.Technologies, tech)
	}
	sortTechnologies(res.Technologies)
	return res
}

// matchRule 取规则里第一条命中的 match 生成技术栈条目。
func (m *Matcher) matchRule(rule *Rule, mat material) (Technology, bool) {
	if rule == nil {
		return Technology{}, false
	}
	for i := range rule.Match {
		mr := &rule.Match[i]
		text, ok := mat.source(mr.Source, mr.Header)
		if !ok || text == "" {
			continue
		}
		hit, err := mr.re.FindStringMatch(text)
		if err != nil || hit == nil {
			continue
		}
		groups := &groupRef{m: hit}
		version, _ := expandTemplate(mr.Version, groups)
		cpe, _ := expandTemplate(mr.CPE, groups)
		if cpe == "" {
			cpe = rule.CPE
		}
		return Technology{
			Name:       rule.Name,
			Version:    strings.TrimSpace(version),
			Category:   rule.Category,
			CPE:        strings.TrimSpace(cpe),
			Confidence: mr.confidenceFor(rule),
			RuleID:     rule.ID,
		}, true
	}
	return Technology{}, false
}

// material 是从一次 HTTP 响应里抽出的匹配素材。
type material struct {
	headerBlock string
	headers     map[string]string // 键名统一小写
	body        string
	title       string
	faviconHash string
}

func newMaterial(resp Response) material {
	mat := material{headers: make(map[string]string, len(resp.Headers))}

	keys := make([]string, 0, len(resp.Headers))
	for k := range resp.Headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" {
			continue
		}
		mat.headers[lk] = resp.Headers[k]
		keys = append(keys, lk)
	}
	// 固定顺序拼接响应头块，保证同一响应多次匹配结果稳定。
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.TrimSpace(mat.headers[k]))
		sb.WriteString("\r\n")
	}
	mat.headerBlock = sb.String()

	if body := resp.Body; len(body) > 0 {
		if len(body) > maxBodyBytes {
			body = body[:maxBodyBytes]
		}
		mat.body = string(body)
		if m := titleRe.FindSubmatch(body); len(m) > 1 {
			t := html.UnescapeString(strings.TrimSpace(string(m[1])))
			mat.title = strings.Join(strings.Fields(t), " ")
		}
	}
	if len(resp.Favicon) > 0 {
		mat.faviconHash = faviconHash(resp.Favicon)
	}
	return mat
}

// source 按 source 类型取出待匹配文本，ok 为 false 表示该类素材不存在。
func (mat material) source(source, header string) (string, bool) {
	switch source {
	case SourceHeader:
		if strings.TrimSpace(header) == "" {
			return mat.headerBlock, mat.headerBlock != ""
		}
		v, ok := mat.headers[strings.ToLower(strings.TrimSpace(header))]
		return v, ok
	case SourceBody:
		return mat.body, mat.body != ""
	case SourceTitle:
		return mat.title, mat.title != ""
	case SourceFavicon:
		return mat.faviconHash, mat.faviconHash != ""
	default:
		return "", false
	}
}

// faviconHash 计算 favicon 的 mmh3 哈希（有符号十进制字符串）。
//
// 算法与业界通用实现一致：先 base64 编码（每 76 字符插入换行并在末尾补一个换行），
// 再对结果取 murmur3 x32 哈希并按 int32 解读。这样得到的哈希才能与公开的 favicon
// 指纹库对齐。
func faviconHash(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(encoded) + len(encoded)/76 + 1)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	return strconv.FormatInt(int64(int32(murmur3.Sum32([]byte(sb.String())))), 10)
}

// groupRef 提供按名字或序号读取捕获组的能力。
type groupRef struct {
	m *regexp2.Match
}

func (g *groupRef) byName(name string) string {
	if g == nil || g.m == nil || name == "" {
		return ""
	}
	if gr := g.m.GroupByName(name); gr != nil {
		return gr.String()
	}
	return ""
}

func (g *groupRef) byNumber(num string) string {
	if g == nil || g.m == nil || num == "" {
		return ""
	}
	n := 0
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return ""
		}
		n = n*10 + int(num[i]-'0')
	}
	if gr := g.m.GroupByNumber(n); gr != nil {
		return gr.String()
	}
	return ""
}

// expandTemplate 展开取值模板，支持 $0..$9、$name 与 ${name}。
func expandTemplate(tpl string, groups *groupRef) (string, []string) {
	if tpl == "" {
		return "", nil
	}
	var sb strings.Builder
	var used []string
	for i := 0; i < len(tpl); {
		if tpl[i] != '$' {
			sb.WriteByte(tpl[i])
			i++
			continue
		}
		if i+1 >= len(tpl) {
			sb.WriteByte('$')
			break
		}
		next := tpl[i+1]
		switch {
		case next == '{':
			end := strings.IndexByte(tpl[i+2:], '}')
			if end < 0 {
				sb.WriteByte('$')
				i++
				continue
			}
			name := tpl[i+2 : i+2+end]
			sb.WriteString(groups.byName(name))
			used = append(used, name)
			i += end + 3
		case next >= '0' && next <= '9':
			j := i + 1
			for j < len(tpl) && tpl[j] >= '0' && tpl[j] <= '9' {
				j++
			}
			num := tpl[i+1 : j]
			sb.WriteString(groups.byNumber(num))
			used = append(used, num)
			i = j
		case isNameByte(next):
			j := i + 1
			for j < len(tpl) && isNameByte(tpl[j]) {
				j++
			}
			name := tpl[i+1 : j]
			sb.WriteString(groups.byName(name))
			used = append(used, name)
			i = j
		default:
			sb.WriteByte('$')
			i++
		}
	}
	return sb.String(), used
}

func isNameByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}
