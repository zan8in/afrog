package webscan

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

// 内置指纹集以 go:embed 方式打进二进制，运行时不需要任何外部文件。
// 用户可以通过 WebFingerprintDir 提供同名的 rules.yaml 来做覆盖或扩展。
//
//go:embed fingerprints/*.yaml fingerprints/*.json
var builtinFS embed.FS

const (
	// builtinRulesFile 是人工维护的精选规则集（含 favicon/CPE 等重型判据）。
	builtinRulesFile = "fingerprints/rules.yaml"
	// communityRulesFile 是从 Wappalyzer 社区库（enthec/webappanalyzer）生成的扩展规则集。
	//
	// 它体量大、覆盖广，与精选集互补：精选集讲究判据强度，社区集讲究覆盖面。
	// 两份规则命中同一技术时按 id 去重，精选集优先（见 LoadDB）。
	communityRulesFile = "fingerprints/wappalyzer.json"
)

// 匹配素材来源。
//
// 前四类（header/body/title/favicon）是内置规则集使用的原生源；其余六类随 Wappalyzer
// 全量库引入，命名与 Wappalyzer 的 source 字段保持一致，便于数据文件从上游直接生成。
const (
	// SourceHeader 匹配响应头：指定 header 时只匹配该头的值，否则匹配整个响应头块。
	SourceHeader = "header"
	// SourceBody 匹配响应正文。
	SourceBody = "body"
	// SourceTitle 匹配页面标题。
	SourceTitle = "title"
	// SourceFavicon 匹配 favicon 的 mmh3 哈希（十进制字符串）。
	SourceFavicon = "favicon"

	// SourceScriptSrc 匹配页面引用的脚本地址（<script src> 与 modulepreload 的 href）。
	SourceScriptSrc = "scriptSrc"
	// SourceScripts 匹配页面内联脚本的内容（<script> 标签体，不含外部脚本）。
	//
	// 与 scriptSrc 的区别：前者看「引了哪个文件」，后者看「页面里写了什么 JS」。
	// 内联脚本是服务端直出的，正是指纹的高信噪素材（如 Next.js 的 __next_f.push）。
	SourceScripts = "scripts"
	// SourceCSS 匹配正文里的 CSS 特征（内联样式、样式表文件内容、class 名）。
	SourceCSS = "css"
	// SourceHTML 匹配页面标记本身（class 名、标签结构），等价于在整段正文里查找。
	//
	// 与 css 分开只是为了与上游数据的 source 命名对齐；两者的匹配素材都是正文。
	SourceHTML = "html"
	// SourceText 匹配正文文本特征。
	SourceText = "text"
	// SourceURL 匹配请求 URL。
	SourceURL = "url"
	// SourceMeta 匹配 <meta> 标签：Key 为 name/property/http-equiv 的值，Pattern 匹配 content。
	SourceMeta = "meta"
	// SourceCookies 匹配 Set-Cookie：Key 为 Cookie 名，Pattern 匹配其值（Pattern 为空即只要存在该 Cookie）。
	SourceCookies = "cookies"
)

// keyedSources 是需要「键 + 值」两段信息的源：键取自 Key 字段（header 沿用它自己的字段）。
var keyedSources = map[string]bool{
	SourceHeader: true, SourceMeta: true, SourceCookies: true,
}

// bodySources 是匹配素材都取自响应正文的源。
//
// 这四类共用同一个多模式预筛器：正文可能长达数百 KB，是唯一需要做批量扫描的素材；
// 其余源（脚本地址、响应头、Cookie、meta）都是短文本，逐条 Contains 已经足够便宜。
var bodySources = map[string]bool{
	SourceBody: true, SourceHTML: true, SourceCSS: true, SourceText: true,
}

// MatchRule 是规则里的一条正则及其提取字段。
type MatchRule struct {
	Source     string `yaml:"source" json:"source"`
	Header     string `yaml:"header,omitempty" json:"header,omitempty"`
	Key        string `yaml:"key,omitempty" json:"key,omitempty"`
	Pattern    string `yaml:"pattern" json:"pattern"`
	Confidence string `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Version    string `yaml:"version,omitempty" json:"version,omitempty"`
	CPE        string `yaml:"cpe,omitempty" json:"cpe,omitempty"`

	re *regexp.Regexp
	// names 是 re 的捕获组名（SubexpNames），与子匹配下标一一对应，供取值模板按名引用。
	names []string
	// literals 是模式里必然出现的字面量，用于匹配前的廉价预筛；任一出现即可放行。
	//
	// 全量库有近八千条模式，逐条跑正则不现实；而绝大多数模式都锚定在固定词上
	// （如 vue、axios、--tw-）。先确认该词存在，再跑正则，可把 99% 的模式在一次
	// 内存扫描里排除掉。
	literals []string
	// literalCI 表示 literals 是在「大小写不敏感」前提下成立的，比对时要先把素材折成小写。
	//
	// 漏掉这一位会造成静默漏报：`(?i)nginx` 的字面量是 nginx，正文写 `NGINX` 时
	// 大小写敏感比对会把本该命中的规则挡在门外。
	literalCI bool
	// bodyLiterals 是 literals 在正文多模式预筛器里的序号；为空表示本条不参与正文预筛。
	bodyLiterals []int32
}

// compile 编译正则并校验字段取值。
func (m *MatchRule) compile(ruleID string) error {
	switch m.Source {
	case SourceHeader, SourceBody, SourceTitle, SourceFavicon,
		SourceScriptSrc, SourceScripts, SourceCSS, SourceHTML, SourceText,
		SourceURL, SourceMeta, SourceCookies:
	case "":
		return fmt.Errorf("webscan: rule %s: match without source", ruleID)
	default:
		return fmt.Errorf("webscan: rule %s: unknown source %q", ruleID, m.Source)
	}
	if m.Header != "" && m.Source != SourceHeader {
		return fmt.Errorf("webscan: rule %s: header is only valid for source %s", ruleID, SourceHeader)
	}
	if m.Key != "" && !keyedSources[m.Source] {
		return fmt.Errorf("webscan: rule %s: key is only valid for keyed sources, got %q", ruleID, m.Source)
	}
	if m.Key != "" && m.Source == SourceHeader {
		return fmt.Errorf("webscan: rule %s: use header instead of key for source %s", ruleID, SourceHeader)
	}
	if (m.Source == SourceMeta || m.Source == SourceCookies) && strings.TrimSpace(m.Key) == "" {
		return fmt.Errorf("webscan: rule %s: source %s requires key", ruleID, m.Source)
	}
	// Pattern 允许为空：cookies/headers 里「只要存在该名字」就是命中（Wappalyzer 的写法）。
	if m.Pattern != "" {
		// 用 RE2（标准库 regexp）而非回溯型引擎：全量库近八千条模式，实测回溯引擎
		// 在 256KB 正文上要 10 秒级，RE2 只要几十毫秒，且天然免疫灾难性回溯。
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return fmt.Errorf("webscan: rule %s: invalid pattern %q: %w", ruleID, m.Pattern, err)
		}
		m.re = re
		m.literals, m.literalCI = literalHints(m.Pattern)
		m.names = re.SubexpNames()
	}

	switch strings.ToLower(strings.TrimSpace(m.Confidence)) {
	case "", "certain", "probable":
	default:
		return fmt.Errorf("webscan: rule %s: unknown confidence %q", ruleID, m.Confidence)
	}
	return nil
}

// literalHints 从模式里抽出若干段「命中时必然出现」的字面量，供预筛使用。
//
// 顶层用 `|` 分成多个分支时，每个分支各抽一段：只要任一分支的字面量出现，这段模式
// 就有可能命中——预筛是「或」的关系。反之，只要有一个分支抽不出字面量，整条模式就
// 放弃预筛（否则那道分支的命中会被静默挡掉）。
//
// 单个分支内部只在最外层（括号之外、字符类之外）收集连续字面量，取最长的一段。
// 这样既覆盖 `<[^>]*class="ant-` 这种「元字符在前、长字面量在后」的写法，也不会被
// `[^<>]*`、`\d+` 之类的结构误导。抽不出至少 3 个字符就放弃——宁可少预筛，
// 也不能让预筛挡掉本该命中的模式。
//
// 第二个返回值表示这些字面量是在大小写不敏感的前提下成立的（模式含 (?i)），
// 比对时需要先把素材折成小写。
func literalHints(pattern string) ([]string, bool) {
	ci := strings.Contains(pattern, "(?i")
	branches := splitTopLevel(pattern)
	hints := make([]string, 0, len(branches))
	seen := make(map[string]bool, len(branches))
	for _, b := range branches {
		lit := longestLiteral(b)
		if lit == "" {
			return nil, false
		}
		if ci {
			lit = foldASCII(lit)
		}
		if seen[lit] {
			continue
		}
		seen[lit] = true
		hints = append(hints, lit)
	}
	if len(hints) == 0 {
		return nil, false
	}
	return hints, ci
}

// splitTopLevel 按最外层的 `|` 切分模式。
//
// 很多模式整体被一对分组包住（`(?:A|B)`），分组本身不是可选结构，等价于直接写
// `A|B`；不解开这层就会把整条模式当成「没有分支」，字面量抽取也随之失效。
func splitTopLevel(pattern string) []string {
	pattern = unwrapOuterGroup(pattern)
	var (
		out   []string
		start int
		depth int
	)
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '[':
			i++
			for i < len(pattern) && pattern[i] != ']' {
				if pattern[i] == '\\' {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				out = append(out, pattern[start:i])
				start = i + 1
			}
		}
	}
	return append(out, pattern[start:])
}

// unwrapOuterGroup 反复剥掉「包住整个模式」的分组外壳。
func unwrapOuterGroup(pattern string) string {
	for len(pattern) > 2 && pattern[0] == '(' {
		close := matchParen(pattern, 0)
		if close != len(pattern)-1 {
			return pattern
		}
		inner := pattern[1:close]
		// 去掉分组前缀：?: ?P<name>: ?<name>: 等。
		if strings.HasPrefix(inner, "?:") {
			inner = inner[2:]
		} else if strings.HasPrefix(inner, "?P<") {
			if j := strings.IndexByte(inner, '>'); j > 0 {
				inner = inner[j+1:]
				if strings.HasPrefix(inner, ":") {
					inner = inner[1:]
				}
			}
		} else if strings.HasPrefix(inner, "?<") {
			if j := strings.IndexByte(inner, '>'); j > 0 {
				inner = inner[j+1:]
				if strings.HasPrefix(inner, ":") {
					inner = inner[1:]
				}
			}
		}
		pattern = inner
	}
	return pattern
}

// matchParen 返回与 start 处的 `(` 配对的 `)` 下标，找不到返回 -1。
func matchParen(pattern string, start int) int {
	depth := 0
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '[':
			i++
			for i < len(pattern) && pattern[i] != ']' {
				if pattern[i] == '\\' {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// longestLiteral 取单个分支里最长的一段必现字面量，取不到返回空串。
func longestLiteral(pattern string) string {
	var best, cur strings.Builder

	flush := func() {
		if cur.Len() > best.Len() {
			best.Reset()
			best.WriteString(cur.String())
		}
		cur.Reset()
	}
	// dropLast 处理「前一个字符可重复零次」的修饰符（? * {0,n}）。
	dropLast := func() {
		if s := cur.String(); len(s) > 0 {
			cur.Reset()
			cur.WriteString(s[:len(s)-1])
		}
	}

	depth := 0
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\':
			if i+1 >= len(pattern) {
				flush()
				continue
			}
			n := pattern[i+1]
			// \d \b \w \A \1 这类转义的是字符类/锚点/引用，本身不是字面量。
			if n >= '0' && n <= '9' || n >= 'a' && n <= 'z' || n >= 'A' && n <= 'Z' {
				flush()
				i++
				continue
			}
			if depth == 0 {
				cur.WriteByte(n)
			}
			i++
		case c == '[':
			flush()
			i++
			for i < len(pattern) && pattern[i] != ']' {
				if pattern[i] == '\\' {
					i++
				}
				i++
			}
		case c == '(':
			flush()
			depth++
		case c == ')':
			flush()
			if depth > 0 {
				depth--
			}
		case c == '|':
			// 已由 splitTopLevel 处理，这里只可能出现在分组内部。
			flush()
		case c == '?' || c == '*':
			dropLast()
			flush()
		case c == '{':
			if j := strings.IndexByte(pattern[i:], '}'); j > 0 {
				if spec := pattern[i+1 : i+j]; strings.HasPrefix(spec, "0") {
					dropLast()
				}
				i += j
			}
			flush()
		case strings.IndexByte(`.^$+}`, c) >= 0:
			flush()
		default:
			if depth == 0 {
				cur.WriteByte(c)
			}
		}
	}
	flush()

	lit := best.String()
	if len(lit) < 3 {
		return ""
	}
	return lit
}

// foldASCII 只把 ASCII 大写字母折成小写，其余字节原样保留。
//
// 预筛只需覆盖 ASCII 字面量；用自定义折叠而不是 strings.ToLower，避免非 ASCII
// 内容在长度/编码上产生意料之外的变换。
func foldASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// confidenceFor 计算本条 match 的可信度，缺省继承规则级 softmatch 判定。
func (m *MatchRule) confidenceFor(r *Rule) Confidence {
	switch strings.ToLower(strings.TrimSpace(m.Confidence)) {
	case "certain":
		return ConfidenceCertain
	case "probable":
		return ConfidenceProbable
	}
	if r.SoftMatch {
		return ConfidenceProbable
	}
	return ConfidenceCertain
}

// Rule 是一条 Web 指纹规则：命中任意一条 match 即认为目标是该技术。
type Rule struct {
	ID        string      `yaml:"id" json:"id"`
	Name      string      `yaml:"name" json:"name"`
	Category  string      `yaml:"category" json:"category"`
	CPE       string      `yaml:"cpe,omitempty" json:"cpe,omitempty"`
	SoftMatch bool        `yaml:"softmatch,omitempty" json:"softmatch,omitempty"`
	Match     []MatchRule `yaml:"match" json:"match"`

	order int
}

func (r *Rule) compile() error {
	if r.ID == "" {
		return fmt.Errorf("webscan: rule with empty id")
	}
	if strings.TrimSpace(r.Name) == "" {
		r.Name = r.ID
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("webscan: rule %s has no match", r.ID)
	}
	for i := range r.Match {
		if err := r.Match[i].compile(r.ID); err != nil {
			return err
		}
	}
	return nil
}

// DB 是一整份 Web 指纹规则集。
type DB struct {
	Rules []*Rule

	// bodyLiterals 是正文类源的字面量多模式预筛器；bodyLiteralCount 是它的维度。
	//
	// 大小写敏感与不敏感的两组字面量分开建：AC 是按字节比较的，混在一起就必然要为
	// (?i) 规则引入漏报。分开之后，CI 组扫描的是折成小写的正文副本。
	bodyLiterals     *literalIndex
	bodyLiteralCount int
	bodyLiteralsCI   *literalIndex
	bodyLiteralCIDim int

	// hasFavicon 记录「外置规则集里是否含 favicon 规则」。
	//
	// 内置规则集本身也带 favicon 规则，但那只是数据：不抓 favicon 时它永远不会参与匹配。
	// 因此这里只看外置规则——用户在外置目录写 favicon 规则本身就说明他要抓 favicon，可以
	// 据此自动开启抓取；否则是否额外请求 /favicon.ico 完全由 -w-favicon 控制，默认不抓。
	hasFavicon bool
}

func (db *DB) compile() error {
	seen := make(map[string]struct{}, len(db.Rules))
	for i, r := range db.Rules {
		if err := r.compile(); err != nil {
			return err
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("webscan: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		r.order = i
	}
	db.indexBodyLiterals()
	return nil
}

// indexBodyLiterals 把正文类源的字面量汇总进去重后的多模式预筛器。
//
// 必须在全部规则编译完成后做：同一个字面量可能被多条规则共用，去重后只扫描一次。
func (db *DB) indexBodyLiterals() {
	var cs, ci []string
	csIDs := make(map[string]int32, 1024)
	ciIDs := make(map[string]int32, 1024)
	for _, r := range db.Rules {
		for i := range r.Match {
			m := &r.Match[i]
			m.bodyLiterals = nil
			if !bodySources[m.Source] || len(m.literals) == 0 {
				continue
			}
			ids, literals := csIDs, &cs
			if m.literalCI {
				ids, literals = ciIDs, &ci
			}
			for _, lit := range m.literals {
				id, ok := ids[lit]
				if !ok {
					id = int32(len(*literals))
					ids[lit] = id
					*literals = append(*literals, lit)
				}
				m.bodyLiterals = append(m.bodyLiterals, id)
			}
		}
	}
	db.bodyLiteralCount = len(cs)
	db.bodyLiterals = buildLiteralIndex(cs)
	db.bodyLiteralCIDim = len(ci)
	db.bodyLiteralsCI = buildLiteralIndex(ci)
}

// LoadDB 加载内置规则集，并在 dir 非空时把外置目录的 rules.yaml 合并进来。
//
// 合并语义与端口指纹一致：外置规则整体排在内置规则之前，同 id 覆盖内置。排在前面保证
// 用户新增的 specific 规则不会被内置的通用规则抢先命中。
// 目录下没有 rules.yaml 不是错误；只有文件存在但解析失败才返回错误。
func LoadDB(dir string) (*DB, error) {
	extra, err := loadBuiltinRules()
	if err != nil {
		return nil, err
	}
	db := &DB{}
	if dir != "" {
		if extra, db.hasFavicon, err = mergeRules(dir, extra); err != nil {
			return nil, err
		}
	}
	db.Rules = extra
	if err := db.compile(); err != nil {
		return nil, err
	}
	return db, nil
}

// loadBuiltinRules 合并两份内置规则源。
//
// 两份数据的分工：精选集判据强（专属 Cookie、favicon 哈希、CPE），社区集体量大、
// 覆盖广（脚本地址、CSS 变量、meta 等）。因此：
//   - 同 id：精选集先入表，社区条目丢弃；
//   - 同技术名（id 不同）：社区判据**追加**到精选规则里，而非另立一条。
//     否则同一个 Vue.js 会出现两条记录，且社区集里更宽的判据（scriptSrc、class 名）
//     会被白白丢掉——覆盖率正是这次要解决的问题。
func loadBuiltinRules() ([]*Rule, error) {
	var curated []*Rule
	if err := unmarshalEmbedded(builtinRulesFile, &curated); err != nil {
		return nil, err
	}
	var community []*Rule
	if err := unmarshalEmbeddedJSON(communityRulesFile, &community); err != nil {
		return nil, err
	}

	merged := make([]*Rule, 0, len(curated)+len(community))
	merged = append(merged, curated...)

	byID := make(map[string]*Rule, len(curated))
	byName := make(map[string]*Rule, len(curated))
	for _, r := range curated {
		byID[r.ID] = r
		byName[strings.ToLower(strings.TrimSpace(r.Name))] = r
	}

	for _, r := range community {
		if _, dup := byID[r.ID]; dup {
			continue
		}
		if host, ok := byName[strings.ToLower(strings.TrimSpace(r.Name))]; ok {
			// 社区判据来自众包数据，强度不如人工精调，统一压到 probable：
			// 追加的是「能多识别一些」的能力，不该顺带把精选集的可信度语义改掉。
			for i := range r.Match {
				r.Match[i].Confidence = "probable"
			}
			host.Match = append(host.Match, r.Match...)
			continue
		}
		byID[r.ID] = r
		byName[strings.ToLower(strings.TrimSpace(r.Name))] = r
		merged = append(merged, r)
	}
	return merged, nil
}

func unmarshalEmbedded(name string, out interface{}) error {
	b, err := builtinFS.ReadFile(name)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func unmarshalEmbeddedJSON(name string, out interface{}) error {
	b, err := builtinFS.ReadFile(name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// mergeRules 把外置目录的 rules.yaml 合并到内置规则之前，并报告外置规则里是否含 favicon 规则。
func mergeRules(dir string, builtin []*Rule) ([]*Rule, bool, error) {
	path := filepath.Join(dir, "rules.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return builtin, false, nil
		}
		return nil, false, err
	}
	var extra []*Rule
	if err := yaml.Unmarshal(b, &extra); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}

	overridden := make(map[string]struct{}, len(extra))
	for _, r := range extra {
		overridden[r.ID] = struct{}{}
	}
	merged := make([]*Rule, 0, len(builtin)+len(extra))
	merged = append(merged, extra...)
	for _, r := range builtin {
		if _, ok := overridden[r.ID]; ok {
			continue
		}
		merged = append(merged, r)
	}
	return merged, hasFaviconRules(extra), nil
}

func hasFaviconRules(rules []*Rule) bool {
	for _, r := range rules {
		for i := range r.Match {
			if r.Match[i].Source == SourceFavicon {
				return true
			}
		}
	}
	return false
}

// Summarize 把技术栈摘要成一行文本，如 "nginx 1.25.3, WordPress 6.4"。
func Summarize(techs []Technology) string {
	if len(techs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(techs))
	for _, t := range techs {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			continue
		}
		if v := strings.TrimSpace(t.Version); v != "" {
			name += " " + v
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
}

// sortTechnologies 按可信度从高到低排序，同可信度保持规则文件顺序。
func sortTechnologies(techs []Technology) {
	sort.SliceStable(techs, func(i, j int) bool {
		return techs[i].Confidence > techs[j].Confidence
	})
}
