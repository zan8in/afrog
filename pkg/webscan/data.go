package webscan

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v2"
)

// 内置指纹集以 go:embed 方式打进二进制，运行时不需要任何外部文件。
// 用户可以通过 WebFingerprintDir 提供同名的 rules.yaml 来做覆盖或扩展。
//
//go:embed fingerprints/*.yaml
var builtinFS embed.FS

const builtinRulesFile = "fingerprints/rules.yaml"

// 匹配素材来源。
const (
	// SourceHeader 匹配响应头：指定 header 时只匹配该头的值，否则匹配整个响应头块。
	SourceHeader = "header"
	// SourceBody 匹配响应正文。
	SourceBody = "body"
	// SourceTitle 匹配页面标题。
	SourceTitle = "title"
	// SourceFavicon 匹配 favicon 的 mmh3 哈希（十进制字符串）。
	SourceFavicon = "favicon"
)

// MatchRule 是规则里的一条正则及其提取字段。
type MatchRule struct {
	Source     string `yaml:"source"`
	Header     string `yaml:"header"`
	Pattern    string `yaml:"pattern"`
	Confidence string `yaml:"confidence"`
	Version    string `yaml:"version"`
	CPE        string `yaml:"cpe"`

	re    *regexp2.Regexp
	names []string
}

// compile 编译正则并校验字段取值。
func (m *MatchRule) compile(ruleID string) error {
	switch m.Source {
	case SourceHeader, SourceBody, SourceTitle, SourceFavicon:
	case "":
		return fmt.Errorf("webscan: rule %s: match without source", ruleID)
	default:
		return fmt.Errorf("webscan: rule %s: unknown source %q", ruleID, m.Source)
	}
	if m.Header != "" && m.Source != SourceHeader {
		return fmt.Errorf("webscan: rule %s: header is only valid for source %s", ruleID, SourceHeader)
	}
	if m.Pattern == "" {
		return fmt.Errorf("webscan: rule %s: empty pattern", ruleID)
	}
	re, err := regexp2.Compile(m.Pattern, regexp2.None)
	if err != nil {
		return fmt.Errorf("webscan: rule %s: invalid pattern %q: %w", ruleID, m.Pattern, err)
	}
	// 与端口指纹一致：限制单条正则的匹配耗时，避免灾难性回溯拖慢扫描。
	re.MatchTimeout = matchTimeout
	m.re = re
	m.names = m.names[:0]
	for _, name := range re.GetGroupNames() {
		if isNumeric(name) {
			continue
		}
		m.names = append(m.names, name)
	}

	switch strings.ToLower(strings.TrimSpace(m.Confidence)) {
	case "", "certain", "probable":
	default:
		return fmt.Errorf("webscan: rule %s: unknown confidence %q", ruleID, m.Confidence)
	}
	return nil
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
	ID        string      `yaml:"id"`
	Name      string      `yaml:"name"`
	Category  string      `yaml:"category"`
	CPE       string      `yaml:"cpe"`
	SoftMatch bool        `yaml:"softmatch"`
	Match     []MatchRule `yaml:"match"`

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
	return nil
}

// LoadDB 加载内置规则集，并在 dir 非空时把外置目录的 rules.yaml 合并进来。
//
// 合并语义与端口指纹一致：外置规则整体排在内置规则之前，同 id 覆盖内置。排在前面保证
// 用户新增的 specific 规则不会被内置的通用规则抢先命中。
// 目录下没有 rules.yaml 不是错误；只有文件存在但解析失败才返回错误。
func LoadDB(dir string) (*DB, error) {
	var rules []*Rule
	if err := unmarshalEmbedded(builtinRulesFile, &rules); err != nil {
		return nil, err
	}
	db := &DB{}
	if dir != "" {
		var err error
		if rules, db.hasFavicon, err = mergeRules(dir, rules); err != nil {
			return nil, err
		}
	}
	db.Rules = rules
	if err := db.compile(); err != nil {
		return nil, err
	}
	return db, nil
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

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
