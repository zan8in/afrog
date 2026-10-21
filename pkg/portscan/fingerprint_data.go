package portscan

import (
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v2"
)

// 内置指纹集（探针 + 规则 + 端口先验）以 go:embed 方式打进二进制，运行时不需要
// 任何外部文件。用户可以通过 FingerprintDir 提供同名文件来做覆盖或扩展。
//
//go:embed fingerprints/*.yaml
var builtinFingerprintFS embed.FS

const (
	builtinProbesFile   = "fingerprints/probes.yaml"
	builtinServicesFile = "fingerprints/services.yaml"
	builtinPortsFile    = "fingerprints/ports.yaml"

	// 探针模式：passive 参与默认识别阶段，active 需要显式开启。
	ProbeModePassive = "passive"
	ProbeModeActive  = "active"

	// 规则响应编码：text 直接按 UTF-8/ASCII 解读，binary 按 latin-1 逐字节映射。
	EncodingText   = "text"
	EncodingBinary = "binary"
)

// Probe 是一条已建立 TCP 连接上要发送（或不发送）的一段 payload。
type Probe struct {
	ID    string `yaml:"id"`
	Desc  string `yaml:"desc"`
	Mode  string `yaml:"mode"`
	Data  string `yaml:"data"`
	Hex   string `yaml:"hex"`
	TLS   bool   `yaml:"tls"`
	Ports []int  `yaml:"ports"`

	payload []byte
	portSet map[int]struct{}
}

// Passive 报告该探针是否属于默认识别阶段。
func (p *Probe) Passive() bool { return p.Mode != ProbeModeActive }

// appliesTo 报告该探针是否适用于指定端口。未声明 ports 的探针对所有端口生效。
func (p *Probe) appliesTo(port int) bool {
	if len(p.portSet) == 0 {
		return true
	}
	_, ok := p.portSet[port]
	return ok
}

func (p *Probe) compile() error {
	switch {
	case p.Hex != "":
		raw := strings.ReplaceAll(strings.TrimSpace(p.Hex), " ", "")
		b, err := hex.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("fingerprint: probe %s: invalid hex payload: %w", p.ID, err)
		}
		p.payload = b
	case p.Data != "":
		p.payload = []byte(p.Data)
	}

	if p.Mode == "" {
		if len(p.payload) > 0 {
			p.Mode = ProbeModeActive
		} else {
			p.Mode = ProbeModePassive
		}
	}
	if p.Mode != ProbeModePassive && p.Mode != ProbeModeActive {
		return fmt.Errorf("fingerprint: probe %s: unknown mode %q", p.ID, p.Mode)
	}

	p.portSet = intSet(p.Ports)
	return nil
}

// MatchRule 是规则里的一条正则及其提取字段。
type MatchRule struct {
	Pattern    string `yaml:"pattern"`
	Confidence string `yaml:"confidence"`
	Product    string `yaml:"product"`
	Version    string `yaml:"version"`
	Info       string `yaml:"info"`
	CPE        string `yaml:"cpe"`
	Hostname   string `yaml:"hostname"`
	OS         string `yaml:"os"`
	Device     string `yaml:"device"`

	re    *regexp2.Regexp
	names []string // 具名捕获组，用于生成 Extras
}

// compile 编译正则并校验 confidence 取值。
func (m *MatchRule) compile(ruleID string) error {
	if m.Pattern == "" {
		return fmt.Errorf("fingerprint: rule %s: empty pattern", ruleID)
	}
	re, err := regexp2.Compile(m.Pattern, regexp2.None)
	if err != nil {
		return fmt.Errorf("fingerprint: rule %s: invalid pattern %q: %w", ruleID, m.Pattern, err)
	}
	// 限制单条正则的匹配耗时，避免灾难性回溯把扫描拖死。
	re.MatchTimeout = fingerprintMatchTimeout
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
		return fmt.Errorf("fingerprint: rule %s: unknown confidence %q", ruleID, m.Confidence)
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

// Rule 是一组「在某个探针的响应上用什么正则、能提取出哪些字段」的规则。
type Rule struct {
	ID        string      `yaml:"id"`
	Service   string      `yaml:"service"`
	Product   string      `yaml:"product"`
	Device    string      `yaml:"device"`
	CPE       string      `yaml:"cpe"`
	Probes    []string    `yaml:"probes"`
	Ports     []int       `yaml:"ports"`
	SoftMatch bool        `yaml:"softmatch"`
	Encoding  string      `yaml:"encoding"`
	Match     []MatchRule `yaml:"match"`

	order    int
	binary   bool
	nameSet  map[string]struct{}
	probeSet map[string]struct{}
}

func (r *Rule) compile(probes map[string]*Probe) error {
	names := r.Probes
	if len(names) == 0 {
		names = []string{DefaultProbeID}
	}
	r.probeSet = make(map[string]struct{}, len(names))
	for _, n := range names {
		if _, ok := probes[n]; !ok {
			return fmt.Errorf("fingerprint: rule %s references unknown probe %q", r.ID, n)
		}
		r.probeSet[n] = struct{}{}
	}

	switch strings.ToLower(strings.TrimSpace(r.Encoding)) {
	case "", EncodingText:
		r.binary = false
	case EncodingBinary:
		r.binary = true
	default:
		return fmt.Errorf("fingerprint: rule %s: unknown encoding %q", r.ID, r.Encoding)
	}

	if len(r.Match) == 0 {
		return fmt.Errorf("fingerprint: rule %s has no match", r.ID)
	}
	for i := range r.Match {
		if err := r.Match[i].compile(r.ID); err != nil {
			return err
		}
	}
	return nil
}

// PortPrior 是某个端口的惯例服务与 TLS 属性，只用于兜底推测与决定是否做 TLS 握手。
type PortPrior struct {
	Port    int    `yaml:"port"`
	Service string `yaml:"service"`
	TLS     bool   `yaml:"tls"`
}

// FingerprintDB 是探针 + 规则 + 端口先验的完整指纹集。
type FingerprintDB struct {
	Probes []*Probe
	Rules  []*Rule
	Priors map[int]*PortPrior
}

// LoadFingerprintDB 加载内置指纹集，并在 dir 非空时把外置目录合并进来。
//
// 合并语义（外置永远优先）：
//   - probes.yaml   按 id 合并，同 id 覆盖内置，新 id 追加
//   - services.yaml 外置规则整体排在内置规则之前，同 id 覆盖内置。排在前面保证了
//     用户新增的 specific 规则不会被内置的通用规则（如 http）抢先命中
//   - ports.yaml    按端口合并，同端口覆盖内置
//
// 目录下缺少某个文件不是错误；只有文件存在但解析失败才返回错误。
func LoadFingerprintDB(dir string) (*FingerprintDB, error) {
	var probes []*Probe
	var rules []*Rule
	var priors []*PortPrior

	if err := unmarshalEmbedded(builtinProbesFile, &probes); err != nil {
		return nil, err
	}
	if err := unmarshalEmbedded(builtinServicesFile, &rules); err != nil {
		return nil, err
	}
	if err := unmarshalEmbedded(builtinPortsFile, &priors); err != nil {
		return nil, err
	}

	if dir != "" {
		var err error
		if probes, err = mergeProbes(dir, probes); err != nil {
			return nil, err
		}
		if rules, err = mergeRules(dir, rules); err != nil {
			return nil, err
		}
		if priors, err = mergePriors(dir, priors); err != nil {
			return nil, err
		}
	}

	db := &FingerprintDB{
		Probes: probes,
		Rules:  rules,
		Priors: make(map[int]*PortPrior, len(priors)),
	}
	for i, r := range rules {
		r.order = i
	}
	for _, p := range priors {
		db.Priors[p.Port] = p
	}
	if err := db.compile(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *FingerprintDB) compile() error {
	index := make(map[string]*Probe, len(db.Probes))
	for _, p := range db.Probes {
		if p.ID == "" {
			return fmt.Errorf("fingerprint: probe with empty id")
		}
		if _, dup := index[p.ID]; dup {
			return fmt.Errorf("fingerprint: duplicate probe id %q", p.ID)
		}
		if err := p.compile(); err != nil {
			return err
		}
		index[p.ID] = p
	}

	seen := make(map[string]struct{}, len(db.Rules))
	for _, r := range db.Rules {
		if r.ID == "" {
			return fmt.Errorf("fingerprint: rule with empty id")
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("fingerprint: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if err := r.compile(index); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalEmbedded(name string, out interface{}) error {
	b, err := builtinFingerprintFS.ReadFile(name)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// unmarshalFile 读取外置文件，文件不存在时返回 (false, nil)。
func unmarshalFile(path string, out interface{}) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func mergeProbes(dir string, builtin []*Probe) ([]*Probe, error) {
	var extra []*Probe
	found, err := unmarshalFile(filepath.Join(dir, "probes.yaml"), &extra)
	if err != nil || !found {
		return builtin, err
	}
	overridden := make(map[string]struct{}, len(extra))
	for _, p := range extra {
		overridden[p.ID] = struct{}{}
	}
	merged := make([]*Probe, 0, len(builtin)+len(extra))
	for _, p := range builtin {
		if _, ok := overridden[p.ID]; ok {
			continue
		}
		merged = append(merged, p)
	}
	return append(merged, extra...), nil
}

func mergeRules(dir string, builtin []*Rule) ([]*Rule, error) {
	var extra []*Rule
	found, err := unmarshalFile(filepath.Join(dir, "services.yaml"), &extra)
	if err != nil || !found {
		return builtin, err
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
	return merged, nil
}

func mergePriors(dir string, builtin []*PortPrior) ([]*PortPrior, error) {
	var extra []*PortPrior
	found, err := unmarshalFile(filepath.Join(dir, "ports.yaml"), &extra)
	if err != nil || !found {
		return builtin, err
	}
	overridden := make(map[int]struct{}, len(extra))
	for _, p := range extra {
		overridden[p.Port] = struct{}{}
	}
	merged := make([]*PortPrior, 0, len(builtin)+len(extra))
	for _, p := range builtin {
		if _, ok := overridden[p.Port]; ok {
			continue
		}
		merged = append(merged, p)
	}
	return append(merged, extra...), nil
}

func intSet(values []int) map[int]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[int]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}
