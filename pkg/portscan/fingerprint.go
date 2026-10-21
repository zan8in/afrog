package portscan

import (
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

const (
	// DefaultProbeID 是规则未声明 probes 时使用的探针：只读、不发送数据。
	DefaultProbeID = "NULL"

	// fingerprintMatchTimeout 限制单条正则的匹配耗时，防止灾难性回溯拖慢扫描。
	fingerprintMatchTimeout = 200 * time.Millisecond

	// maxBannerBytes 是写入 ScanResult.Banner 的响应长度上限。
	maxBannerBytes = 2048
)

// Confidence 表示端口指纹识别结果的可信度。数值越大证据越强。
type Confidence int

const (
	// ConfidenceUnknown 没有任何证据。
	ConfidenceUnknown Confidence = iota
	// ConfidencePortOnly 只有端口惯例，属于推测。
	ConfidencePortOnly
	// ConfidenceProbable 弱特征命中（softmatch 或显式 probable）。
	ConfidenceProbable
	// ConfidenceCertain 明确 banner / 协议特征命中。
	ConfidenceCertain
)

func (c Confidence) String() string {
	switch c {
	case ConfidencePortOnly:
		return "port"
	case ConfidenceProbable:
		return "probable"
	case ConfidenceCertain:
		return "certain"
	default:
		return "unknown"
	}
}

// Observation 是一条探针在某个端口上观察到的原始响应。
type Observation struct {
	ProbeID string
	Data    []byte
	TLS     bool
}

// ServiceInfo 是端口指纹识别的结果。
type ServiceInfo struct {
	Service    string
	Product    string
	Version    string
	Device     string
	Hostname   string
	OS         string
	CPE        string
	Info       string
	TLS        bool
	Confidence Confidence
	RuleID     string
	ProbeID    string
	Banner     string
	Extras     map[string]string
}

// Fingerprinter 是数据驱动的端口指纹识别引擎，可安全并发使用。
type Fingerprinter struct {
	db *FingerprintDB
}

// NewFingerprinter 加载内置指纹集（dir 非空时合并外置目录）并返回识别引擎。
func NewFingerprinter(dir string) (*Fingerprinter, error) {
	db, err := LoadFingerprintDB(dir)
	if err != nil {
		return nil, err
	}
	return &Fingerprinter{db: db}, nil
}

// PriorFor 返回端口的先验信息，没有先验时返回 nil。
func (f *Fingerprinter) PriorFor(port int) *PortPrior {
	return f.db.Priors[port]
}

// TLSPort 报告该端口按惯例是否为 TLS 端口。
func (f *Fingerprinter) TLSPort(port int) bool {
	p := f.db.Priors[port]
	return p != nil && p.TLS
}

// webServices 是以 HTTP(S) 为传输层的服务名，取自 nmap-services 的命名习惯。
var webServices = map[string]struct{}{
	"http":       {},
	"http-alt":   {},
	"http-mgmt":  {},
	"http-proxy": {},
	"https":      {},
	"https-alt":  {},
	"squid-http": {},
	"whm":        {},
}

// IsWebService 报告服务名是否以 HTTP(S) 为传输层，用于判断端口是否值得做 Web 探测。
//
// 名称中含 "http" / "web" 的一律按 Web 处理，因此外置指纹库新增的
// 同类服务名（如 webmail、infoweb）无需改动代码即可生效。
func IsWebService(service string) bool {
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return false
	}
	if _, ok := webServices[service]; ok {
		return true
	}
	return strings.Contains(service, "http") || strings.Contains(service, "web")
}

// Probes 返回应在指定端口上执行的探针（保持文件顺序即优先级），
// mode 取 ProbeModePassive 或 ProbeModeActive。
func (f *Fingerprinter) Probes(port int, mode string) []*Probe {
	var out []*Probe
	for _, p := range f.db.Probes {
		if p.Mode != mode || !p.appliesTo(port) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Identify 根据某个端口上收集到的全部探针响应给出识别结果。
//
// 结果合并顺序：先按端口先验给出推测，再用所有命中的规则做证据叠加——可信度最高
// 的规则决定服务名、产品、版本与可信度，其余规则只补充尚未确定的字段（如设备厂商）。
func (f *Fingerprinter) Identify(port int, obs []Observation) *ServiceInfo {
	info := &ServiceInfo{}
	if prior := f.db.Priors[port]; prior != nil {
		info.Service = prior.Service
		info.TLS = prior.TLS
		if prior.Service != "" {
			info.Confidence = ConfidencePortOnly
		}
	}

	var banner []byte
	var cands []*candidate
	for i := range obs {
		o := &obs[i]
		if o.TLS {
			info.TLS = true
		}
		if len(o.Data) == 0 {
			continue
		}
		if banner == nil {
			banner = o.Data
		}
		cands = append(cands, f.matchAll(o)...)
	}

	var best *candidate
	for _, c := range cands {
		if best == nil || c.better(best) {
			best = c
		}
	}
	if best != nil {
		best.write(info, true)
		banner = best.data
		for _, c := range cands {
			if c != best {
				c.write(info, false)
			}
		}
	}
	if banner != nil {
		info.Banner = sanitizeBanner(banner)
	}
	return info
}

// matchAll 返回该响应在所有适用规则上命中的候选（每条规则取第一条命中的 pattern）。
func (f *Fingerprinter) matchAll(o *Observation) []*candidate {
	var out []*candidate
	view := obsView{data: o.Data}
	for _, r := range f.db.Rules {
		if _, ok := r.probeSet[o.ProbeID]; !ok {
			continue
		}
		text := view.text(r.binary)
		for i := range r.Match {
			m := &r.Match[i]
			mm, err := m.re.FindStringMatch(text)
			if err != nil || mm == nil {
				continue
			}
			out = append(out, newCandidate(r, m, mm, o.ProbeID, o.Data))
			break
		}
	}
	return out
}

// obsView 为一条响应惰性准备 text / binary 两种解读方式。
type obsView struct {
	data    []byte
	raw     string
	bin     string
	rawDone bool
	binDone bool
}

func (v *obsView) text(binary bool) string {
	if !binary {
		if !v.rawDone {
			v.raw = string(v.data)
			v.rawDone = true
		}
		return v.raw
	}
	if !v.binDone {
		v.bin = latin1String(v.data)
		v.binDone = true
	}
	return v.bin
}

// candidate 是一条规则的一次命中。
type candidate struct {
	rule    *Rule
	probeID string
	data    []byte
	conf    Confidence

	service  string
	product  string
	version  string
	device   string
	hostname string
	os       string
	cpe      string
	info     string
	extras   map[string]string
}

func newCandidate(rule *Rule, m *MatchRule, mm *regexp2.Match, probeID string, data []byte) *candidate {
	groups := &groupRef{m: mm}
	used := make(map[string]struct{}, 4)
	expand := func(tpl string) string {
		if tpl == "" {
			return ""
		}
		v, names := expandTemplate(tpl, groups)
		for _, n := range names {
			used[n] = struct{}{}
		}
		return v
	}

	c := &candidate{
		rule:     rule,
		probeID:  probeID,
		data:     data,
		service:  rule.Service,
		conf:     m.confidenceFor(rule),
		product:  firstNonEmpty(expand(m.Product), expand(rule.Product)),
		version:  strings.TrimSpace(expand(m.Version)),
		device:   firstNonEmpty(expand(m.Device), expand(rule.Device)),
		hostname: strings.TrimSpace(expand(m.Hostname)),
		os:       strings.TrimSpace(expand(m.OS)),
		cpe:      firstNonEmpty(expand(m.CPE), expand(rule.CPE)),
		info:     collapseSpaces(expand(m.Info)),
	}

	// 未被任何字段引用的具名组进入 Extras，便于 PoC 与报告使用。
	for _, name := range m.names {
		if _, ok := used[name]; ok {
			continue
		}
		v := groups.byName(name)
		if v == "" {
			continue
		}
		if c.extras == nil {
			c.extras = make(map[string]string, 2)
		}
		c.extras[name] = v
	}
	return c
}

// better 报告本条候选是否比另一条更可信：先比可信度，再比规则在文件中的顺序。
func (c *candidate) better(o *candidate) bool {
	if c.conf != o.conf {
		return c.conf > o.conf
	}
	return c.rule.order < o.rule.order
}

// write 把候选字段写入结果。overwrite 为 false 时只填充尚未确定的字段，
// 因此弱规则永远不会覆盖强规则已经识别出的内容。
func (c *candidate) write(info *ServiceInfo, overwrite bool) {
	if overwrite {
		if c.service != "" {
			info.Service = c.service
		}
		info.RuleID = c.rule.ID
		info.ProbeID = c.probeID
		info.Extras = c.extras
	}
	set := func(dst *string, v string) {
		if v == "" || (!overwrite && *dst != "") {
			return
		}
		*dst = v
	}
	set(&info.Product, c.product)
	set(&info.Version, c.version)
	set(&info.Device, c.device)
	set(&info.Hostname, c.hostname)
	set(&info.OS, c.os)
	set(&info.CPE, c.cpe)
	set(&info.Info, c.info)
	if c.conf > info.Confidence {
		info.Confidence = c.conf
	}
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
	if g == nil || g.m == nil {
		return ""
	}
	n := 0
	for i := 0; i < len(num); i++ {
		n = n*10 + int(num[i]-'0')
	}
	if gr := g.m.GroupByNumber(n); gr != nil {
		return gr.String()
	}
	return ""
}

// expandTemplate 展开取值模板，支持 $0..$9、$name 与 ${name}，返回用到的引用名。
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

// latin1String 把原始字节按 latin-1 逐字节映射成字符，使正则里的 \xNN 能与
// 任意二进制字节一一对应（用于 MQTT 之类纯二进制协议）。
func latin1String(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// sanitizeBanner 生成可安全输出的 banner：截断到上限、替换非法 UTF-8 与 NUL。
func sanitizeBanner(b []byte) string {
	if len(b) > maxBannerBytes {
		b = b[:maxBannerBytes]
	}
	s := strings.TrimSpace(string(b))
	s = strings.ToValidUTF8(s, ".")
	return strings.ReplaceAll(s, "\x00", ".")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func collapseSpaces(s string) string {
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), " ")
}

func isNameByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
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
