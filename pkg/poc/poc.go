package poc

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
	"gopkg.in/yaml.v2"
)

// https://docs.xray.cool/#/guide/poc/v2
// Rule有序，参考：https://github.com/WAY29/pocV/blob/main/pkg/xray/structs/poc.go

const (
	STOP_IF_FIRST_MATCH    = "STOP_IF_FIRST_MATCH"
	STOP_IF_FIRST_MISMATCH = "STOP_IF_FIRST_MISMATCH"
)

type WaitGroupTask struct {
	Key   int
	Value any
}

type Poc struct {
	Id         string        `yaml:"id"`        //  脚本名称
	Transport  string        `yaml:"transport"` // 传输方式，该字段用于指定发送数据包的协议，该字段用于指定发送数据包的协议:①tcp ②udp ③http
	Set        yaml.MapSlice `yaml:"set"`       // 全局变量定义，该字段用于定义全局变量。比如随机数，反连平台等
	Payloads   Payloads      `yaml:"payloads"`
	Rules      RuleMapSlice  `yaml:"rules"`
	Expression string        `yaml:"expression"`
	Info       Info          `yaml:"info"`
	Gopoc      string        `yaml:"gopoc"` // Gopoc 脚本名称
	Extractors []Extractors  `yaml:"extractors"`

	EstimatedTaskTimeoutSec    int    `yaml:"-"`
	EstimatedTaskTimeoutReason string `yaml:"-"`
}

// TODO REMARK
type Payloads struct {
	Continue bool          `yaml:"continue"`
	Payloads yaml.MapSlice `yaml:"payloads"`
}

// 以下是 脚本部分
var order = 0

// 用于帮助yaml解析，保证Rule有序
type RuleMap struct {
	Key   string
	Value Rule
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapSlice []RuleMap
type Rule struct {
	Brute          yaml.MapSlice `yaml:"brute"`
	Request        RuleRequest   `yaml:"request"`
	Expression     string        `yaml:"expression"`
	Expressions    []string      `yaml:"expressions"`
	Output         yaml.MapSlice `yaml:"output"`
	Extractors     []Extractors  `yaml:"extractors"`
	StopIfMatch    bool          `yaml:"stop_if_match"`
	StopIfMismatch bool          `yaml:"stop_if_mismatch"`
	BeforeSleep    int           `yaml:"before_sleep"`
	order          int
}

type ruleAlias struct {
	Brute          yaml.MapSlice `yaml:"brute"`
	Request        RuleRequest   `yaml:"request"`
	Expression     string        `yaml:"expression"`
	Expressions    []string      `yaml:"expressions"`
	Output         yaml.MapSlice `yaml:"output"`
	Extractors     []Extractors  `yaml:"extractors"`
	StopIfMatch    bool          `yaml:"stop_if_match"`
	StopIfMismatch bool          `yaml:"stop_if_mismatch"`
	BeforeSleep    int           `yaml:"before_sleep"`
}

// http/tcp/udp cache 是否使用缓存的请求，如果该选项为 true，那么如果在一次探测中其它脚本对相同目标发送过相同请求，那么便使用之前缓存的响应，而不发新的数据包
// content 用于tcp/udp请求，请求内容，比如：content: "request"
// read_timeout 用于tcp/udp请求，发送请求之后的读取超时时间（注 实际是一个 int， 但是为了能够变量渲染，设置为 string）
type RuleRequest struct {
	Type            string            `yaml:"type"`         // 传输方式，默认 http，可选：tcp,udp,ssl,go 等任意扩展
	Host            string            `yaml:"host"`         // tcp/udp 请求的主机名
	Port            int               `yaml:"port"`         // tcp/udp 端口（可选，优先级低于 host 中显式端口）
	Data            string            `yaml:"data"`         // tcp/udp 发送的内容
	DataType        string            `yaml:"data-type"`    // tcp/udp 发送的数据类型，默认字符串
	ReadSize        int               `yaml:"read-size"`    // tcp/udp 读取内容的长度
	ReadTimeout     int               `yaml:"read-timeout"` // tcp/udp专用
	Steps           []NetStep         `yaml:"steps"`
	Raw             string            `yaml:"raw"` // raw 专用
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

type NetStep struct {
	Read  *NetReadStep  `yaml:"read,omitempty"`
	Write *NetWriteStep `yaml:"write,omitempty"`
}

type NetReadStep struct {
	ReadSize    int    `yaml:"read-size"`
	ReadTimeout int    `yaml:"read-timeout"`
	ReadUntil   string `yaml:"read-until,omitempty"`
	ReadType    string `yaml:"read-type,omitempty"`
	SaveAs      string `yaml:"save-as"`
}

type NetWriteStep struct {
	Data     string `yaml:"data"`
	DataType string `yaml:"data-type"`
}

const (
	HTTP_Type  = "http"
	HTTPS_Type = "https"
	TCP_Type   = "tcp"
	UDP_Type   = "udp"
	SSL_Type   = "ssl"
	GO_Type    = "go"
)

// 以下开始是 信息部分
type Info struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Verified       bool           `yaml:"verified"`
	Description    string         `yaml:"description"`
	Reference      []string       `yaml:"reference"`
	Affected       string         `yaml:"affected"`  // 影响版本
	Solutions      string         `yaml:"solutions"` // 解决方案
	Tags           string         `yaml:"tags"`      // 标签
	Requires       []string       `yaml:"requires"`
	RequiresMode   string         `yaml:"requires-mode"`
	Classification Classification `yaml:"classification"`
	Created        string         `yaml:"created"` // create time
}

func (i *Info) UnmarshalYAML(unmarshal func(any) error) error {
	type infoYAML struct {
		Name           string         `yaml:"name"`
		Author         string         `yaml:"author"`
		Severity       string         `yaml:"severity"`
		Verified       bool           `yaml:"verified"`
		Description    string         `yaml:"description"`
		Reference      []string       `yaml:"reference"`
		Affected       string         `yaml:"affected"`
		Solutions      string         `yaml:"solutions"`
		Tags           string         `yaml:"tags"`
		Requires       any            `yaml:"requires"`
		RequiresMode   string         `yaml:"requires-mode"`
		RequiresMode2  string         `yaml:"requiresMode"`
		RequiresMode3  string         `yaml:"requires_mode"`
		Classification Classification `yaml:"classification"`
		Created        string         `yaml:"created"`
	}
	var tmp infoYAML
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	i.Name = tmp.Name
	i.Author = tmp.Author
	i.Severity = tmp.Severity
	i.Verified = tmp.Verified
	i.Description = tmp.Description
	i.Reference = tmp.Reference
	i.Affected = tmp.Affected
	i.Solutions = tmp.Solutions
	i.Tags = tmp.Tags
	i.Classification = tmp.Classification
	i.Created = tmp.Created

	i.Requires = normalizeRequires(tmp.Requires)
	i.RequiresMode = firstNonEmpty(tmp.RequiresMode, tmp.RequiresMode2, tmp.RequiresMode3)
	return nil
}

func normalizeRequires(v any) []string {
	if v == nil {
		return nil
	}
	out := make([]string, 0)
	switch vv := v.(type) {
	case string:
		s := strings.TrimSpace(vv)
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		for _, p := range parts {
			pp := strings.ToLower(strings.TrimSpace(p))
			if pp == "" {
				continue
			}
			out = append(out, pp)
		}
	case []any:
		for _, it := range vv {
			ss, ok := it.(string)
			if !ok {
				continue
			}
			ss = strings.ToLower(strings.TrimSpace(ss))
			if ss == "" {
				continue
			}
			out = append(out, ss)
		}
	default:
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	dedup := out[:0]
	var prev string
	for _, s := range out {
		if s == prev {
			continue
		}
		dedup = append(dedup, s)
		prev = s
	}
	if len(dedup) == 0 {
		return nil
	}
	return append([]string(nil), dedup...)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

type Classification struct {
	CvssMetrics string  `yaml:"cvss-metrics"`
	CvssScore   float64 `yaml:"cvss-score"`
	CveId       string  `yaml:"cve-id"`
	CweId       string  `yaml:"cwe-id"`
}

const DefaultLocalPocDirectory = "pocs"

var (
	LocalFileList    []string
	LocalAppendList  []string
	LocalTestList    []string
	LocalCuratedList []string
	LocalMyList      []string
)
var LocalPocDirectory string

func init() {
	LocalPocDirectory, _ = InitPocHomeDirectory()
	LocalFileList, _ = LocalWalkFiles(LocalPocDirectory)

	// 确保在启动时创建用户目录下的 afrog-curated-pocs 和 afrog-my-pocs
	EnsureCuratedAndMyPocDirectories()

	// 初始化 curated 和 my pocs 列表
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".config", "afrog")

	// 优先检查环境变量 AFROG_POCS_CURATED_DIR
	curatedDir := os.Getenv("AFROG_POCS_CURATED_DIR")
	if curatedDir == "" {
		curatedDir = filepath.Join(configDir, "pocs-curated")
	}
	LocalCuratedList, _ = LocalWalkFiles(curatedDir)

	LocalMyList, _ = LocalWalkFiles(filepath.Join(configDir, "pocs-my"))
}

func InitLocalAppendList(pathFolder []string) {
	if len(pathFolder) == 0 {
		return
	}

	for _, path := range pathFolder {
		if f, err := LocalWalkFiles(path); err == nil {
			LocalAppendList = append(LocalAppendList, f...)
		}
	}
}

func InitLocalTestList(pathFolder []string) {
	if len(pathFolder) == 0 {
		return
	}

	for _, path := range pathFolder {
		if f, err := LocalWalkFiles(path); err == nil {
			LocalTestList = append(LocalTestList, f...)
		}
	}
}

func LocalReadContentByName(name string) ([]byte, error) {
	var (
		err    error
		result []byte
	)

	if len(LocalFileList) == 0 && len(LocalAppendList) == 0 && len(LocalCuratedList) == 0 && len(LocalMyList) == 0 {
		return nil, fmt.Errorf("local file list is empty")
	}

	for _, file := range LocalFileList {
		file = strings.ReplaceAll(file, "\\", "/")
		lastSlashIndex := strings.LastIndex(file, "/")
		if lastSlashIndex != -1 {
			fname := file[lastSlashIndex+1:]
			if name == fname || name+".yaml" == fname || name+".yml" == fname {
				return os.ReadFile(file)
			}
		}
	}

	if len(LocalAppendList) > 0 {
		for _, file := range LocalAppendList {
			file = strings.ReplaceAll(file, "\\", "/")
			lastSlashIndex := strings.LastIndex(file, "/")
			if lastSlashIndex != -1 {
				fname := file[lastSlashIndex+1:]
				if name == fname || name+".yaml" == fname || name+".yml" == fname {
					return os.ReadFile(file)
				}
			}
		}
	}

	if len(LocalCuratedList) > 0 {
		for _, file := range LocalCuratedList {
			file = strings.ReplaceAll(file, "\\", "/")
			lastSlashIndex := strings.LastIndex(file, "/")
			if lastSlashIndex != -1 {
				fname := file[lastSlashIndex+1:]
				if name == fname || name+".yaml" == fname || name+".yml" == fname {
					return os.ReadFile(file)
				}
			}
		}
	}

	if len(LocalMyList) > 0 {
		for _, file := range LocalMyList {
			file = strings.ReplaceAll(file, "\\", "/")
			lastSlashIndex := strings.LastIndex(file, "/")
			if lastSlashIndex != -1 {
				fname := file[lastSlashIndex+1:]
				if name == fname || name+".yaml" == fname || name+".yml" == fname {
					return os.ReadFile(file)
				}
			}
		}
	}

	return result, err
}

// Initialize afrog-pocs directory
// @return pocsDir {{UserHomeDir}}/afrog-pocs
func InitPocHomeDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".config", "afrog")
	_ = os.MkdirAll(configDir, 0755)
	pocsDir := filepath.Join(configDir, DefaultLocalPocDirectory)
	if _, err := os.Stat(pocsDir); err != nil {
		_ = os.MkdirAll(pocsDir, 0755)
	}
	return pocsDir, nil
}

func GetPocVersionNumber() (string, error) {
	version := LocalPocDirectory + "/version"
	v, err := utils.ReadFromFile(version)
	if err != nil {
		return "0", nil
	}
	return strings.TrimSpace(string(v)), nil
}

func LocalWalkFiles(folderPath string) ([]string, error) {
	fileList := []string{}
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 检查是否为文件且以 .yaml 或 .yml 扩展名结尾
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			fileList = append(fileList, path)
		}

		return nil
	})

	return fileList, err
}

// Read a poc yaml file from disk.
// `pocYaml` is a poc yaml file of absolute path.
func LocalReadPocByPath(pocYaml string) (Poc, error) {
	var poc = Poc{}

	file, err := os.Open(pocYaml)
	if err != nil {
		return poc, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&poc); err != nil {
		return poc, err
	}
	return poc, nil
}

func (r *Rule) UnmarshalYAML(unmarshal func(any) error) error {
	var tmp ruleAlias
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	r.Brute = tmp.Brute
	r.Request = tmp.Request
	r.Expression = tmp.Expression
	r.Expressions = append(r.Expressions, tmp.Expressions...)
	r.Output = tmp.Output
	r.Extractors = append(r.Extractors, tmp.Extractors...)
	r.StopIfMatch = tmp.StopIfMatch
	r.StopIfMismatch = tmp.StopIfMismatch
	r.BeforeSleep = tmp.BeforeSleep
	r.order = order

	order += 1
	return nil
}

func (m *RuleMapSlice) UnmarshalYAML(unmarshal func(any) error) error {
	order = 0

	tempMap := make(map[string]Rule, 1)
	if err := unmarshal(&tempMap); err != nil {
		return err
	}

	type pair struct {
		name string
		rule Rule
	}
	arr := make([]pair, 0, len(tempMap))
	for name, rule := range tempMap {
		arr = append(arr, pair{name: name, rule: rule})
	}

	sort.Slice(arr, func(i, j int) bool { return arr[i].rule.order < arr[j].rule.order })

	newRuleSlice := make([]RuleMap, 0, len(arr))
	for _, p := range arr {
		newRuleSlice = append(newRuleSlice, RuleMap{Key: p.name, Value: p.rule})
	}

	*m = RuleMapSlice(newRuleSlice)
	return nil
}

func (poc *Poc) Reset() {
	poc.Id = ""
	poc.Transport = ""
	poc.Set = nil
	poc.Payloads = Payloads{}
	poc.Rules = nil
	poc.Expression = ""
	poc.Info = Info{}
}

func (poc *Poc) IsHTTPType() bool {
	for _, rule := range poc.Rules {
		reqType := rule.Value.Request.Type
		if len(reqType) == 0 || reqType == HTTP_Type || reqType == HTTPS_Type {
			return true
		}
	}
	return false
}

func (poc *Poc) IsReverse() bool {
	// ... existing code ...
	for _, set := range poc.Set {
		k := set.Key.(string)
		vStr, ok := set.Value.(string)
		if !ok {
			// 值不是字符串时无需参与反连判断，直接跳过
			continue
		}
		if strings.Contains(k, "reverse") || strings.Contains(vStr, "reverse.url") {
			return true
		}
	}

	return false
}

// IsNetOnly returns true if the PoC only has network-layer rules (TCP/UDP/SSL)
// and no HTTP, HTTPS, or Go-based rules.
func (poc *Poc) IsNetOnly() bool {
	hasHTTP := false
	hasNet := false
	hasGo := false
	for _, rm := range poc.Rules {
		t := strings.ToLower(strings.TrimSpace(rm.Value.Request.Type))
		switch t {
		case "", HTTP_Type, HTTPS_Type:
			hasHTTP = true
		case TCP_Type, UDP_Type, SSL_Type:
			hasNet = true
		case GO_Type:
			hasGo = true
		default:
			hasHTTP = true
		}
	}
	if hasGo {
		return false
	}
	return hasNet && !hasHTTP
}

type Extractors struct {
	Type      string        `yaml:"type"`      // regex,str
	Extractor yaml.MapSlice `yaml:"extractor"` //
}

// FindPocYamlById 通过POC ID查找原始YAML内容
// 优先从embed POC中查找，然后从local POC中查找
// 添加函数类型定义用于回调
type EmbedPocFinderFunc func(pocId string) ([]byte, error)

// 全局变量存储embed poc查找函数
var embedPocFinder EmbedPocFinderFunc

// 设置embed poc查找函数
func SetEmbedPocFinder(finder EmbedPocFinderFunc) {
	embedPocFinder = finder
}

func FindPocYamlById(pocId string) ([]byte, error) {
	// 首先尝试从embed POC中查找
	if embedPocFinder != nil {
		if content, err := embedPocFinder(pocId); err == nil {
			return content, nil
		}
	}

	// 然后尝试从本地POC中查找
	return findLocalPocById(pocId)
}

func findLocalPocById(pocId string) ([]byte, error) {
	// 搜索LocalFileList
	for _, filePath := range LocalFileList {
		if poc, err := LocalReadPocByPath(filePath); err == nil {
			if poc.Id == pocId {
				return os.ReadFile(filePath)
			}
		}
	}

	// 搜索LocalAppendList
	for _, filePath := range LocalAppendList {
		if poc, err := LocalReadPocByPath(filePath); err == nil {
			if poc.Id == pocId {
				return os.ReadFile(filePath)
			}
		}
	}

	return nil, fmt.Errorf("local poc with id '%s' not found", pocId)
}

// getFileNameFromPath 从文件路径中提取文件名
func getFileNameFromPath(filePath string) string {
	lastSlashIndex := strings.LastIndex(filePath, "/")
	if lastSlashIndex != -1 {
		return filePath[lastSlashIndex+1:]
	}
	return filePath
}

// EnsureCuratedAndMyPocDirectories
// 启动时确保在用户家目录下创建 afrog-curated-pocs 和 afrog-my-pocs 两个目录（若不存在则创建）
func EnsureCuratedAndMyPocDirectories() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configDir := filepath.Join(homeDir, ".config", "afrog")
	_ = os.MkdirAll(configDir, 0755)
	dirs := []string{
		filepath.Join(configDir, "pocs-curated"),
		filepath.Join(configDir, "pocs-my"),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			_ = os.MkdirAll(dir, 0755)
		}
	}
}

// 仅解析 POC 元数据，避免解析 rules 触发 RuleMapSlice 的 Unmarshal
type PocMeta struct {
	Id   string `yaml:"id"`
	Info Info   `yaml:"info"`
}

// 从本地路径读取 POC 元数据（不解析 rules）
func LocalReadPocMetaByPath(pocYaml string) (PocMeta, error) {
	var pm PocMeta

	file, err := os.Open(pocYaml)
	if err != nil {
		return pm, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&pm); err != nil {
		return pm, err
	}
	return pm, nil
}

type MigrateReport struct {
	FilesSeen    int
	FilesChanged int
	Changes      int
}

func MigrateLegacyPocs(root string) (MigrateReport, error) {
	r := MigrateReport{}
	root = strings.TrimSpace(root)
	if root == "" {
		return r, fmt.Errorf("missing -pocmigrate")
	}

	root = filepath.Clean(root)
	if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != "" {
		root = resolved
	}
	fi, err := os.Stat(root)
	if err != nil {
		return r, err
	}

	if !fi.IsDir() {
		changed, n, err := migrateFile(root)
		if err != nil {
			return r, err
		}
		r.FilesSeen++
		if changed {
			r.FilesChanged++
			r.Changes += n
		}
		return r, nil
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		low := strings.ToLower(d.Name())
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			return nil
		}
		changed, n, err := migrateFile(path)
		if err != nil {
			return err
		}
		r.FilesSeen++
		if changed {
			r.FilesChanged++
			r.Changes += n
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	return r, nil
}

var (
	reOobWaitObjCall         = regexp.MustCompile(`\boobWait\s*\(\s*oob\s*,\s*`)
	reOobCheckObjCall        = regexp.MustCompile(`\boobCheck\s*\(\s*oob\s*,\s*`)
	reOobCheckTokenObjCall   = regexp.MustCompile(`\boobCheckToken\s*\(\s*oob\s*,\s*`)
	reOobCheckLeadSpace      = regexp.MustCompile(`\boobCheck\s*\(\s+`)
	reOobCheckTokenLeadSpace = regexp.MustCompile(`\boobCheckToken\s*\(\s+`)
	reOobDNSTpl              = regexp.MustCompile(`\{\{\s*oobDNS\s*\}\}`)
	reOobHTTPTpl             = regexp.MustCompile(`\{\{\s*oobHTTP\s*\}\}`)
	reOobFilterTpl           = regexp.MustCompile(`\{\{\s*oobFilter\s*\}\}`)

	reWordOobDNS    = regexp.MustCompile(`\boobDNS\b`)
	reWordOobHTTP   = regexp.MustCompile(`\boobHTTP\b`)
	reWordOobFilter = regexp.MustCompile(`\boobFilter\b`)
)

func migrateFile(path string) (changed bool, changes int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, 0, err
	}
	orig := string(b)
	s := orig

	if reOobWaitObjCall.MatchString(s) {
		s2 := reOobWaitObjCall.ReplaceAllString(s, "oobCheck(")
		if s2 != s {
			changes++
			s = s2
		}
	}
	if reOobCheckObjCall.MatchString(s) {
		s2 := reOobCheckObjCall.ReplaceAllString(s, "oobCheck(")
		if s2 != s {
			changes++
			s = s2
		}
	}
	if reOobCheckTokenObjCall.MatchString(s) {
		s2 := reOobCheckTokenObjCall.ReplaceAllString(s, "oobCheckToken(")
		if s2 != s {
			changes++
			s = s2
		}
	}
	if reOobCheckLeadSpace.MatchString(s) {
		s2 := reOobCheckLeadSpace.ReplaceAllString(s, "oobCheck(")
		if s2 != s {
			changes++
			s = s2
		}
	}
	if reOobCheckTokenLeadSpace.MatchString(s) {
		s2 := reOobCheckTokenLeadSpace.ReplaceAllString(s, "oobCheckToken(")
		if s2 != s {
			changes++
			s = s2
		}
	}

	s = replaceTpl(&changes, s, reOobDNSTpl, "{{oob.DNS}}")
	s = replaceTpl(&changes, s, reOobHTTPTpl, "{{oob.HTTP}}")
	s = replaceTpl(&changes, s, reOobFilterTpl, "{{oob.Filter}}")

	s = replaceWord(&changes, s, reWordOobDNS, "oob.DNS")
	s = replaceWord(&changes, s, reWordOobHTTP, "oob.HTTP")
	s = replaceWord(&changes, s, reWordOobFilter, "oob.Filter")

	s2, n := stripLegacyOOBSet(s)
	if n > 0 {
		changes += n
		s = s2
	}

	if s == orig {
		return false, 0, nil
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		return false, 0, err
	}
	return true, changes, nil
}

func replaceTpl(changes *int, s string, re *regexp.Regexp, repl string) string {
	if !re.MatchString(s) {
		return s
	}
	out := re.ReplaceAllString(s, repl)
	if out != s {
		*changes++
	}
	return out
}

func replaceWord(changes *int, s string, re *regexp.Regexp, repl string) string {
	if !re.MatchString(s) {
		return s
	}
	out := re.ReplaceAllString(s, repl)
	if out != s {
		*changes++
	}
	return out
}

func stripLegacyOOBSet(s string) (string, int) {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	changes := 0

	inSet := false
	setIndent := ""
	setStartIdx := -1
	setOutStartIdx := -1
	keptNonEmpty := false

	flushSet := func() {
		if setStartIdx == -1 {
			return
		}
		if !keptNonEmpty {
			if setOutStartIdx >= 0 && setOutStartIdx < len(out) {
				out = append(out[:setOutStartIdx], out[setOutStartIdx+1:]...)
				changes++
			}
		}
		inSet = false
		setIndent = ""
		setStartIdx = -1
		setOutStartIdx = -1
		keptNonEmpty = false
	}

	isLegacyOOBSetLine := func(l string) bool {
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "#") {
			return false
		}
		key, _, ok := strings.Cut(trim, ":")
		if !ok {
			return false
		}
		key = strings.TrimSpace(key)
		val := strings.TrimSpace(strings.TrimPrefix(trim, key+":"))
		switch key {
		case "oob":
			return val == "oob()"
		case "oobDNS":
			return val == "oob.DNS"
		case "oobHTTP":
			return val == "oob.HTTP"
		case "oobFilter":
			return val == "oob.Filter"
		case "oob.DNS":
			return val == "oob.DNS"
		case "oob.HTTP":
			return val == "oob.HTTP"
		case "oob.Filter":
			return val == "oob.Filter"
		default:
			return false
		}
	}

	for _, l := range lines {
		if !inSet {
			if strings.HasPrefix(l, "set:") || strings.HasPrefix(l, "set: ") {
				inSet = true
				setIndent = ""
				setStartIdx = len(out)
				setOutStartIdx = len(out)
				keptNonEmpty = false
				out = append(out, l)
				continue
			}
			out = append(out, l)
			continue
		}

		if setIndent == "" {
			if strings.TrimSpace(l) == "" {
				out = append(out, l)
				continue
			}
			prefix := leadingSpaces(l)
			if prefix == "" {
				flushSet()
				out = append(out, l)
				continue
			}
			setIndent = prefix
		}

		if strings.TrimSpace(l) == "" {
			out = append(out, l)
			continue
		}

		if !strings.HasPrefix(l, setIndent) {
			flushSet()
			out = append(out, l)
			continue
		}

		if isLegacyOOBSetLine(l) {
			changes++
			continue
		}

		keptNonEmpty = true
		out = append(out, l)
	}
	flushSet()

	return strings.Join(out, "\n"), changes
}

func leadingSpaces(s string) string {
	i := 0
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return s[:i]
}
