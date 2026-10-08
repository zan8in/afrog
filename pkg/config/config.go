package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"gopkg.in/yaml.v2"
)

// Config is a afrog-config.yaml catalog helper implementation
type Config struct {
	ServerAddress string     `yaml:"server"`
	Reverse       Reverse    `yaml:"reverse"`
	Webhook       Webhook    `yaml:"webhook"`
	Cyberspace    Cyberspace `yaml:"cyberspace"`
	Curated       Curated    `yaml:"curated"`
	Cluster       Cluster    `yaml:"cluster"`
	AI            AI         `yaml:"ai"`
}

// AI 是「AI 辅助」的模型接入配置。
//
// 只实现 OpenAI 兼容的 chat completions 协议（POST {base_url}/chat/completions），
// 所以换供应商只需要改 base_url 与 model：OpenAI / DeepSeek / 通义 / one-api /
// 本地 Ollama 都走这一套。三项（base_url、model、api_key）缺任意一项即视为未配置，
// 界面会引导去补齐，而不是报一个看不懂的错。
type AI struct {
	BaseURL    string `yaml:"base_url"`
	Model      string `yaml:"model"`
	APIKey     string `yaml:"api_key"`
	TimeoutSec int    `yaml:"timeout_sec"`
	MaxTokens  int    `yaml:"max_tokens"`
}

// Cluster 是多实例编排（Web 控制台）的配置。
//
// 只在需要「一个控制台同时看多个 afrog 实例」时配置：把自己的名字写进 name，
// 给同一批实例配同一个 token（集群内互访凭证），再把同伴的地址登记进 peers。
// 留空即单实例，Web 控制台照常工作。
type Cluster struct {
	Name  string        `yaml:"name"`
	Token string        `yaml:"token"`
	Peers []ClusterPeer `yaml:"peers"`
}

// ClusterPeer 是一个同伴实例：name 只用于展示，url 指向它的 Web 控制台地址。
type ClusterPeer struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type Curated struct {
	Enabled    string `yaml:"enabled"`
	AutoUpdate *bool  `yaml:"auto_update"`
	Endpoint   string `yaml:"endpoint"`
	Bin        string `yaml:"bin,omitempty"`
	TimeoutSec int    `yaml:"timeout_sec"`
	Channel    string `yaml:"channel"`
	LicenseKey string `yaml:"license_key"`
}
type ConfigHttp struct {
	Proxy               string `yaml:"proxy"`
	DialTimeout         int32  `yaml:"dial_timeout"`
	ReadTimeout         string `yaml:"read_timeout"`
	WriteTimeout        string `yaml:"write_timeout"`
	MaxRedirect         int32  `yaml:"max_redirect"`
	MaxIdle             string `yaml:"max_idle"`
	Concurrency         int    `yaml:"concurrency"`
	MaxConnsPerHost     int    `yaml:"max_conns_per_host"`
	MaxResponseBodySize int    `yaml:"max_responsebody_sizse"`
	UserAgent           string `yaml:"user_agent"`
}

type Webhook struct {
	Dingtalk Dingtalk `yaml:"dingtalk"`
	Wecom    Wecom    `yaml:"wecom"`
}

type Wecom struct {
	Tokens    []string `yaml:"tokens"`
	AtMobiles []string `yaml:"at_mobiles"`
	AtAll     bool     `yaml:"at_all"`
	Range     string   `yaml:"range"`
	Markdown  bool     `yaml:"markdown"`
}

type Dingtalk struct {
	Tokens    []string `yaml:"tokens"`
	AtMobiles []string `yaml:"at_mobiles"`
	AtAll     bool     `yaml:"at_all"`
	Range     string   `yaml:"range"`
}

type Reverse struct {
	Alphalog   Alphalog   `yaml:"alphalog"`
	Ceye       Ceye       `yaml:"ceye"`
	Dnslogcn   Dnslogcn   `yaml:"dnslogcn"`
	Eye        Eye        `yaml:"eye"`
	Interactsh Interactsh `yaml:"interactsh"`
	Jndi       Jndi       `yaml:"jndi"`
	Xray       Xray       `yaml:"xray"`
	Revsuit    Revsuit    `yaml:"revsuit"`
}

type Ceye struct {
	ApiKey string `yaml:"api-key"`
	Domain string `yaml:"domain"`
}

type Dnslogcn struct {
	Domain string `yaml:"domain"`
}

type Eye struct {
	Host   string `yaml:"host"`
	Token  string `yaml:"token"`
	Domain string `yaml:"domain"`
}

type Alphalog struct {
	Domain string `yaml:"domain"`
	ApiUrl string `yaml:"api_url"`
}

type Xray struct {
	XToken string `yaml:"x_token"`
	Domain string `yaml:"domain"`
	ApiUrl string `yaml:"api_url"`
}

type Revsuit struct {
	Token     string `yaml:"token"`
	DnsDomain string `yaml:"dns_domain"`
	HttpUrl   string `yaml:"http_url"`
	ApiUrl    string `yaml:"api_url"`
}

type Interactsh struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
}

type Jndi struct {
	JndiAddress string `yaml:"jndi_address"`
	LdapPort    string `yaml:"ldap_port"`
	ApiPort     string `yaml:"api_port"`
}

type Cyberspace struct {
	ZoomEyes []string `yaml:"zoom_eyes"`
}

const afrogConfigFilename = "afrog-config.yaml"

// Create and initialize afrog-config.yaml configuration info
func NewConfig(configFile string) (*Config, error) {
	if len(configFile) > 0 && !strings.HasSuffix(configFile, ".yml") && !strings.HasSuffix(configFile, ".yaml") {
		return nil, errors.New("afrog config file must be yaml format")
	}
	if isExistConfigFile(configFile) != nil {
		c := Config{}
		c.ServerAddress = ":16868"

		reverse := c.Reverse

		// alphalog
		reverse.Alphalog.Domain = ""
		reverse.Alphalog.ApiUrl = ""

		// ceye
		reverse.Ceye.ApiKey = ""
		reverse.Ceye.Domain = ""

		// dnslogcn
		reverse.Dnslogcn.Domain = "dnslog.cn"

		// eyes.sh
		reverse.Eye.Host = ""
		reverse.Eye.Domain = ""
		reverse.Eye.Token = ""

		// jndi
		reverse.Jndi.JndiAddress = ""
		reverse.Jndi.LdapPort = ""
		reverse.Jndi.ApiPort = ""

		// xray
		reverse.Xray.XToken = ""
		reverse.Xray.Domain = ""
		reverse.Xray.ApiUrl = "http://x.x.x.x:8777"

		// revsuit
		reverse.Revsuit.Token = ""
		reverse.Revsuit.DnsDomain = ""
		reverse.Revsuit.HttpUrl = ""
		reverse.Revsuit.ApiUrl = ""

		// interactsh
		reverse.Interactsh.Server = "oast.pro"
		reverse.Interactsh.Token = ""

		c.Reverse = reverse

		webhook := c.Webhook
		webhook.Dingtalk.Tokens = []string{""}
		webhook.Dingtalk.AtMobiles = []string{""}
		webhook.Dingtalk.AtAll = false
		webhook.Dingtalk.Range = "high,critical"

		webhook.Wecom.Tokens = []string{""}
		webhook.Wecom.AtMobiles = []string{""}
		webhook.Wecom.AtAll = false
		webhook.Wecom.Range = "high,critical"
		webhook.Wecom.Markdown = true

		c.Webhook = webhook

		cyberspace := c.Cyberspace
		cyberspace.ZoomEyes = []string{""}
		c.Cyberspace = cyberspace

		curated := c.Curated
		curated.Enabled = "auto"
		au := true
		curated.AutoUpdate = &au
		curated.Endpoint = ""
		curated.TimeoutSec = 10
		curated.Channel = "stable"
		curated.LicenseKey = ""
		c.Curated = curated

		WriteConfiguration(&c, configFile)
	}
	return ReadConfiguration(configFile)
}

// LoadConfigReadOnly loads the afrog configuration without touching the filesystem.
//
// Unlike [NewConfig], it never creates ~/.config/afrog, never writes
// afrog-config.yaml, and never rewrites an existing user config to inject new
// sections. Library consumers must not have side effects on the host's home
// directory merely by constructing a scanner, so the SDK uses this instead.
//
// When no configuration file exists, it returns a Config populated with the
// same defaults NewConfig would have written.
func LoadConfigReadOnly(configFile string) (*Config, error) {
	if len(configFile) > 0 && !strings.HasSuffix(configFile, ".yml") && !strings.HasSuffix(configFile, ".yaml") {
		return nil, errors.New("afrog config file must be yaml format")
	}

	path := configFile
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return defaultConfig(), nil
		}
		path = filepath.Join(homeDir, ".config", "afrog", afrogConfigFilename)
	}

	file, err := os.Open(path)
	if err != nil {
		if configFile != "" {
			return nil, err
		}
		return defaultConfig(), nil
	}
	defer file.Close()

	config := &Config{}
	if err := yaml.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	normalizeCuratedDefaults(config)
	normalizeInteractshDefaults(config)
	return config, nil
}

// defaultConfig returns the built-in configuration defaults.
func defaultConfig() *Config {
	c := &Config{ServerAddress: ":16868"}

	c.Reverse.Dnslogcn.Domain = "dnslog.cn"
	c.Reverse.Xray.ApiUrl = "http://x.x.x.x:8777"
	c.Reverse.Interactsh.Server = "oast.pro"

	c.Webhook.Dingtalk.Range = "high,critical"
	c.Webhook.Wecom.Range = "high,critical"
	c.Webhook.Wecom.Markdown = true

	autoUpdate := true
	c.Curated.Enabled = "auto"
	c.Curated.AutoUpdate = &autoUpdate
	c.Curated.TimeoutSec = 10
	c.Curated.Channel = "stable"

	return c
}

func isExistConfigFile(configFile string) error {
	if len(configFile) > 0 {
		if utils.Exists(configFile) {
			return nil
		}
		return errors.New("could not get config file")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return errors.Wrap(err, "could not get home directory")
	}

	configFile = filepath.Join(homeDir, ".config", "afrog", afrogConfigFilename)
	if utils.Exists(configFile) {
		return nil
	}

	return errors.New("could not get config file")
}

func (c *Config) GetConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	configFile := filepath.Join(homeDir, ".config", "afrog", afrogConfigFilename)
	if !utils.Exists(configFile) {
		return configFile
	}
	return configFile
}

func getConfigFile() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "could not get home directory")
	}

	configDir := filepath.Join(homeDir, ".config", "afrog")
	_ = os.MkdirAll(configDir, 0755)

	afrogConfigFile := filepath.Join(configDir, afrogConfigFilename)
	return afrogConfigFile, nil
}

// DefaultConfigPath 返回默认配置文件路径：~/.config/afrog/afrog-config.yaml。
// 未显式指定 -config 时，写回配置就落在这里。
func DefaultConfigPath() string {
	p, err := getConfigFile()
	if err != nil {
		return ""
	}
	return p
}

// ReadConfiguration reads the afrog configuration file from disk.
func ReadConfiguration(configFile string) (*Config, error) {
	var afrogConfigFile string
	var err error
	if len(configFile) > 0 {
		afrogConfigFile = configFile
	} else {
		afrogConfigFile, err = getConfigFile()
		if err != nil {
			return nil, err
		}
	}

	file, err := os.Open(afrogConfigFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	if err := yaml.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	normalizeCuratedDefaults(config)
	normalizeInteractshDefaults(config)
	normalizeAIDefaults(config)
	_ = ensureCuratedSection(afrogConfigFile, config.Curated)
	_ = ensureInteractshSection(afrogConfigFile, config.Reverse.Interactsh)
	return config, nil
}

func normalizeCuratedDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	enabled := strings.ToLower(strings.TrimSpace(cfg.Curated.Enabled))
	switch enabled {
	case "auto", "true", "false", "on", "off", "1", "0":
	default:
		enabled = "auto"
	}
	cfg.Curated.Enabled = enabled
	if cfg.Curated.TimeoutSec <= 0 {
		cfg.Curated.TimeoutSec = 10
	}
	if strings.TrimSpace(cfg.Curated.Channel) == "" {
		cfg.Curated.Channel = "stable"
	}
	if enabled == "off" || enabled == "false" || enabled == "0" {
		return
	}
	if cfg.Curated.AutoUpdate == nil {
		au := true
		cfg.Curated.AutoUpdate = &au
	}
}

func normalizeInteractshDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	s := strings.TrimSpace(cfg.Reverse.Interactsh.Server)
	if s == "" {
		s = "oast.pro"
	}
	cfg.Reverse.Interactsh.Server = s
}

// normalizeAIDefaults 归一化 AI 配置：地址去掉结尾斜杠（拼 /chat/completions 时不能再多一条），
// 兜底超时与输出上限。三项连接信息保持原样——空即「未配置」，由界面引导补齐。
func normalizeAIDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.AI.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.AI.BaseURL), "/")
	cfg.AI.Model = strings.TrimSpace(cfg.AI.Model)
	cfg.AI.APIKey = strings.TrimSpace(cfg.AI.APIKey)
	if cfg.AI.TimeoutSec <= 0 {
		cfg.AI.TimeoutSec = 60
	}
	if cfg.AI.MaxTokens <= 0 {
		cfg.AI.MaxTokens = 1200
	}
}

func ensureCuratedSection(configPath string, curated Curated) error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	curatedIdx := -1
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if leadingSpaces(line) != 0 {
			continue
		}
		t := strings.TrimSpace(stripYAMLLineComment(line))
		if strings.HasPrefix(t, "curated:") {
			curatedIdx = i
			break
		}
	}

	if curatedIdx == -1 {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, curatedSectionLines(0, curated)...)
		return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
	}

	baseIndent := leadingSpaces(lines[curatedIdx])
	end := len(lines)
	for j := curatedIdx + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if leadingSpaces(lines[j]) <= baseIndent {
			end = j
			break
		}
	}

	childIndent := baseIndent + 2
	present := map[string]bool{}
	for j := curatedIdx + 1; j < end; j++ {
		raw := strings.TrimSpace(stripYAMLLineComment(lines[j]))
		if raw == "" {
			continue
		}
		if leadingSpaces(lines[j]) < childIndent {
			continue
		}
		colon := strings.Index(raw, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(raw[:colon])
		present[key] = true
	}

	insert := curatedKeyLines(childIndent, curated, present)
	if len(insert) == 0 {
		return nil
	}

	out := make([]string, 0, len(lines)+len(insert))
	out = append(out, lines[:end]...)
	out = append(out, insert...)
	out = append(out, lines[end:]...)
	return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644)
}

func ensureInteractshSection(configPath string, interactsh Interactsh) error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	reverseIdx := -1
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if leadingSpaces(line) != 0 {
			continue
		}
		t := strings.TrimSpace(stripYAMLLineComment(line))
		if strings.HasPrefix(t, "reverse:") {
			reverseIdx = i
			break
		}
	}

	if reverseIdx == -1 {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, reverseInteractshSectionLines(0, interactsh)...)
		return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
	}

	baseIndent := leadingSpaces(lines[reverseIdx])
	reverseEnd := len(lines)
	for j := reverseIdx + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if leadingSpaces(lines[j]) <= baseIndent {
			reverseEnd = j
			break
		}
	}

	interactshIdx := -1
	interactshIndent := baseIndent + 2
	for j := reverseIdx + 1; j < reverseEnd; j++ {
		if leadingSpaces(lines[j]) != interactshIndent {
			continue
		}
		t := strings.TrimSpace(stripYAMLLineComment(lines[j]))
		if strings.HasPrefix(t, "interactsh:") {
			interactshIdx = j
			break
		}
	}

	if interactshIdx == -1 {
		insert := interactshSectionLines(interactshIndent, interactsh)
		out := make([]string, 0, len(lines)+len(insert))
		out = append(out, lines[:reverseEnd]...)
		if reverseEnd > 0 && strings.TrimSpace(out[reverseEnd-1]) != "" {
			out = append(out, "")
		}
		out = append(out, insert...)
		out = append(out, lines[reverseEnd:]...)
		return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644)
	}

	interactshEnd := reverseEnd
	for j := interactshIdx + 1; j < reverseEnd; j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if leadingSpaces(lines[j]) <= interactshIndent {
			interactshEnd = j
			break
		}
	}

	childIndent := interactshIndent + 2
	present := map[string]bool{}
	for j := interactshIdx + 1; j < interactshEnd; j++ {
		raw := strings.TrimSpace(stripYAMLLineComment(lines[j]))
		if raw == "" {
			continue
		}
		if leadingSpaces(lines[j]) < childIndent {
			continue
		}
		colon := strings.Index(raw, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(raw[:colon])
		present[key] = true
	}

	insert := interactshKeyLines(childIndent, interactsh, present)
	if len(insert) == 0 {
		return nil
	}

	out := make([]string, 0, len(lines)+len(insert))
	out = append(out, lines[:interactshEnd]...)
	out = append(out, insert...)
	out = append(out, lines[interactshEnd:]...)
	return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644)
}

func reverseInteractshSectionLines(baseIndent int, interactsh Interactsh) []string {
	lines := []string{strings.Repeat(" ", baseIndent) + "reverse:"}
	lines = append(lines, interactshSectionLines(baseIndent+2, interactsh)...)
	return lines
}

func interactshSectionLines(baseIndent int, interactsh Interactsh) []string {
	lines := []string{strings.Repeat(" ", baseIndent) + "interactsh:"}
	return append(lines, interactshKeyLines(baseIndent+2, interactsh, map[string]bool{})...)
}

func interactshKeyLines(indent int, interactsh Interactsh, present map[string]bool) []string {
	prefix := strings.Repeat(" ", indent)
	lines := make([]string, 0, 2)

	server := strings.TrimSpace(interactsh.Server)
	if server == "" {
		server = "oast.pro"
	}
	if !present["server"] {
		lines = append(lines, prefix+"server: "+strconv.Quote(server))
	}
	if !present["token"] {
		lines = append(lines, prefix+"token: "+strconv.Quote(strings.TrimSpace(interactsh.Token)))
	}
	return lines
}

// UpdateCuratedSection 把 curated（会员）段整体写回配置文件，其余段落原样保留。
//
// configPath 为空时回退到默认的 ~/.config/afrog/afrog-config.yaml。
// 该段内的原有注释会被新内容覆盖（与 cluster/ai/reverse 同），段外注释不受影响。
func UpdateCuratedSection(configPath string, curated Curated) error {
	return replaceTopLevelSection(configPath, "curated", curatedSectionLines(0, curated))
}

// UpdateClusterSection 把 cluster 段整体写回配置文件，其余段落原样保留。
//
// configPath 为空时回退到默认的 ~/.config/afrog/afrog-config.yaml。
func UpdateClusterSection(configPath string, cluster Cluster) error {
	return replaceTopLevelSection(configPath, "cluster", clusterSectionLines(0, cluster))
}

// UpdateAISection 把 ai 段整体写回配置文件，其余段落原样保留。
func UpdateAISection(configPath string, ai AI) error {
	return replaceTopLevelSection(configPath, "ai", aiSectionLines(0, ai))
}

// UpdateReverseSection 把 reverse（OOB 带外检测）段整体写回配置文件，
// 其余段落原样保留。界面只编辑常见适配器的凭据，eye/jndi 等未暴露项由调用方
// 从当前配置原样带回，避免被覆盖。
func UpdateReverseSection(configPath string, reverse Reverse) error {
	return replaceTopLevelSection(configPath, "reverse", reverseSectionLines(0, reverse))
}

// replaceTopLevelSection 用 block 整体替换顶层 key 段；文件里没有该段时追加到末尾。
//
// 与 ensureCuratedSection 那种「缺哪个键就补哪个键」的增量写法不同：cluster 的
// peers 是列表、ai 的字段会整体重填，逐行增量反而容易留下半截配置，所以整块替换。
// 代价是该块内原有的注释会被新内容覆盖，块外的注释不受影响。
func replaceTopLevelSection(configPath, key string, block []string) error {
	if strings.TrimSpace(configPath) == "" {
		p, err := getConfigFile()
		if err != nil {
			return err
		}
		configPath = p
	}

	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	keyPrefix := key + ":"
	start := -1
	for i := 0; i < len(lines); i++ {
		if leadingSpaces(lines[i]) != 0 {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(stripYAMLLineComment(lines[i])), keyPrefix) {
			start = i
			break
		}
	}

	if start == -1 {
		out := lines
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, block...)
		return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644)
	}

	baseIndent := leadingSpaces(lines[start])
	end := len(lines)
	for j := start + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if leadingSpaces(lines[j]) <= baseIndent {
			end = j
			break
		}
	}

	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:start]...)
	out = append(out, block...)
	out = append(out, lines[end:]...)
	return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644)
}

// clusterSectionLines 按 afrog-config.yaml 的手写风格生成 cluster 段。
func clusterSectionLines(baseIndent int, cluster Cluster) []string {
	prefix := strings.Repeat(" ", baseIndent)
	lines := []string{
		prefix + "cluster:",
		prefix + "  name: " + strconv.Quote(strings.TrimSpace(cluster.Name)),
		prefix + "  token: " + strconv.Quote(strings.TrimSpace(cluster.Token)),
	}
	if len(cluster.Peers) == 0 {
		return append(lines, prefix+"  peers: []")
	}
	lines = append(lines, prefix+"  peers:")
	for _, p := range cluster.Peers {
		lines = append(lines,
			prefix+"    - name: "+strconv.Quote(strings.TrimSpace(p.Name)),
			prefix+"      url: "+strconv.Quote(strings.TrimSpace(p.URL)),
		)
	}
	return lines
}

// aiSectionLines 生成 ai 段。
func aiSectionLines(baseIndent int, ai AI) []string {
	prefix := strings.Repeat(" ", baseIndent)
	return []string{
		prefix + "ai:",
		prefix + "  base_url: " + strconv.Quote(strings.TrimRight(strings.TrimSpace(ai.BaseURL), "/")),
		prefix + "  model: " + strconv.Quote(strings.TrimSpace(ai.Model)),
		prefix + "  api_key: " + strconv.Quote(strings.TrimSpace(ai.APIKey)),
		prefix + "  timeout_sec: " + strconv.Itoa(ai.TimeoutSec),
		prefix + "  max_tokens: " + strconv.Itoa(ai.MaxTokens),
	}
}

// reverseSectionLines 按 afrog-config.yaml 的手写风格生成 reverse 段。
//
// 覆盖全部子段：界面可编辑的适配器（alphalog/ceye/dnslogcn/interactsh/xray/revsuit）
// 以及不暴露但需保留的 eye/jndi。键名必须与结构体 yaml tag 一致。
func reverseSectionLines(baseIndent int, r Reverse) []string {
	prefix := strings.Repeat(" ", baseIndent)
	q := strconv.Quote
	trim := strings.TrimSpace

	interactshServer := trim(r.Interactsh.Server)
	if interactshServer == "" {
		interactshServer = "oast.pro"
	}

	return []string{
		prefix + "reverse:",
		prefix + "  alphalog:",
		prefix + "    domain: " + q(trim(r.Alphalog.Domain)),
		prefix + "    api_url: " + q(trim(r.Alphalog.ApiUrl)),
		prefix + "  ceye:",
		prefix + "    api-key: " + q(trim(r.Ceye.ApiKey)),
		prefix + "    domain: " + q(trim(r.Ceye.Domain)),
		prefix + "  dnslogcn:",
		prefix + "    domain: " + q(trim(r.Dnslogcn.Domain)),
		prefix + "  eye:",
		prefix + "    host: " + q(trim(r.Eye.Host)),
		prefix + "    token: " + q(trim(r.Eye.Token)),
		prefix + "    domain: " + q(trim(r.Eye.Domain)),
		prefix + "  interactsh:",
		prefix + "    server: " + q(interactshServer),
		prefix + "    token: " + q(trim(r.Interactsh.Token)),
		prefix + "  jndi:",
		prefix + "    jndi_address: " + q(trim(r.Jndi.JndiAddress)),
		prefix + "    ldap_port: " + q(trim(r.Jndi.LdapPort)),
		prefix + "    api_port: " + q(trim(r.Jndi.ApiPort)),
		prefix + "  xray:",
		prefix + "    x_token: " + q(trim(r.Xray.XToken)),
		prefix + "    domain: " + q(trim(r.Xray.Domain)),
		prefix + "    api_url: " + q(trim(r.Xray.ApiUrl)),
		prefix + "  revsuit:",
		prefix + "    token: " + q(trim(r.Revsuit.Token)),
		prefix + "    dns_domain: " + q(trim(r.Revsuit.DnsDomain)),
		prefix + "    http_url: " + q(trim(r.Revsuit.HttpUrl)),
		prefix + "    api_url: " + q(trim(r.Revsuit.ApiUrl)),
	}
}

func curatedSectionLines(baseIndent int, curated Curated) []string {
	lines := []string{strings.Repeat(" ", baseIndent) + "curated:"}
	return append(lines, curatedKeyLines(baseIndent+2, curated, map[string]bool{})...)
}

func curatedKeyLines(indent int, curated Curated, present map[string]bool) []string {
	prefix := strings.Repeat(" ", indent)
	lines := make([]string, 0, 6)

	if !present["enabled"] {
		lines = append(lines, prefix+"enabled: "+strconv.Quote(curated.Enabled))
	}
	if !present["auto_update"] {
		val := true
		if curated.AutoUpdate != nil {
			val = *curated.AutoUpdate
		}
		if val {
			lines = append(lines, prefix+"auto_update: true")
		} else {
			lines = append(lines, prefix+"auto_update: false")
		}
	}
	if !present["endpoint"] {
		lines = append(lines, prefix+"endpoint: "+strconv.Quote(strings.TrimSpace(curated.Endpoint)))
	}
	if !present["timeout_sec"] {
		lines = append(lines, prefix+"timeout_sec: "+strconv.Itoa(curated.TimeoutSec))
	}
	if !present["channel"] {
		lines = append(lines, prefix+"channel: "+strconv.Quote(strings.TrimSpace(curated.Channel)))
	}
	if !present["license_key"] {
		lines = append(lines, prefix+"license_key: "+strconv.Quote(strings.TrimSpace(curated.LicenseKey)))
	}
	return lines
}

func stripYAMLLineComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// WriteConfiguration writes the updated afrog configuration to disk
func WriteConfiguration(config *Config, configFile string) error {
	var afrogConfigFile string
	var err error
	if len(configFile) > 0 {
		afrogConfigFile = configFile
	} else {
		afrogConfigFile, err = getConfigFile()
		if err != nil {
			return err
		}
	}

	afrogConfigYAML, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}

	// afrogConfigFile, err = getConfigFile()
	// if err != nil {
	// 	return err
	// }

	file, err := os.OpenFile(afrogConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(afrogConfigYAML); err != nil {
		return err
	}
	return nil
}
