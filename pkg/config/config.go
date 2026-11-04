package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/v3/pkg/passive"
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
	Passive       Passive    `yaml:"passive"`
}

// 被动扫描的默认参数。
const (
	// DefaultPassiveHost 只监听回环地址：被动代理需要安装根证书，
	// 暴露到公网等同于把任意流量的解密能力开放给他人。
	DefaultPassiveHost = "127.0.0.1"
	DefaultPassivePort = 16869
	// DefaultPassiveMaxRPS 是重放请求的全局速率上限，保守取 100/s。
	DefaultPassiveMaxRPS = 100
	// DefaultPassiveHostConcurrency 是单目标并发上限。
	DefaultPassiveHostConcurrency = 4
	// DefaultPassiveWorkers 是门控池并发处理事务的 worker 数。
	//
	// 门控池只负责判定「这条请求要不要检测」，纯本地计算，因此它决定的是入口吞吐，
	// 而不是对目标的压力。
	DefaultPassiveWorkers = 8
	// DefaultPassiveDetectWorkers 是检测池的 worker 数。
	//
	// 它等于**实际重放并发度**：检测器在一个事务内是串行发请求的，所以同时在飞的
	// 重放请求数就是检测池 worker 数。取 8 是为了不低于 DefaultPassiveHostConcurrency(4)，
	// 否则会白白闲置 Prober 已经允许的并发额度；对目标的真实压力仍由
	// MaxRPS / HostConcurrency 兜底，调大 worker 不等于调大攻击面。
	DefaultPassiveDetectWorkers = 8
	// DefaultPassiveQueueSize 是门控入口队列容量。队列满时新流量直接丢弃（不回压真实业务流量），
	// 因此这个值决定了突发流量能被缓冲多少。
	DefaultPassiveQueueSize = 256
	// DefaultPassiveDetector 是默认启用的检测器。
	DefaultPassiveDetector = "sqli"
)

// DefaultPassiveDetectors 是默认启用的检测器集合。
//
// 除 SQLi 外还默认启用敏感信息提取（extract）：它是**零流量的本地类**提取器，
// 不额外发包、不受注入点短路影响，因此默认开启只增发现能力、不增网络负担。
var DefaultPassiveDetectors = []string{"sqli", "extract"}

// Passive 是内嵌被动扫描（MITM 代理 + 检测器管道）的配置。
//
// 只暴露真正需要使用者决策的项：监听位置、上游代理、检测器开关与流量上限。
// 其余判定参数（相似度阈值、SLEEP 秒数等）属于检测器内部策略，不在此处开放，
// 避免把「调参」变成使用者的负担。
type Passive struct {
	// AutoStart 表示 afrog web 启动时自动开启被动扫描。
	AutoStart bool `yaml:"auto_start"`
	// Host 是监听地址。127.0.0.1 仅本机可用；0.0.0.0 允许局域网与手机接入。
	Host string `yaml:"host"`
	// Port 是监听端口。
	Port int `yaml:"port"`
	// Upstream 是上游代理（如 http://127.0.0.1:8080），为空表示直连目标。
	Upstream string `yaml:"upstream"`
	// Detectors 是启用的检测器列表。
	Detectors []string `yaml:"detectors"`
	// MaxRPS 是重放请求的全局速率上限（请求/秒）。
	MaxRPS int `yaml:"max_rps"`
	// HostConcurrency 是单目标并发上限。
	HostConcurrency int `yaml:"host_concurrency"`
	// Workers 是「门控池」并发处理事务的 worker 数，0 表示用默认值。
	//
	// 门控池只做「这条请求要不要检测」的筛选，属于纯本地计算、几乎不会成为瓶颈；
	// 它的并发决定了入口能吞下多快的流量。
	Workers int `yaml:"workers"`
	// DetectWorkers 是「检测池」的 worker 数，0 表示用默认值。
	//
	// 这才是「检测吞吐」的真正旋钮：检测池执行昂贵且耗时不可控的重放，
	// 一个事务内检测器是串行发请求的，所以并行重放数就等于这个 worker 数。
	// 它同时不低于 HostConcurrency 才不会让 Prober 的并发额度闲置。
	DetectWorkers int `yaml:"detect_workers"`
	// QueueSize 是门控入口队列容量，0 表示用默认值。队列满即丢弃，不回压业务流量。
	QueueSize int `yaml:"queue_size"`
	// ProjectID 是被动命中的归属渗透项目。
	//
	// 命中按 (project_id, fingerprint) 聚合：同一项目内反复命中归到一条并累加次数，
	// 不同项目之间互不去重。为空表示「未归属」——按无项目归档，仍可正常记录。
	ProjectID string `yaml:"project_id"`
	// ScopeHostAllow 是扫描范围的 Host 白名单：非空时只扫描匹配的 Host。
	//
	// 用于把统计、CDN、地图等第三方域名挡在代理层之外——它们没有业务价值，
	// 放进来只会白白消耗检测队列。匹配规则见 passive.Scope。
	ScopeHostAllow []string `yaml:"scope_host_allow"`
	// ScopeHostDeny 是永不扫描的 Host，优先级高于 ScopeHostAllow。
	ScopeHostDeny []string `yaml:"scope_host_deny"`
	// ScopePathDeny 是永不扫描的路径（如 /logout、/pay）。
	ScopePathDeny []string `yaml:"scope_path_deny"`
	// ScanUnsafeMethods 表示是否扫描 PUT / PATCH / DELETE 这类非幂等请求。
	//
	// 默认 false：检测器会把同一请求重放数十次，这些方法会修改或删除业务数据，
	// 在真实业务流量上重放有实际破坏风险。仅在确认端点无副作用时才开启。
	ScanUnsafeMethods bool `yaml:"scan_unsafe_methods"`
}

// Addr 返回 host:port 形式的监听地址。
func (p Passive) Addr() string {
	host := strings.TrimSpace(p.Host)
	if host == "" {
		host = DefaultPassiveHost
	}
	port := p.Port
	if port <= 0 {
		port = DefaultPassivePort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// EnabledDetectors 返回启用的检测器集合。
func (p Passive) EnabledDetectors() []string {
	out := make([]string, 0, len(p.Detectors))
	for _, d := range p.Detectors {
		if v := strings.ToLower(strings.TrimSpace(d)); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultPassiveDetectors...)
	}
	return out
}

// WorkersOrDefault 返回门控池 worker 数，未配置时退回默认值。
func (p Passive) WorkersOrDefault() int {
	if p.Workers > 0 {
		return p.Workers
	}
	return DefaultPassiveWorkers
}

// DetectWorkersOrDefault 返回检测池 worker 数，未配置时退回默认值。
func (p Passive) DetectWorkersOrDefault() int {
	if p.DetectWorkers > 0 {
		return p.DetectWorkers
	}
	return DefaultPassiveDetectWorkers
}

// QueueSizeOrDefault 返回待检队列容量，未配置时退回默认值。
func (p Passive) QueueSizeOrDefault() int {
	if p.QueueSize > 0 {
		return p.QueueSize
	}
	return DefaultPassiveQueueSize
}

// Scope 把范围配置整理成代理层认识的裁剪规则。
//
// 集中在这里转换，代理层与 SDK 就只需认识 passive.Scope 一种结构，
// 新增范围维度时也不会漏改某一个入口。
func (p Passive) Scope() passive.Scope {
	return passive.Scope{
		HostAllow: p.ScopeHostAllow,
		HostDeny:  p.ScopeHostDeny,
		PathDeny:  p.ScopePathDeny,
	}
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

		// 被动扫描：首次生成的配置里就把默认值写全，使用者打开文件即可知道有哪些项。
		c.Passive = Passive{
			AutoStart:       false,
			Host:            DefaultPassiveHost,
			Port:            DefaultPassivePort,
			Upstream:        "",
			Detectors:       append([]string(nil), DefaultPassiveDetectors...),
			MaxRPS:          DefaultPassiveMaxRPS,
			HostConcurrency: DefaultPassiveHostConcurrency,
			Workers:         DefaultPassiveWorkers,
			DetectWorkers:   DefaultPassiveDetectWorkers,
			QueueSize:       DefaultPassiveQueueSize,
			ProjectID:       "",
			ScopeHostAllow:  []string{},
			ScopeHostDeny:   []string{},
			ScopePathDeny:   []string{},
		}

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

	c.Passive = Passive{
		AutoStart:       false,
		Host:            DefaultPassiveHost,
		Port:            DefaultPassivePort,
		Upstream:        "",
		Detectors:       append([]string(nil), DefaultPassiveDetectors...),
		MaxRPS:          DefaultPassiveMaxRPS,
		HostConcurrency: DefaultPassiveHostConcurrency,
		Workers:         DefaultPassiveWorkers,
		DetectWorkers:   DefaultPassiveDetectWorkers,
		QueueSize:       DefaultPassiveQueueSize,
		ProjectID:       "",
	}

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
	normalizePassiveDefaults(config)
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

// normalizePassiveDefaults 为老配置文件补齐 passive 段的默认值。
//
// 老版本的 afrog-config.yaml 里没有这一段，解码后全是零值；如果不补，
// 被动代理会以空地址启动并失败。
func normalizePassiveDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.Passive.Host = strings.TrimSpace(cfg.Passive.Host)
	if cfg.Passive.Host == "" {
		cfg.Passive.Host = DefaultPassiveHost
	}
	if cfg.Passive.Port <= 0 || cfg.Passive.Port > 65535 {
		cfg.Passive.Port = DefaultPassivePort
	}
	cfg.Passive.Upstream = strings.TrimRight(strings.TrimSpace(cfg.Passive.Upstream), "/")
	if cfg.Passive.MaxRPS <= 0 {
		cfg.Passive.MaxRPS = DefaultPassiveMaxRPS
	}
	if cfg.Passive.HostConcurrency <= 0 {
		cfg.Passive.HostConcurrency = DefaultPassiveHostConcurrency
	}
	if cfg.Passive.Workers <= 0 {
		cfg.Passive.Workers = DefaultPassiveWorkers
	}
	if cfg.Passive.DetectWorkers <= 0 {
		cfg.Passive.DetectWorkers = DefaultPassiveDetectWorkers
	}
	if cfg.Passive.QueueSize <= 0 {
		cfg.Passive.QueueSize = DefaultPassiveQueueSize
	}
	if len(cfg.Passive.Detectors) == 0 {
		cfg.Passive.Detectors = append([]string(nil), DefaultPassiveDetectors...)
	}
	cfg.Passive.ProjectID = strings.TrimSpace(cfg.Passive.ProjectID)
	cfg.Passive.ScopeHostAllow = normalizeScopeList(cfg.Passive.ScopeHostAllow)
	cfg.Passive.ScopeHostDeny = normalizeScopeList(cfg.Passive.ScopeHostDeny)
	cfg.Passive.ScopePathDeny = normalizeScopeList(cfg.Passive.ScopePathDeny)
}

// normalizeScopeList 去掉范围规则里的空白项。
//
// 界面里多敲一个空行不该变成一条规则，空列表统一归一成 nil 以便 YAML 写成 []。
func normalizeScopeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
		return writeConfigFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
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
	return writeConfigFile(configPath, []byte(strings.Join(out, "\n")), 0644)
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
		return writeConfigFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
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
		return writeConfigFile(configPath, []byte(strings.Join(out, "\n")), 0644)
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
	return writeConfigFile(configPath, []byte(strings.Join(out, "\n")), 0644)
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

// UpdatePassiveSection 把 passive 段整体写回配置文件，其余段落原样保留。
func UpdatePassiveSection(configPath string, passive Passive) error {
	return replaceTopLevelSection(configPath, "passive", passiveSectionLines(0, passive))
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
		return writeConfigFile(configPath, []byte(strings.Join(out, "\n")), 0644)
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
	return writeConfigFile(configPath, []byte(strings.Join(out, "\n")), 0644)
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

// passiveSectionLines 生成 passive 段。
//
// 写回时统一按「已补齐默认值」的形态输出：使用者手工删掉某项后，下次保存
// 仍会得到一份完整可读的配置，而不是缺项的半截文件。
func passiveSectionLines(baseIndent int, p Passive) []string {
	prefix := strings.Repeat(" ", baseIndent)
	q := strconv.Quote

	host := strings.TrimSpace(p.Host)
	if host == "" {
		host = DefaultPassiveHost
	}
	port := p.Port
	if port <= 0 {
		port = DefaultPassivePort
	}
	maxRPS := p.MaxRPS
	if maxRPS <= 0 {
		maxRPS = DefaultPassiveMaxRPS
	}
	conc := p.HostConcurrency
	if conc <= 0 {
		conc = DefaultPassiveHostConcurrency
	}
	workers := p.WorkersOrDefault()
	detectWorkers := p.DetectWorkersOrDefault()
	queueSize := p.QueueSizeOrDefault()

	lines := []string{
		prefix + "passive:",
		prefix + "  auto_start: " + strconv.FormatBool(p.AutoStart),
		prefix + "  host: " + q(host),
		prefix + "  port: " + strconv.Itoa(port),
		prefix + "  upstream: " + q(strings.TrimRight(strings.TrimSpace(p.Upstream), "/")),
		prefix + "  detectors:",
	}
	for _, d := range p.EnabledDetectors() {
		lines = append(lines, prefix+"    - "+q(d))
	}
	lines = append(lines,
		prefix+"  max_rps: "+strconv.Itoa(maxRPS),
		prefix+"  host_concurrency: "+strconv.Itoa(conc),
		prefix+"  workers: "+strconv.Itoa(workers),
		prefix+"  detect_workers: "+strconv.Itoa(detectWorkers),
		prefix+"  queue_size: "+strconv.Itoa(queueSize),
		prefix+"  project_id: "+q(strings.TrimSpace(p.ProjectID)),
	)
	// 范围规则列表：空列表写成 [] 而不是留一个空键，避免使用者误以为配置被截断。
	listLines := func(key string, items []string) []string {
		if len(items) == 0 {
			return []string{prefix + "  " + key + ": []"}
		}
		out := []string{prefix + "  " + key + ":"}
		for _, it := range items {
			out = append(out, prefix+"    - "+q(it))
		}
		return out
	}
	lines = append(lines, listLines("scope_host_allow", p.ScopeHostAllow)...)
	lines = append(lines, listLines("scope_host_deny", p.ScopeHostDeny)...)
	lines = append(lines, listLines("scope_path_deny", p.ScopePathDeny)...)
	lines = append(lines, prefix+"  scan_unsafe_methods: "+strconv.FormatBool(p.ScanUnsafeMethods))
	return lines
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

// writeConfigFile 原子写回配置文件（先写同目录临时文件，再 rename 覆盖）。
//
// 原先直接 os.WriteFile，语义是「先截断、再写入」。同一台机器上并发启动的多个 afrog
// 进程会同时读同一个 ~/.config/afrog/afrog-config.yaml，读方恰好落进截断窗口就会读到
// 0 字节，yaml.NewDecoder(...).Decode 随即返回 io.EOF，NewConfig 失败、整个扫描零事件
// 退出——命令行上只留下一句没头没尾的 [ERR] EOF。
//
// rename 在同一文件系统内是原子的：读方要么看到旧内容、要么看到新内容，不会读到半截
// 文件。因此临时文件必须建在目标文件的同目录，跨设备 rename 会直接失败。
func writeConfigFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".afrog-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// CreateTemp 建出来是 0600，改回调用方给的权限，避免写一次配置就把文件收窄。
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
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

	return writeConfigFile(afrogConfigFile, afrogConfigYAML, 0644)
}
