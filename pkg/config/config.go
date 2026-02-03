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
}

type Dingtalk struct {
	Tokens    []string `yaml:"tokens"`
	AtMobiles []string `yaml:"at_mobiles"`
	AtAll     bool     `yaml:"at_all"`
	Range     string   `yaml:"range"`
}

type Reverse struct {
	Alphalog Alphalog `yaml:"alphalog"`
	Ceye     Ceye     `yaml:"ceye"`
	Dnslogcn Dnslogcn `yaml:"dnslogcn"`
	Eye      Eye      `yaml:"eye"`
	Jndi     Jndi     `yaml:"jndi"`
	Xray     Xray     `yaml:"xray"`
	Revsuit  Revsuit  `yaml:"revsuit"`
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

		c.Reverse = reverse

		webhook := c.Webhook
		webhook.Dingtalk.Tokens = []string{""}
		webhook.Dingtalk.AtMobiles = []string{""}
		webhook.Dingtalk.AtAll = false
		webhook.Dingtalk.Range = "high,critical"
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
	_ = ensureCuratedSection(afrogConfigFile, config.Curated)
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
