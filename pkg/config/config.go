package config

import (
	"os"
	"path/filepath"
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
		webhook.Wecom.Tokens = []string{""}
		webhook.Wecom.AtMobiles = []string{""}
		webhook.Wecom.AtAll = false
		webhook.Wecom.Range = "high,critical"
		webhook.Wecom.Markdown = true
		c.Webhook = webhook

		cyberspace := c.Cyberspace
		cyberspace.ZoomEyes = []string{""}
		c.Cyberspace = cyberspace

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
	return config, nil
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
