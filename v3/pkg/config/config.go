package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/v2/pkg/utils"
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
}

type Dingtalk struct {
	Tokens    []string `yaml:"tokens"`
	AtMobiles []string `yaml:"at_mobiles"`
	AtAll     bool     `yaml:"at_all"`
	Range     string   `yaml:"range"`
}

type Reverse struct {
	Ceye Ceye `yaml:"ceye"`
	Jndi Jndi `yaml:"jndi"`
	Eye  Eye  `yaml:"eye"`
}

type Ceye struct {
	ApiKey string `yaml:"api-key"`
	Domain string `yaml:"domain"`
}

type Eye struct {
	Host   string `yaml:"host"`
	Token  string `yaml:"token"`
	Domain string `yaml:"domain"`
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
func NewConfig() (*Config, error) {
	if isExistConfigFile() != nil {
		c := Config{}
		c.ServerAddress = ":16868"

		reverse := c.Reverse
		reverse.Ceye.ApiKey = ""
		reverse.Ceye.Domain = ""
		reverse.Eye.Host = "eyes.sh"

		reverse.Jndi.JndiAddress = ""
		reverse.Jndi.LdapPort = ""
		reverse.Jndi.ApiPort = ""
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

		WriteConfiguration(&c)
	}
	return ReadConfiguration()
}

func isExistConfigFile() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return errors.Wrap(err, "could not get home directory")
	}

	configFile := filepath.Join(homeDir, ".config", "afrog", afrogConfigFilename)
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
func ReadConfiguration() (*Config, error) {
	afrogConfigFile, err := getConfigFile()
	if err != nil {
		return nil, err
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
func WriteConfiguration(config *Config) error {
	afrogConfigYAML, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}

	afrogConfigFile, err := getConfigFile()
	if err != nil {
		return err
	}

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
