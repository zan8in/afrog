package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/pkg/utils"
	"gopkg.in/yaml.v2"
)

// Config is a afrog-config.yaml catalog helper implementation
type Config struct {
	ConfigVersion       string     `yaml:"version"`
	PocSizeWaitGroup    int32      `yaml:"poc_sizewaitgroup"`
	TargetSizeWaitGroup int32      `yaml:"target_sizewaitgroup"`
	ConfigHttp          ConfigHttp `yaml:"http"`
	Reverse             Reverse    `yaml:"reverse"`
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

type Reverse struct {
	Ceye Ceye `yaml:"ceye"`
}

type Ceye struct {
	ApiKey string `yaml:"api-key"`
	Domain string `yaml:"domain`
}

const afrogConfigFilename = "afrog-config.yaml"
const Version = "1.0.8"

// Create and initialize afrog-config.yaml configuration info
func New() (*Config, error) {
	if isExistConfigFile() != nil {
		c := Config{}
		c.ConfigVersion = Version
		c.PocSizeWaitGroup = 25
		c.TargetSizeWaitGroup = 6
		configHttp := c.ConfigHttp
		configHttp.Proxy = ""
		configHttp.DialTimeout = 5
		configHttp.ReadTimeout = "5000ms"
		configHttp.WriteTimeout = "5000ms"
		configHttp.MaxIdle = "5s"
		configHttp.MaxRedirect = 5
		configHttp.Concurrency = 4096
		configHttp.MaxConnsPerHost = 10000
		configHttp.MaxResponseBodySize = 1024 * 1024 * 2
		configHttp.UserAgent = ""
		c.ConfigHttp = configHttp
		reverse := c.Reverse
		reverse.Ceye.ApiKey = "bba3368c28118247ddc4785630b8fca0"
		reverse.Ceye.Domain = "7gn2sm.ceye.io"
		c.Reverse = reverse
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
		return ""
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
