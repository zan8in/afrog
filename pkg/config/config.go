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
	// PocSizeWaitGroup         int32      `yaml:"poc_sizewaitgroup"`
	// TargetSizeWaitGroup      int32      `yaml:"target_sizewaitgroup"`
	// FingerprintSizeWaitGroup int32      `yaml:"fingerprint_sizewaitgroup"`
	// ConfigHttp               ConfigHttp `yaml:"http"`
	Reverse Reverse `yaml:"reverse"`
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
const Version = "2.2.1"

// Create and initialize afrog-config.yaml configuration info
func New() (*Config, error) {
	if isExistConfigFile() != nil {
		c := Config{}
		// c.PocSizeWaitGroup = 25
		// c.TargetSizeWaitGroup = 25
		// c.FingerprintSizeWaitGroup = 100
		// configHttp := c.ConfigHttp
		// configHttp.Proxy = ""
		// configHttp.DialTimeout = 10
		// configHttp.ReadTimeout = "10000ms"
		// configHttp.WriteTimeout = "3000ms"
		// configHttp.MaxIdle = "1h"
		// configHttp.MaxRedirect = 3
		// configHttp.Concurrency = 4096
		// configHttp.MaxConnsPerHost = 512 // MaxConnsPerHost是一个限流的参数，保证对一个Host最大的打开连接数，如果超过这个数字，则会直接拒绝，这里默认值是512，但如果你打算用来做压测之类的事情，需要增加这个值，比如这里我就增加到了16384
		// configHttp.MaxResponseBodySize = 1024 * 1024 * 2
		// configHttp.UserAgent = ""
		// c.ConfigHttp = configHttp
		reverse := c.Reverse
		reverse.Ceye.ApiKey = ""
		reverse.Ceye.Domain = ""
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
