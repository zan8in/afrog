package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Config is a afrog-config.yaml catalog helper implementation
type Config struct {
	ConfigVersion       string     `yaml:"version"`
	PocSizeWaitGroup    int32      `yaml:"poc_sizewaitgroup"`
	TargetSizeWaitGroup int32      `yaml:"target_sizewaitgroup"`
	ConfigHttp          ConfigHttp `yaml:"http"`
}

type ConfigHttp struct {
	Proxy               string `yaml:"proxy"`
	ReadTimeout         string `yaml:"read_timeout"`
	WriteTimeout        string `yaml:"write_timeout"`
	MaxIdle             string `yaml:"max_idle"`
	Concurrency         int    `yaml:"concurrency"`
	MaxResponseBodySize int    `yaml:"max_responsebody_sizse"`
	MaxRedirectCount    int    `yaml:"max_redirect_count"`
}

const afrogConfigFilename = ".afrog-config.yaml"
const Version = "1.0"

func New() (*Config, error) {
	config, err := ReadConfiguration()
	if err != nil {
		return config, err
	}
	c := Config{}
	c.ConfigVersion = Version
	c.PocSizeWaitGroup = 8
	c.TargetSizeWaitGroup = 8
	configHttp := c.ConfigHttp
	configHttp.Proxy = ""
	configHttp.ReadTimeout = "500ms"
	configHttp.ReadTimeout = "500ms"
	configHttp.MaxIdle = "1h"
	configHttp.Concurrency = 4096
	configHttp.MaxResponseBodySize = 1024 * 1024 * 2
	configHttp.MaxRedirectCount = 5
	c.ConfigHttp = configHttp
	WriteConfiguration(&c)
	return ReadConfiguration()
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
