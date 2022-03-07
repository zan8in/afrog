package config

import (
	"github.com/zan8in/afrog/pkg/utils"
)

type Options struct {
	// afrog-config.yaml configuration file
	Config *Config

	// Pocs Directory
	PocsDirectory utils.StringSlice

	// Target URLs/Domains to scan
	Targets utils.StringSlice
}
