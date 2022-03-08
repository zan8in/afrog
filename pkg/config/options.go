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

	// Target URLs/Domains to scan
	Target string

	// TargetsFilePath specifies the targets from a file to scan.
	TargetsFilePath string

	// PocsFilePath specifies the directory of pocs to scan.
	PocsFilePath string

	// output file to write found issues/vulnerabilities
	Output string
}
