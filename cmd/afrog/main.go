package main

import (
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
)

var options = &config.Options{}

func main() {
	readConfig()

	if _, err := runner.New(options); err != nil {
		log.Log().Fatal(err.Error())
	}
}

func readConfig() {
	options.Targets.Set("http://example.com")

	pocsDir, err := poc.InitPocHomeDirectory()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.PocsDirectory.Set(pocsDir)

	config, err := config.New()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.Config = config
}
