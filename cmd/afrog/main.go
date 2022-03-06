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
	// options.Targets.Set("https://202.65.121.62:7199")
	options.Targets.Set("https://34.141.128.122")
	// options.Targets.Set("http://121.196.164.206:9000")
	// options.Targets.Set("http://139.9.119.190:9001")
	// allTargets, _ := utils.ReadFileLineByLine("./urls.txt")
	// for _, t := range allTargets {
	// 	options.Targets.Set(t)
	// 	// utils.BufferWriteAppend("./result.txt", t)
	// }

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
