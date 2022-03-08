package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
)

var options = &config.Options{}

func main() {
	readConfig()

	app := cli.NewApp()
	app.Name = runner.ShowBanner(options.Config.ConfigVersion)
	app.Usage = " "
	app.UsageText = "afrog [global options] command [command options] [arguments...]"
	app.Version = options.Config.ConfigVersion

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "target", Aliases: []string{"t"}, Destination: &options.Target, Value: "", Usage: "target URLS/hosts to scan"},
		&cli.StringFlag{Name: "targetFilePath", Aliases: []string{"T"}, Destination: &options.TargetsFilePath, Value: "", Usage: "path to file containing a list of target URLs/hosts to scan (one per line)"},
		&cli.StringFlag{Name: "PocsFilePath", Aliases: []string{"P"}, Destination: &options.PocsFilePath, Value: "", Usage: "path to file containing a list of target poc*.yaml to scan (default {{home}}/afrog-pocs)"},
		&cli.StringFlag{Name: "Output", Aliases: []string{"o"}, Destination: &options.Output, Value: "", Usage: "Output file to write found issues/vulnerabilities"},
	}

	app.Action = func(c *cli.Context) error {
		var err error

		if _, err := runner.New(options); err != nil {
			log.Log().Fatal(err.Error())
		}

		return err
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Log().Fatal(fmt.Sprintf("app run err, %s", err.Error()))
	}
}

func readConfig() {
	// options.Targets.Set("https://202.65.121.62:7199")
	// options.Targets.Set("https://34.141.128.122")
	// options.Targets.Set("http://121.196.164.206:9000")
	// options.Targets.Set("http://139.9.119.190:9001")
	// options.Targets.Set("http://127.0.0.1")
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
