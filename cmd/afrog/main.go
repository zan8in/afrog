package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"

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
	app.UsageText = "afrog [命令]"
	app.Version = options.Config.ConfigVersion

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "target", Aliases: []string{"t"}, Destination: &options.Target, Value: "", Usage: "指定扫描的URL/Host"},
		&cli.StringFlag{Name: "targetFilePath", Aliases: []string{"T"}, Destination: &options.TargetsFilePath, Value: "", Usage: "指定需要扫描的URL/Host文件（一行一个）"},
		&cli.StringFlag{Name: "PocsFilePath", Aliases: []string{"P"}, Destination: &options.PocsFilePath, Value: "", Usage: "指定需要扫描的POC脚本的路径（非必须，默认加载{home}/afrog-pocs）"},
		&cli.StringFlag{Name: "Output", Aliases: []string{"o"}, Destination: &options.Output, Value: "", Usage: "输出扫描结果到文件"},
	}

	app.Action = func(c *cli.Context) error {
		var err error

		title := color.HiBlueString("一款基于 YAML 语法模板的定制化快速漏洞扫描器 - afrog V" + c.App.Version)
		defconfig := color.BlueString("默认配置  " + options.Config.GetConfigPath())
		defpocdir := color.BlueString("默认脚本  " + poc.GetPocPath())
		fmt.Println(title + "\r\n" + defconfig + "\r\n" + defpocdir)

		if _, err := runner.New(options); err != nil {
			return err
		}

		return err
	}

	err := app.Run(os.Args)
	if err != nil {
		// log.Log().Fatal(fmt.Sprintf("app run err, %s", err.Error()))
		fmt.Println(color.HiRedString("启动 afrog 出错，%s", err.Error()))
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
