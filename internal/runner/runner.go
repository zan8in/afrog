package runner

import (
	"errors"
	"fmt"
	"os"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
)

type Runner struct {
	options *config.Options
	catalog *catalog.Catalog
}

func New(options *config.Options, acb config.ApiCallBack) error {
	runner := &Runner{options: options}

	// init callback
	options.ApiCallBack = acb

	// init poc home directory
	pocsDir, err := poc.InitPocHomeDirectory()
	if err != nil {
		return err
	}
	options.PocsDirectory.Set(pocsDir)

	// init config file
	config, err := config.New()
	if err != nil {
		return err
	}
	options.Config = config

	if len(options.Config.Reverse.Ceye.Domain) == 0 || len(options.Config.Reverse.Ceye.ApiKey) == 0 {
		homeDir, _ := os.UserHomeDir()
		return errors.New("please edit `api-key` and `domain` in `" + homeDir + "/.config/afrog/afrog-config.yaml`")
	}

	// init targets
	if len(options.Target) > 0 {
		options.Targets.Set(options.Target)
	}
	if len(options.TargetsFilePath) > 0 {
		allTargets, err := utils.ReadFileLineByLine(options.TargetsFilePath)
		if err != nil {
			return err
		}
		for _, t := range allTargets {
			options.Targets.Set(t)
		}
	}
	if len(options.Targets) == 0 {
		return errors.New("could not find targets")
	}

	// init pocs
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
		// console print
		fmt.Println(log.LogColor.Info("指定脚本  " + options.PocsFilePath))
	}

	allPocsYamlSlice := runner.catalog.GetPocsPath(options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 {
		return errors.New("未找到可执行脚本(POC)，请检查`默认脚本`或指定新の脚本(POC)")
	}

	// console print
	if len(options.Output) > 0 {
		fmt.Println(log.LogColor.Info("输出文件  " + options.Output))
	}

	// init scan sum
	options.Count = len(options.Targets) * len(allPocsYamlSlice)

	//
	e := core.New(options)
	e.Execute(allPocsYamlSlice)

	return nil
}
