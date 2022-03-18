package runner

import (
	"errors"
	"fmt"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/utils"
)

type Runner struct {
	options *config.Options
	catalog *catalog.Catalog
}

func New(options *config.Options) (*Runner, error) {
	runner := &Runner{options: options}

	// init targets
	if len(options.Target) > 0 {
		options.Targets.Set(options.Target)
	}
	if len(options.TargetsFilePath) > 0 {
		allTargets, err := utils.ReadFileLineByLine(options.TargetsFilePath)
		if err != nil {
			return nil, err
		}
		for _, t := range allTargets {
			options.Targets.Set(t)
		}
	}
	if len(options.Targets) == 0 {
		return nil, errors.New("could not find targets")
	}

	// init pocs
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
		// console print
		otherpocdir := log.LogColor.Info("指定脚本  " + options.PocsFilePath)
		fmt.Println(otherpocdir)
	}
	allPocsYamlSlice := runner.catalog.GetPocsPath(options.PocsDirectory)
	if len(allPocsYamlSlice) == 0 {
		return nil, errors.New("未找到可执行脚本(POC)，请检查`默认脚本`或指定新の脚本(POC)")
	}

	// console print
	if len(options.Output) > 0 {
		otherpocdir := log.LogColor.Info("输出文件  " + options.Output)
		fmt.Println(otherpocdir)
	}

	// init scan sum
	options.Count = len(options.Targets) * len(allPocsYamlSlice)

	// return nil, nil
	//log.Log().Debug(utils.ToString(allPocsSlice))
	e := core.New(options)
	e.Execute(allPocsYamlSlice)

	return runner, nil
}
