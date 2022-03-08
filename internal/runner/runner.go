package runner

import (
	"errors"

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

	// for k, v := range options.Targets {
	// 	fmt.Println(k, v)
	// }

	// init pocs
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
	}
	allPocsYamlSlice := runner.catalog.GetPocsPath(options.PocsDirectory)
	if len(allPocsYamlSlice) == 0 {
		log.Log().Fatal("Could not find poc yaml file")
	}

	// for k, v := range options.PocsDirectory {
	// 	fmt.Println(k, v)
	// }
	// for k, v := range allPocsYamlSlice {
	// 	fmt.Println(k, v)
	// }

	// return nil, nil
	//log.Log().Debug(utils.ToString(allPocsSlice))
	e := core.New(options)
	e.Execute(allPocsYamlSlice)

	return runner, nil
}
