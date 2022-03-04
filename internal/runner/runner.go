package runner

import (
	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/log"
)

type Runner struct {
	options *config.Options
	catalog *catalog.Catalog
}

func New(options *config.Options) (*Runner, error) {
	runner := &Runner{options: options}

	allUrlSlice := options.Targets
	if len(allUrlSlice) == 0 {
		log.Log().Fatal("Could not find targets")
	}
	//log.Log().Debug(utils.ToString(allUrlSlice))

	allPocsYamlSlice := runner.catalog.GetPocsPath(options.PocsDirectory)
	if len(allPocsYamlSlice) == 0 {
		log.Log().Fatal("Could not find poc yaml file")
	}
	//log.Log().Debug(utils.ToString(allPocsSlice))
	e := core.New(options)
	e.Execute(allPocsYamlSlice)

	return runner, nil
}
