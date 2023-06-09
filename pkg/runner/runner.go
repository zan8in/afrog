package runner

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/report"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
)

type OnResult func(*result.Result)

type Runner struct {
	options       *config.Options
	catalog       *catalog.Catalog
	Report        *report.Report
	JsonReport    *report.JsonReport
	OnResult      OnResult
	PocsYaml      utils.StringSlice
	PocsEmbedYaml utils.StringSlice
	engine        *Engine
}

func NewRunner(options *config.Options) (*Runner, error) {
	runner := &Runner{options: options}

	runner.engine = NewEngine(options)

	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           options.Proxy,
		Timeout:         options.Timeout,
		Retries:         options.Retries,
		MaxRespBodySize: options.MaxRespBodySize,
	})

	jr, err := report.NewJsonReport(options.Json, options.JsonAll)
	if err != nil {
		return runner, fmt.Errorf("%s", err.Error())
	}
	runner.JsonReport = jr

	report, err := report.NewReport(options.Output, report.DefaultTemplate)
	if err != nil {
		return runner, fmt.Errorf("%s", err.Error())
	}
	runner.Report = report

	if len(runner.options.Target) > 0 {
		for _, t := range runner.options.Target {
			runner.options.Targets.Append(t)
		}

	}
	if len(runner.options.TargetsFile) > 0 {
		allTargets, err := utils.ReadFileLineByLine(runner.options.TargetsFile)
		if err != nil {
			return runner, err
		}
		for _, t := range allTargets {
			if len(strings.TrimSpace(t)) > 0 {
				runner.options.Targets.Append(t)
			}
		}
	}
	if runner.options.Targets.Len() == 0 {
		return runner, errors.New("target not found")
	}

	// gologger.Print().Msgf("Targets loaded for scan: %d", runner.options.Targets.Len())

	// init pocs
	allPocsEmbedYamlSlice := []string{}
	if len(runner.options.PocFile) > 0 {
		runner.options.PocsDirectory.Set(runner.options.PocFile)
	} else {
		// init default afrog-pocs
		if allDefaultPocsYamlSlice, err := pocs.GetPocs(); err == nil {
			allPocsEmbedYamlSlice = append(allPocsEmbedYamlSlice, allDefaultPocsYamlSlice...)
		}
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			runner.options.PocsDirectory.Set(pocsDir)
		}
	}
	allPocsYamlSlice := runner.catalog.GetPocsPath(runner.options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 && len(allPocsEmbedYamlSlice) == 0 {
		return runner, errors.New("afrog-pocs not found")
	}

	runner.PocsYaml = allPocsYamlSlice
	runner.PocsEmbedYaml = allPocsEmbedYamlSlice

	// runner.options.Count = (len(allPocsYamlSlice) + len(allPocsEmbedYamlSlice)) * runner.options.Targets.Len()

	return runner, nil
}

func (runner *Runner) Run() error {

	// show banner
	// gologger.Print().Msgf("PoCs added in last update: %d", len(allPocsYamlSlice))
	// gologger.Print().Msgf("PoCs loaded for scan: %d", len(allPocsYamlSlice)+len(allPocsEmbedYamlSlice))
	// gologger.Print().Msgf("Creating output html file: %s", htemplate.Filename)

	// whitespace show banner

	// gologger.Print().Msg("Tip: Fingerprint has been disabled, the replacement tool is Pyxis (https://github.com/zan8in/pyxis)\n\n")

	if runner.options.MonitorTargets {
		go runner.monitorTargets()
	}

	runner.Execute()

	return nil
}
