package runner

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/report"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
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

	// init pocs
	if len(runner.options.PocFile) > 0 {
		runner.options.PocsDirectory.Set(runner.options.PocFile)
	} else {
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			runner.options.PocsDirectory.Set(pocsDir)
		}
		// append PoCs
		if len(runner.options.AppendPoc) > 0 {
			for _, p := range runner.options.AppendPoc {
				runner.options.PocsDirectory.Set(p)
			}
		}
	}

	allPocsYamlSlice := runner.catalog.GetPocsPath(runner.options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 && len(pocs.EmbedFileList) == 0 {
		return runner, errors.New("afrog-pocs not found")
	}

	runner.PocsYaml = allPocsYamlSlice
	runner.PocsEmbedYaml = pocs.EmbedFileList

	checkReversePlatform()

	return runner, nil
}

func (runner *Runner) Run() error {

	if runner.options.MonitorTargets {
		go runner.monitorTargets()
	}

	runner.Execute()

	return nil
}

func checkReversePlatform() {

	wg := sync.WaitGroup{}
	if len(config.ReverseJndi) > 0 && len(config.ReverseLdapPort) > 0 && len(config.ReverseApiPort) > 0 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if !JndiTest() {
				gologger.Info().Msg("JNDI platform exception may affect some POCs")
				config.ReverseJndiLive = false
			} else {
				config.ReverseJndiLive = true
			}

		}()
	}

	if len(config.ReverseCeyeDomain) > 0 && len(config.ReverseCeyeApiKey) > 0 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if !CeyeTest() {
				gologger.Info().Msg("Ceye platform exception may affect some POCs")
				config.ReverseCeyeLive = false
			} else {
				config.ReverseCeyeLive = true
			}

		}()

	}

	wg.Wait()
}
