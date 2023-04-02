package runner

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/output"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
)

type Runner struct {
	options *config.Options
	catalog *catalog.Catalog
}

func New(options *config.Options, htemplate *html.HtmlTemplate, acb config.ApiCallBack) error {
	runner := &Runner{options: options}

	// afrog engine update
	if options.UpdateAfrogVersion {
		return UpdateAfrogVersionToLatest(true)
	}

	// print pocs list
	if options.PrintPocs {
		options.PrintPocList()
		return nil
	}

	// update afrog-pocs
	upgrade := upgrade.New(options.UpdatePocs)
	upgrade.UpgradeAfrogPocs()
	if options.UpdatePocs {
		return nil
	}

	// output to afrog report
	if len(options.Output) == 0 {
		options.Output = utils.GetNowDateTimeReportName() + ".html"
	}
	htemplate.Filename = options.Output
	if err := htemplate.New(); err != nil {
		gologger.Fatal().Msgf("Output failed, %s", err.Error())
	}

	// output to json file
	if len(options.OutputJson) > 0 {
		options.OJ = output.NewOutputJson(options.OutputJson)
	}

	// show banner
	ShowBanner2(upgrade)

	// init callback
	options.ApiCallBack = acb

	// init proxyURL
	if err := config.LoadProxyServers(options); err != nil {
		return err
	}

	// init config file
	config, err := config.New()
	if err != nil {
		return err
	}
	options.Config = config

	// init rtryhttp
	retryhttpclient.Init(options)

	// init targets
	if len(options.Target) > 0 {
		options.Targets.Append(options.Target)
	}
	if len(options.TargetsFilePath) > 0 {
		allTargets, err := utils.ReadFileLineByLine(options.TargetsFilePath)
		if err != nil {
			return err
		}
		for _, t := range allTargets {
			options.Targets.Append(t)
		}
	}
	if options.Targets.Len() == 0 {
		return errors.New("target not found")
	}

	// show banner
	gologger.Print().Msgf("Targets loaded for scan: %d", options.Targets.Len())

	// init pocs
	allPocsEmbedYamlSlice := []string{}
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
	} else {
		// init default afrog-pocs
		if allDefaultPocsYamlSlice, err := pocs.GetPocs(); err == nil {
			allPocsEmbedYamlSlice = append(allPocsEmbedYamlSlice, allDefaultPocsYamlSlice...)
		}
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			options.PocsDirectory.Set(pocsDir)
		}
	}
	allPocsYamlSlice := runner.catalog.GetPocsPath(options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 && len(allPocsEmbedYamlSlice) == 0 {
		return errors.New("afrog-pocs not found")
	}

	// show banner
	gologger.Print().Msgf("PoCs added in last update: %d", len(allPocsYamlSlice))
	gologger.Print().Msgf("PoCs loaded for scan: %d", len(allPocsYamlSlice)+len(allPocsEmbedYamlSlice))
	gologger.Print().Msgf("Creating output html file: %s", htemplate.Filename)

	// reverse set
	if len(options.Config.Reverse.Ceye.Domain) == 0 || len(options.Config.Reverse.Ceye.ApiKey) == 0 {
		homeDir, _ := os.UserHomeDir()
		configDir := homeDir + "/.config/afrog/afrog-config.yaml"
		gologger.Error().Msgf("`ceye` reverse service not set: %s", configDir)
	}

	// whitespace show banner
	fmt.Println()

	gologger.Print().Msg("Tip: Fingerprint has been disabled, the replacement tool is Pyxis (https://github.com/zan8in/pyxis)\n\n")

	// check poc
	e := core.New(options)
	e.Execute(allPocsYamlSlice, allPocsEmbedYamlSlice)

	return nil
}
