package runner

import (
	"errors"
	"fmt"
	"os"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/fingerprint"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/targets"
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
	if options.UpdatePocs {
		upgrade.UpgradeAfrogPocs()
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

	ShowBanner3(upgrade)

	// printPathLog(upgrade)

	// init TargetLive
	options.TargetLive = utils.New()

	// init callback
	options.ApiCallBack = acb

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

	// init fasthttp
	http2.Init(options)

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
		return errors.New("not found targets")
	}

	gologger.Info().Msgf("Targets loaded for scan: %d", len(options.Targets))

	// init pocs
	allPocsEmbedYamlSlice := []string{}
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
		// console print
		fmt.Println("   " + options.PocsFilePath)
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
		return errors.New("no found pocs")
	}

	gologger.Info().Msgf("PoCs added in last update: %d", len(allPocsYamlSlice))
	gologger.Info().Msgf("PoCs loaded for scan: %d", len(allPocsYamlSlice)+len(allPocsEmbedYamlSlice))
	gologger.Info().Msgf("Creating output html file: %s", htemplate.Filename)

	// whitespace
	fmt.Println()

	// fmt.Println(ShowUsage())

	// if !options.NoTips {
	// 	fmt.Println(ShowTips())
	// }

	// fingerprint
	if !options.NoFinger {
		s, _ := fingerprint.New(options)
		s.Execute()
		if len(s.ResultSlice) > 0 {
			htemplate.AppendFinger(s.ResultSlice)
			printFingerResultConsole()
		}
	}

	//check target live
	go targets.RunTargetLivenessCheck(options)

	e := core.New(options)
	e.Execute(allPocsYamlSlice, allPocsEmbedYamlSlice)

	return nil
}

func printFingerResultConsole() {
	fmt.Printf("\r" + log.LogColor.Time("000 "+utils.GetNowDateTime()) + " " +
		log.LogColor.Vulner("Fingerprint") + " " + log.LogColor.Info("INFO") + "                    \r\n")

}

func printPathLog(upgrade *upgrade.Upgrade) {
	fmt.Println("PATH:")
	// fmt.Println("   " + options.Config.GetConfigPath())
	// if options.UpdatePocs {
	// 	fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.LastestVersion)
	// } else {
	// 	if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
	// 		fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion + " (" + log.LogColor.Vulner(upgrade.LastestVersion) + ")")
	// 	} else {
	// 		fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion)
	// 	}
	// }
}
