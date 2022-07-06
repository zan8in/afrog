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
	"github.com/zan8in/afrog/pkg/scan"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
)

type Runner struct {
	options *config.Options
	catalog *catalog.Catalog
}

func New(options *config.Options, htemplate *html.HtmlTemplate, acb config.ApiCallBack) error {
	runner := &Runner{options: options}

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

	// console print
	if len(options.Output) > 0 {
		fmt.Println("   ./reports/" + options.Output)
	}

	// // init scan sum
	// options.Count = len(options.Targets) * (len(allPocsYamlSlice) + len(allPocsEmbedYamlSlice))

	// fmt.Println(ShowUsage())

	if !options.NoTips {
		fmt.Println(ShowTips())
	}

	fmt.Println("port scan before : ", len(options.Targets))

	if options.WebPort {
		if scan, err := scan.New(options); err == nil {
			scan.Execute()
		}
	}

	fmt.Println("port scan after : ", len(options.Targets))
	for k, v := range options.Targets {
		fmt.Println(k, v)
	}

	// fingerprint
	if !options.NoFinger {
		s, _ := fingerprint.New(options)
		s.Execute()
		if len(s.ResultSlice) > 0 {
			htemplate.AppendFinger(s.ResultSlice)
			printFingerResultConsole()
		}
	}

	//
	e := core.New(options)
	e.Execute(allPocsYamlSlice, allPocsEmbedYamlSlice)

	return nil
}

func printFingerResultConsole() {
	fmt.Printf("\r" + log.LogColor.Time("000 "+utils.GetNowDateTime()) + " " +
		log.LogColor.Vulner("Fingerprint") + " " + log.LogColor.Info("INFO") + "\r\n")

}
