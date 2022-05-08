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
		return errors.New("could not find targets")
	}

	// init pocs
	allPocsYamlSlice := []string{}
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
		// console print
		fmt.Println("   " + options.PocsFilePath)
	} else {
		// init default afrog-pocs
		if allDefaultPocsYamlSlice, err := pocs.GetPocs(); err == nil {
			allPocsYamlSlice = append(allPocsYamlSlice, allDefaultPocsYamlSlice...)
		}
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			options.PocsDirectory.Set(pocsDir)
		}
	}
	allPocsYamlSlice = append(allPocsYamlSlice, runner.catalog.GetPocsPath(options.PocsDirectory)...)

	if len(allPocsYamlSlice) == 0 {
		return errors.New("未找到可执行脚本(POC)，请检查`默认脚本`或指定新の脚本(POC)")
	}

	// console print
	if len(options.Output) > 0 {
		fmt.Println("   ./reports/" + options.Output)
	}

	// init scan sum
	options.Count = len(options.Targets) * len(allPocsYamlSlice)

	// fmt.Println(ShowUsage())

	if !options.NoTips {
		fmt.Println(ShowTips())
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
	e.Execute(allPocsYamlSlice)

	return nil
}

func printFingerResultConsole() {
	fmt.Printf("\r" + log.LogColor.Time("000 "+utils.GetNowDateTime()) + " " +
		log.LogColor.Vulner("Fingerprint") + " " + log.LogColor.Info("INFO") + "\r\n")

}
