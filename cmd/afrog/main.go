package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/urfave/cli/v2"
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/fingerprint"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
)

var options = &config.Options{}
var htemplate = &html.HtmlTemplate{}
var lock sync.Mutex
var number = 0

func main() {
	app := cli.NewApp()
	app.Name = runner.ShowBanner()
	app.Usage = "v" + config.Version
	app.UsageText = runner.ShowTips()
	app.Version = config.Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "target", Aliases: []string{"t"}, Destination: &options.Target, Value: "", Usage: "target URLs/hosts to scan"},
		&cli.StringFlag{Name: "targets", Aliases: []string{"T"}, Destination: &options.TargetsFilePath, Value: "", Usage: "path to file containing a list of target URLs/hosts to scan (one per line)"},
		&cli.StringFlag{Name: "pocs", Aliases: []string{"P"}, Destination: &options.PocsFilePath, Value: "", Usage: "poc.yaml or poc directory paths to include in the scan（no default `afrog-pocs` directory）"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Destination: &options.Output, Value: "", Usage: "output html report, eg: -o result.html "},
		&cli.StringFlag{Name: "search", Aliases: []string{"s"}, Destination: &options.Search, Value: "", Usage: "search PoC by `keyword` , eg: -s tomcat,phpinfo"},
		&cli.StringFlag{Name: "severity", Aliases: []string{"S"}, Destination: &options.Severity, Value: "", Usage: "pocs to run based on severity. Possible values: info, low, medium, high, critical, unknown"},
		&cli.BoolFlag{Name: "silent", Destination: &options.Silent, Value: false, Usage: "no progress, only results"},
		&cli.BoolFlag{Name: "nofinger", Aliases: []string{"nf"}, Destination: &options.NoFinger, Value: false, Usage: "disable fingerprint"},
		&cli.BoolFlag{Name: "notips", Aliases: []string{"nt"}, Destination: &options.NoTips, Value: false, Usage: "disable show tips"},
		&cli.BoolFlag{Name: "updatepocs", Aliases: []string{"up"}, Destination: &options.UpdatePocs, Value: false, Usage: "update afrog-pocs"},
		// &cli.BoolFlag{Name: "webport", Aliases: []string{"wp"}, Destination: &options.WebPort, Value: false, Usage: "enable web port scan, default top 1000 port"},
		// &cli.StringFlag{Name: "port", Destination: &options.Port, Value: "", Usage: "web port scan, default top 1000, eg: --port 80,443,8000-9000"},
	}

	app.Action = func(c *cli.Context) error {
		upgrade := upgrade.New()
		upgrade.IsUpdatePocs = options.UpdatePocs
		upgrade.UpgradeAfrogPocs()

		if !options.UpdatePocs {
			runner.ShowBanner2(upgrade.LastestAfrogVersion)
		}

		if !options.UpdatePocs {
			printPathLog(upgrade)
		}

		if len(options.Output) == 0 {
			options.Output = utils.GetNowDateTimeReportName() + ".html"
		}

		htemplate.Filename = options.Output
		if err := htemplate.New(); err != nil {
			return err
		}

		err := runner.New(options, htemplate, func(result interface{}) {
			r := result.(*core.Result)

			lock.Lock()

			if !options.Silent {
				options.CurrentCount++
			}

			if r.IsVul {
				if r.FingerResult != nil {
					// Fingerprint Scan
					//fr := r.FingerResult.(fingerprint.Result)
					//printFingerprintInfoConsole(fr)
				} else {
					// PoC Scan
					number++

					r.PrintColorResultInfoConsole(utils.GetNumberText(number))

					htemplate.Result = r
					htemplate.Number = utils.GetNumberText(number)
					htemplate.Append()
				}
			}

			if !options.Silent {
				fmt.Printf("\r%d/%d | %d%% ", options.CurrentCount, options.Count, options.CurrentCount*100/options.Count)
			}

			lock.Unlock()

		})
		if err != nil {
			return err
		}

		return err
	}

	err := app.Run(os.Args)
	if err != nil && !options.UpdatePocs {
		fmt.Println(runner.ShowTips())
		fmt.Println(log.LogColor.High("start afrog failed，", err.Error()))
	}
}

func printFingerprintInfoConsole(fr fingerprint.Result) {
	if len(fr.StatusCode) > 0 {
		fmt.Printf("\r" + fr.Url + " " +
			log.LogColor.Low(""+fr.StatusCode+"") + " " +
			log.LogColor.Title(fr.Title) + " " +
			log.LogColor.Critical(fr.Name) + "\r\n")
	}
}

func printPathLog(upgrade *upgrade.Upgrade) {
	fmt.Println("PATH:")
	fmt.Println("   " + options.Config.GetConfigPath())
	if options.UpdatePocs {
		fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.LastestVersion)
	} else {
		if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
			fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion + " (" + log.LogColor.Vulner(upgrade.LastestVersion) + ")")
		} else {
			fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion)
		}
	}
}
