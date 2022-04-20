package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/html"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/upgrade"
)

var options = &config.Options{}
var htemplate = &html.HtmlTemplate{}

func main() {
	app := cli.NewApp()
	app.Name = runner.ShowBanner()
	app.Usage = "V" + config.Version
	app.UsageText = "afrog [command]\n\n\t afrog -t example.com -o result.html\n\t afrog -T urls.txt -o result.html\n\t afrog -t example.com -P ./pocs/poc-test.yaml -o result.html\n\t afrog -t example.com -P ./pocs/ -o result.html"
	app.Version = config.Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "Target", Aliases: []string{"t"}, Destination: &options.Target, Value: "", Usage: "target URLs/hosts to scan"},
		&cli.StringFlag{Name: "TargetFilePath", Aliases: []string{"T"}, Destination: &options.TargetsFilePath, Value: "", Usage: "path to file containing a list of target URLs/hosts to scan (one per line)"},
		&cli.StringFlag{Name: "PocsFilePath", Aliases: []string{"P"}, Destination: &options.PocsFilePath, Value: "", Usage: "poc.yaml or poc directory paths to include in the scan（no default `afrog-pocs` directory）"},
		&cli.StringFlag{Name: "Output", Aliases: []string{"o"}, Destination: &options.Output, Value: "", Usage: "output html report, eg: -o result.html "},
		&cli.BoolFlag{Name: "Silent", Aliases: []string{"s"}, Destination: &options.Silent, Value: false, Usage: "no progress, only results"},
	}

	app.Action = func(c *cli.Context) error {

		title := log.LogColor.Vulner(runner.ShowBanner() + " - V" + config.Version)

		upgrade := upgrade.New()
		upgrade.UpgradeAfrogPocs()

		defconfig := log.LogColor.Low("Default Conf  " + options.Config.GetConfigPath())
		defpocdir := log.LogColor.Low("Default Pocs  " + poc.GetPocPath())

		fmt.Println(title + "\r\n" + defconfig + "\r\n" + defpocdir + " v" + upgrade.LastestVersion + "")

		htemplate.Filename = options.Output
		if err := htemplate.New(); err != nil {
			return err
		}

		err := runner.New(options, func(result interface{}) {
			r := result.(*core.Result)

			options.OptLock.Lock()
			defer options.OptLock.Unlock()

			if !options.Silent {
				options.CurrentCount++
			}

			if r.IsVul {
				r.PrintColorResultInfoConsole()

				if len(r.Output) > 0 {
					go func() {
						htemplate.AppendMutex.Lock()
						htemplate.Result = r
						htemplate.Append()
						htemplate.AppendMutex.Unlock()
					}()
				}
			}

			if !options.Silent {
				fmt.Printf("\r%d/%d | %d%% ", options.CurrentCount, options.Count, options.CurrentCount*100/options.Count)
			}
		})
		if err != nil {
			return err
		}

		return err
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(log.LogColor.High("Failed to start afrog，", err.Error()))
	}
}

func PrintTraceInfo(result *core.Result) {
	for i, v := range result.AllPocResult {
		log.Log().Info(fmt.Sprintf("\r\n%s（%d）\r\n%s\r\n\r\n%s（%d）\r\n%s\r\n", "Request:", i, v.ReadFullResultRequestInfo(), "Response:", i, v.ReadFullResultResponseInfo()))
	}
}
