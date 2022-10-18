package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

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
	"github.com/zan8in/afrog/pocs"
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
		&cli.StringFlag{Name: "scan-stable", Aliases: []string{"ss"}, Destination: &options.ScanStable, Value: "", Usage: "scan stable. Possible values: 1(generally)(default), 2(normal), 3(stablize)"},
		&cli.BoolFlag{Name: "silent", Destination: &options.Silent, Value: false, Usage: "no progress, only results"},
		&cli.BoolFlag{Name: "nofinger", Aliases: []string{"nf"}, Destination: &options.NoFinger, Value: false, Usage: "disable fingerprint"},
		&cli.BoolFlag{Name: "notips", Aliases: []string{"nt"}, Destination: &options.NoTips, Value: false, Usage: "disable show tips"},
		&cli.BoolFlag{Name: "updatepocs", Aliases: []string{"up"}, Destination: &options.UpdatePocs, Value: false, Usage: "update afrog-pocs"},
		&cli.BoolFlag{Name: "printpocs", Aliases: []string{"pp"}, Destination: &options.PrintPocs, Value: false, Usage: "print afrog-pocs list"},
		// &cli.BoolFlag{Name: "webport", Aliases: []string{"wp"}, Destination: &options.WebPort, Value: false, Usage: "enable web port scan, default top 1000 port"},
		// &cli.StringFlag{Name: "port", Destination: &options.Port, Value: "", Usage: "web port scan, default top 1000, eg: --port 80,443,8000-9000"},
	}

	app.Action = func(c *cli.Context) error {
		// print pocs list
		if options.PrintPocs {
			plist, err := pocs.PrintPocs()
			if err != nil {
				return err
			}
			for _, v := range plist {
				fmt.Println(v)
			}
			fmt.Println("PoC count: ", len(plist))
			return nil
		}

		starttime := time.Now()
		upgrade := upgrade.New()
		upgrade.IsUpdatePocs = options.UpdatePocs
		upgrade.UpgradeAfrogPocs()

		runner.ShowBanner2(upgrade.LastestAfrogVersion)

		printPathLog(upgrade)

		if len(options.Output) == 0 {
			options.Output = utils.GetNowDateTimeReportName() + ".html"
		}

		htemplate.Filename = options.Output
		if err := htemplate.New(); err != nil {
			return err
		}

		// fixed 99% bug
		go func() {
			startcount := options.CurrentCount
			for {
				time.Sleep(3 * time.Minute)
				if options.CurrentCount > 0 && startcount == options.CurrentCount {
					endtime := time.Now()
					fmt.Println(log.LogColor.High("Error, Time: ", endtime.Sub(starttime)))
					os.Exit(1)
				}
				startcount = options.CurrentCount
			}
		}()

		err := runner.New(options, htemplate, func(result any) {
			r := result.(*core.Result)

			lock.Lock()

			if !options.Silent {
				options.CurrentCount++
			}

			if r.IsVul {
				if r.FingerResult != nil {
					fr := r.FingerResult.(fingerprint.Result)
					printFingerprintInfoConsole(fr)
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

		endtime := time.Now()
		fmt.Println(log.LogColor.Vulner(" Time: ", endtime.Sub(starttime)))

		return err
	}

	err := app.Run(os.Args)
	if err != nil && !options.UpdatePocs {
		fmt.Println(runner.ShowTips())
		fmt.Println(log.LogColor.High("start afrog failed，", err.Error()))
	}

	utils.RandSleep(1000)
}

func printFingerprintInfoConsole(fr fingerprint.Result) {
	if len(fr.StatusCode) > 0 {
		statusCode := log.LogColor.Vulner("" + fr.StatusCode + "")
		if !strings.HasPrefix(fr.StatusCode, "2") {
			statusCode = log.LogColor.Midium("" + fr.StatusCode + "")
		}
		fmt.Printf("\r" + fr.Url + " " +
			statusCode + " " +
			fr.Title + " " +
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
