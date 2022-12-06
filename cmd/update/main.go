package main

import (
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/goflags"
)

var options = &config.Options{}

func main() {
	// runner.UpdateAfrogVersionToLatest(true)
	readConfig()
}

func readConfig() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`afrog`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&options.Target, "target", "t", "", "target URLs/hosts to scan"),
		flagSet.StringVarP(&options.TargetsFilePath, "Targets", "T", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
	)

	flagSet.CreateGroup("pocs", "PoCs",
		flagSet.StringVarP(&options.PocsFilePath, "pocs", "P", "", "poc.yaml or poc directory paths to include in the scan（no default `afrog-pocs` directory）"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "output html report, eg: -o result.html"),
		flagSet.BoolVarP(&options.PrintPocs, "printpocs", "pp", false, "print afrog-pocs list"),
	)

	flagSet.CreateGroup("filters", "Filtering",
		flagSet.StringVarP(&options.Search, "search", "s", "", "search PoC by `keyword` , eg: -s tomcat,phpinfo"),
		flagSet.StringVarP(&options.Severity, "severity", "S", "", "pocs to run based on severity. Possible values: info, low, medium, high, critical, unknown"),
	)

	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.BoolVar(&options.Silent, "silent", false, "no progress, only results"),
		flagSet.BoolVarP(&options.NoFinger, "nofinger", "nf", false, "disable fingerprint"),
		flagSet.BoolVarP(&options.NoTips, "notips", "nt", false, "disable show tips"),
		flagSet.StringVarP(&options.ScanStable, "scan-stable", "ss", "", "scan stable. Possible values: 1(generally)(default), 2(normal), 3(stablize)"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVar(&options.UpdateAfrogVersion, "update", false, "update afrog engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdatePocs, "update-pocs", "up", false, "update afrog-pocs to latest released version"),
	)

	_ = flagSet.Parse()

}
