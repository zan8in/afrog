package main

import (
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
)

var options = &config.Options{}

func main() {
	readConfig()
	_, err := runner.New(options)
	if err != nil {
		log.Log().Fatal(err.Error())
	}
}

// func cmd() {
// 	app := cli.NewApp()
// 	app.Name = "afrog"
// 	app.Usage = "Use with caution. You are responsible for your actions\nDevelopers assume no liability and are not responsible for any misuse or damage.\n"
// 	app.UsageText = "dcain [global options] command [command options] [arguments...] \n	 eg: afrog -t http://example.com"
// 	app.Version = options.Config.ConfigVersion
// 	app.Flags = []cli.Flag{
// 		&cli.StringFlag{
// 			Name:    "targets",
// 			Aliases: []string{"t"},
// 			Value:   "",
// 			Usage:   "",
// 		},
// 	}
// 	app.Action = run

// 	err := app.Run(os.Args)
// 	if err != nil {
// 		log.Log().Fatal(fmt.Sprintf("cli.RunApp err: %v", err))
// 		return
// 	}
// }

// func run(c *cli.Context) error {
// 	path := []string{options.PocsDirectory[0]}
// 	c1 := catalog.New("")
// 	r := c1.GetPocsPath(path)
// 	if len(r) == 0 {
// 		log.Log().Fatal("no pocs file")
// 	}
// 	fmt.Println(r)

// 	poc2, err := poc.ReadPocs(r[0])
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	fmt.Println(poc2)

// 	return nil
// }

func readConfig() {
	url1 := "http://192.168.66.168"
	options.Targets.Set(url1)
	// options.Targets.Set(url2)
	// options.Targets.Set(url3)

	// read pocs from afrog-pocs directory
	pocsDir, err := poc.SetPocDirectory()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.PocsDirectory.Set(pocsDir)

	// read afrog-config.yaml file
	config, err := config.New()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.Config = config
}
