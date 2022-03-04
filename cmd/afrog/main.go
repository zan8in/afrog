package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/operators/celgo"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
)

var options = &config.Options{}

func main() {
	readConfig()

	_, err := runner.New(options)
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	//log.Log().Debug("runner.catalog")
	// todo
	// 初始化配置内容
	// 初始化Pocs内容
	// sync.Work 控制扫描并发
	//

	//cmd()
	//testCel()
}

func cmd() {
	app := cli.NewApp()
	app.Name = "afrog"
	app.Usage = "Use with caution. You are responsible for your actions\nDevelopers assume no liability and are not responsible for any misuse or damage.\n"
	app.UsageText = "dcain [global options] command [command options] [arguments...] \n	 eg: afrog -t http://example.com"
	app.Version = options.Config.ConfigVersion
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "targets",
			Aliases: []string{"t"},
			Value:   "",
			Usage:   "",
		},
	}
	app.Action = run

	err := app.Run(os.Args)
	if err != nil {
		log.Log().Fatal(fmt.Sprintf("cli.RunApp err: %v", err))
		return
	}
}

func run(c *cli.Context) error {
	path := []string{options.PocsDirectory[0]}
	c1 := catalog.New("")
	r := c1.GetPocsPath(path)
	if len(r) == 0 {
		log.Log().Fatal("no pocs file")
	}
	fmt.Println(r)

	poc2, err := poc.ReadPocs(r[0])
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(poc2)

	return nil
}

func readConfig() {
	for i := 0; i < 10; i++ {

	}
	options.Targets.Set("http://example.com")
	options.Targets.Set("lankegp.com")

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

func testCel() {
	c := celgo.NewCustomLib()

	var protoResp = proto.Response{}
	protoResp.Body = []byte("test.php")

	var variableMap = map[string]interface{}{
		"response": &protoResp,
	}

	c.Run(`response.body.bcontains(b'te')`, variableMap, func(isVul interface{}, err error) {
		fmt.Println(isVul, err)
	})
}
