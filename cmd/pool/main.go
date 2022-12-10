package main

import (
	"sync"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	c := catalog.New("./pocs/temp/afrog-pocs")
	// allPocsYamlSlice, err := c.GetPocPath("C:\\Users\\zanbi\\afrog-pocs")
	allPocsYamlSlice, err := c.GetPocPath("./pocs/temp/afrog-pocs")
	if err != nil && len(allPocsYamlSlice) == 0 {
		gologger.Fatal().Msg(err.Error())
	}
	var pocSlice []poc.Poc
	for _, pocYaml := range allPocsYamlSlice {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	allTargets, err := utils.ReadFileLineByLine("./nacos.txt")
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	pool := core.NewPool(allTargets, pocSlice)
	defer pool.ReleaseAll()

	wgpoc := sync.WaitGroup{}
	for i := 0; i < core.MAX_QUEUE_SIZE; i++ {
		wgpoc.Add(1)
		go pool.PocConsumer(&wgpoc)
	}

	wgtarget := sync.WaitGroup{}
	for i := 0; i < core.MAX_PQUEUE_SIZE; i++ {
		wgtarget.Add(1)
		go pool.TargetConsumer(&wgtarget, nil)
	}

	pool.Producer()

	pool.Stop()

	wgpoc.Wait()

	wgtarget.Wait()

	gologger.Fatal().Msgf("%d * %d = %d", len(allTargets), len(pocSlice), len(allTargets)*len(pocSlice))

}
