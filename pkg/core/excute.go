package core

import (
	"sync"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/pkg/gopoc"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
)

var (
	ReverseCeyeApiKey string
	ReverseCeyeDomain string
)

type TargetAndPocs struct {
	Target string
	PocKey string
}

func (e *Engine) Execute(allPocsYamlSlice, allPocsEmbedYamlSlice utils.StringSlice) {
	ReverseCeyeApiKey = e.options.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = e.options.Config.Reverse.Ceye.Domain

	var pocSlice []poc.Poc

	for _, pocYaml := range allPocsYamlSlice {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
			log.Log().Error(err.Error())
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	for _, pocEmbedYaml := range allPocsEmbedYamlSlice {
		p, err := pocs.ReadPocs(pocEmbedYaml)
		if err != nil {
			log.Log().Error(err.Error())
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	if len(e.options.PocsFilePath) == 0 {
		// added gopoc @date: 2022.6.19
		gopocNameSlice := gopoc.MapGoPocName()
		if len(gopocNameSlice) > 0 {
			for _, v := range gopocNameSlice {
				poc := poc.Poc{}
				poc.Gopoc = v
				poc.Id = v
				poc.Info.Name = v
				poc.Info.Severity = "unkown"
				pocSlice = append(pocSlice, poc)
			}
		}
	}

	// added search poc by keywords
	newPocSlice := []poc.Poc{}
	if len(e.options.Search) > 0 && e.options.SetSearchKeyword() {
		for _, v := range pocSlice {
			if e.options.CheckPocKeywords(v.Id, v.Info.Name) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else if len(e.options.Severity) > 0 && e.options.SetSeverityKeyword() {
		// added severity filter @date: 2022.6.13 10:58
		for _, v := range pocSlice {
			if e.options.CheckPocSeverityKeywords(v.Info.Severity) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else {
		newPocSlice = append(newPocSlice, pocSlice...)
	}

	// init scan sum
	e.options.Count += len(e.options.Targets) * len(newPocSlice)

	// health check
	doHealthCheck(newPocSlice)

	// handle all afrog-pocs
	allTargetAndPocs := []TargetAndPocs{}
	pocsMap := make(map[string]poc.Poc)
	for _, np := range newPocSlice {
		pocsMap[np.Id] = np
		for _, target := range e.options.Targets {
			allTargetAndPocs = append(allTargetAndPocs, TargetAndPocs{Target: target, PocKey: np.Id})
		}
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(e.workPool.config.PocConcurrency, func(p any) {
		e.executeTargets(p.(poc.Poc))
		wg.Done()
	})
	defer p.Release()
	for _, poc := range newPocSlice {
		wg.Add(1)
		_ = p.Invoke(poc)
	}
	wg.Wait()
}

func (e *Engine) executeTargets(poc1 poc.Poc) {
	defer func() {
		if r := recover(); r != nil {
			log.Log().Error("gorutine recover() error from pkg/core/exccute/excutTargets")
		}
	}()

	allTargets := e.options.Targets
	if len(allTargets) == 0 {
		log.Log().Error("executeTargets failed, no targets")
		return
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(e.workPool.config.TargetConcurrency, func(wgTask any) {
		defer wg.Done()
		target := wgTask.(poc.WaitGroupTask).Value.(string)
		// key := wgTask.(poc.WaitGroupTask).Key
		//add: check target alive
		if e.options.TargetLive.HandleTargetLive(target, -1) != -1 {
			e.executeExpression(target, poc1)
		} else {
			e.executeExpression("", poc1)
		}

	})
	defer p.Release()
	for k, target := range allTargets {
		wg.Add(1)
		_ = p.Invoke(poc.WaitGroupTask{Value: target, Key: k})
	}
	wg.Wait()
}

func (e *Engine) executeExpression(target string, poc poc.Poc) {
	defer func() {
		if r := recover(); r != nil {
			log.Log().Error("gorutine recover() error from pkg/core/exccute/executeExpression")
		}
	}() // https://github.com/zan8in/afrog/issues/7

	// fmt.Println("target the number of goroutines: ", runtime.NumGoroutine())

	c := e.AcquireChecker()
	defer e.ReleaseChecker(c)

	// gopoc check
	if len(poc.Gopoc) > 0 {
		if err := c.CheckGopoc(target, poc.Gopoc); err != nil {
			log.Log().Error(err.Error())
		}
		return
	}

	// yaml poc check
	if err := c.Check(target, poc); err != nil {
		log.Log().Error(err.Error())
	}
}

func doHealthCheck(pocs []poc.Poc) {
	pocIds := []string{}
	repeatPocIds := []string{}
	for _, np := range pocs {
		if len(pocIds) == 0 {
			pocIds = append(pocIds, np.Id)
			continue
		}
		repeat := false
		for _, id := range pocIds {
			if id == np.Id {
				repeatPocIds = append(repeatPocIds, id)
				repeat = true
				break
			}
		}
		if !repeat {
			pocIds = append(pocIds, np.Id)
		}
		repeat = false
	}

	if len(repeatPocIds) > 0 {
		gologger.Error().Msgf("Health check:")
		for _, h := range repeatPocIds {
			gologger.Error().Msgf("%s ", h)
		}
		gologger.Fatal().Msgf("Already exists\n")
	}

}
