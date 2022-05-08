package core

import (
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	ReverseCeyeApiKey string
	ReverseCeyeDomain string
)

func (e *Engine) Execute(allPocsYamlSlice utils.StringSlice) {
	ReverseCeyeApiKey = e.options.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = e.options.Config.Reverse.Ceye.Domain

	//http2.Init(e.options)

	var pocSlice []poc.Poc

	for _, pocYaml := range allPocsYamlSlice {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
			log.Log().Error(err.Error())
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	swg := e.workPool.PocSwg
	for _, p := range pocSlice {
		swg.Add()
		go func(p poc.Poc) {
			defer swg.Done()
			e.executeTargets(p)
		}(p)
	}
	e.workPool.Wait()
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

	wg := e.workPool.NewPool(e.workPool.config.TargetConcurrencyType)
	for _, target := range allTargets {
		wg.WaitGroup.Add()
		go func(target string, poc1 poc.Poc) {
			defer wg.WaitGroup.Done()
			//fmt.Println("the number of goroutines: ", runtime.NumGoroutine())
			e.executeExpression(target, poc1)
		}(target, poc1)
	}
	wg.WaitGroup.Wait()
}

func (e *Engine) executeExpression(target string, poc poc.Poc) {
	defer func() {
		if r := recover(); r != nil {
			log.Log().Error("gorutine recover() error from pkg/core/exccute/executeExpression")
		}
	}() // https://github.com/zan8in/afrog/issues/7

	c := e.AcquireChecker()
	defer e.ReleaseChecker(c)
	if err := c.Check(target, poc); err != nil {
		log.Log().Error(err.Error())
	}
}
