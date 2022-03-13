package core

import (
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
)

func (e *Engine) Execute(allPocsYamlSlice utils.StringSlice) {
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

	wg := e.workPool.NewPool(e.workPool.config.TargetConcurrencyType)

	allTargets := e.options.Targets
	if len(allTargets) == 0 {
		log.Log().Error("executeTargets failed, no targets")
		return
	}

	for _, target := range allTargets {
		wg.WaitGroup.Add()
		go func(target string, poc1 poc.Poc) {
			defer wg.WaitGroup.Done()
			e.executeExpression(target, poc1)
		}(target, poc1)
	}
	wg.WaitGroup.Wait()

	// utils.RandSleep(500)
}

func (e *Engine) executeExpression(target string, poc poc.Poc) {
	defer func() {
		if r := recover(); r != nil {
			log.Log().Error("gorutine recover() error from pkg/core/exccute/executeExpression")
		}
	}()

	c := NewChecker(*e.options, target, poc)
	if err := c.Check(); err != nil {
		log.Log().Error(err.Error())
	}

	// utils.RandSleep(500)
}
