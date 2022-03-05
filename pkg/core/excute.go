package core

import (
	"math/rand"
	"time"

	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
)

func (e *Engine) Execute(allPocsYamlSlice utils.StringSlice) {
	var pocSlice []poc.Poc
	for _, pocYaml := range allPocsYamlSlice {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
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
	// log.Log().Debug(fmt.Sprintf("scan pocs count:%d", len(pocSlice)))
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
	// log.Log().Debug(fmt.Sprintf("scan targets count:%d", len(allTargets)))
	randSleep()
}

func (e *Engine) executeExpression(target string, poc poc.Poc) {
	defer func() {
		if r := recover(); r != nil {
			log.Log().Error("gorutine recover() error from pkg/core/exccute/executeExpression")
		}
	}()
	c := NewChecker(*e.options, target, poc)
	c.Check()
	randSleep()
}

func randSleep() {
	ms := 500 + rand.Intn(500)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
