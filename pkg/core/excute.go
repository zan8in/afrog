package core

import (
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
)

var (
	ReverseCeyeApiKey string
	ReverseCeyeDomain string
)

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

	swg := e.workPool.PocSwg
	for _, p := range newPocSlice {
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
