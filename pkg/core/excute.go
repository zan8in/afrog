package core

import (
	"sync"

	"github.com/panjf2000/ants"
	"github.com/zan8in/afrog/pkg/gopoc"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
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

	// outdated: 2022.7.25
	// swg := e.workPool.PocSwg
	// swg := e.workPool.NewPool(e.workPool.config.PocConcurrencyType)
	// for _, p := range newPocSlice {
	// 	swg.WaitGroup.Add()
	// 	go func(p poc.Poc) {
	// 		defer swg.WaitGroup.Done()
	// 		e.executeTargets(p)
	// 	}(p)
	// }
	// swg.WaitGroup.Wait()

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(e.workPool.config.PocConcurrency, func(p interface{}) {
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

	// outdated: 2022.7.25
	// wg := e.workPool.NewPool(e.workPool.config.TargetConcurrencyType)
	// for k, target := range allTargets {
	// 	wg.WaitGroup.Add()
	// 	go func(k int, target string, poc1 poc.Poc) {
	// 		defer wg.WaitGroup.Done()

	// 		// add: check target alive
	// 		if alive := e.options.CheckLiveByCount(target); alive && !http2.IsFullHttpFormat(target) {
	// 			target = http2.CheckLive(target)
	// 			if !http2.IsFullHttpFormat(target) {
	// 				e.options.SetCheckLiveValue(target)
	// 			} else {
	// 				e.options.Targets[k] = target
	// 			}
	// 		}

	// 		e.executeExpression(target, poc1)

	// 		// fmt.Println("poc the number of goroutines: ", runtime.NumGoroutine())
	// 	}(k, target, poc1)
	// }
	// wg.WaitGroup.Wait()

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(e.workPool.config.TargetConcurrency, func(wgTask interface{}) {
		defer wg.Done()
		target := wgTask.(poc.WaitGroupTask).Value.(string)
		key := wgTask.(poc.WaitGroupTask).Key
		//add: check target alive
		if alive := e.options.CheckLiveByCount(target); alive && !http2.IsFullHttpFormat(target) {
			target = http2.CheckLive(target)
			if !http2.IsFullHttpFormat(target) {
				e.options.SetCheckLiveValue(target)
			} else {
				e.options.Targets[key] = target
			}
		}

		e.executeExpression(target, poc1)
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
