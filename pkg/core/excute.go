package core

import (
	"context"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
)

var (
	ReverseCeyeApiKey string
	ReverseCeyeDomain string

	Ticker *time.Ticker
)

type TargetAndPocs struct {
	Target string
	Poc    poc.Poc
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
	e.options.Count += e.options.Targets.Len() * len(newPocSlice)

	// poc scan
	Ticker = time.NewTicker(time.Second / time.Duration(e.options.RateLimit))
	var wg sync.WaitGroup

	p, _ := ants.NewPoolWithFunc(e.options.Concurrency, func(p any) {
		defer wg.Done()
		<-Ticker.C

		tap := p.(*TargetAndPocs)

		if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.options.Timeout)*time.Second)
			defer cancel()
			e.executeExpression(ctx, tap.Target, &tap.Poc)
		}

	})
	defer p.Release()

	for _, poc := range newPocSlice {
		for _, t := range e.options.Targets.List() {
			wg.Add(1)
			p.Invoke(&TargetAndPocs{Target: t.(string), Poc: poc})
		}
	}

	wg.Wait()
}

func (e *Engine) executeExpression(ctx context.Context, target string, poc *poc.Poc) {
	c := e.AcquireChecker()
	defer e.ReleaseChecker(c)

	defer func() {
		// https://github.com/zan8in/afrog/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
		}
	}()

	// yaml poc check
	c.Check(ctx, target, poc)
	c.Options.ApiCallBack(c.Result)

}
