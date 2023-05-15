package runner

import (
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
)

var CheckerPool = sync.Pool{
	New: func() any {
		return &Checker{
			Options: &config.Options{},
			// OriginalRequest: &http.Request{},
			VariableMap: make(map[string]any),
			Result:      &result.Result{},
			CustomLib:   NewCustomLib(),
		}
	},
}

func (e *Engine) AcquireChecker() *Checker {
	c := CheckerPool.Get().(*Checker)
	c.Options = e.options
	c.Result.Output = e.options.Output
	return c
}

func (e *Engine) ReleaseChecker(c *Checker) {
	// *c.OriginalRequest = http.Request{}
	c.VariableMap = make(map[string]any)
	c.Result = &result.Result{}
	c.CustomLib = NewCustomLib()
	CheckerPool.Put(c)
}

type Engine struct {
	options *config.Options
	ticker  *time.Ticker
}

func NewEngine(options *config.Options) *Engine {
	engine := &Engine{
		options: options,
	}
	return engine
}

func (runner *Runner) Execute() {

	var pocSlice []poc.Poc

	for _, pocYaml := range runner.PocsYaml {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	for _, pocEmbedYaml := range runner.PocsEmbedYaml {
		p, err := pocs.ReadPocs(pocEmbedYaml)
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	// added search poc by keywords
	newPocSlice := []poc.Poc{}
	if len(runner.options.Search) > 0 && runner.options.SetSearchKeyword() {
		for _, v := range pocSlice {
			if runner.options.CheckPocKeywords(v.Id, v.Info.Name) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else if len(runner.options.Severity) > 0 && runner.options.SetSeverityKeyword() {
		// added severity filter @date: 2022.6.13 10:58
		for _, v := range pocSlice {
			if runner.options.CheckPocSeverityKeywords(v.Info.Severity) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else {
		newPocSlice = append(newPocSlice, pocSlice...)
	}

	latestPocSlice := []poc.Poc{}
	order := []string{"info", "low", "medium", "high", "critical"}
	for _, o := range order {
		for _, s := range newPocSlice {
			if o == strings.ToLower(s.Info.Severity) {
				latestPocSlice = append(latestPocSlice, s)
			}
		}
	}

	runner.options.Count += runner.options.Targets.Len() * len(latestPocSlice)

	// runner.authomaticThread()

	runner.engine.ticker = time.NewTicker(time.Second / time.Duration(runner.options.RateLimit))
	var wg sync.WaitGroup

	p, _ := ants.NewPoolWithFunc(runner.options.Concurrency, func(p any) {
		defer wg.Done()
		<-runner.engine.ticker.C

		tap := p.(*TransData)

		if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {
			runner.executeExpression(tap.Target, &tap.Poc)
		}

	})
	defer p.Release()

	for _, poc := range latestPocSlice {
		for _, t := range runner.options.Targets.List() {
			wg.Add(1)
			p.Invoke(&TransData{Target: t.(string), Poc: poc})
		}
	}

	wg.Wait()
}

func (runner *Runner) executeExpression(target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)

	defer func() {
		// https://github.com/zan8in/afrog/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			runner.OnResult(c.Result)
		}
	}()

	c.Check(target, poc)
	runner.OnResult(c.Result)
}

type TransData struct {
	Target string
	Poc    poc.Poc
}

// func (runner *Runner) authomaticThread() {
// 	if runner.options.Concurrency == 25 && runner.options.Count >= 8000 {
// 		runner.options.Concurrency = runtime.NumCPU() * 50
// 	}
// }
