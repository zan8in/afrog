package runner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/gologger"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
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

	options := runner.options

	pocSlice := options.CreatePocList()

	reversePocs, otherPocs := options.ReversePoCs(pocSlice)

	// fmt.Println(len(reversePocs), len(otherPocs), len(pocSlice))
	// 如果无 OOB PoC 将跳过 OOB 存活检测
	if len(reversePocs) > 0 {
		runner.options.SetOOBAdapter()
		if oobAdapter, err := oobadapter.NewOOBAdapter(options.OOB, &oobadapter.ConnectorParams{
			Key:     options.OOBKey,
			Domain:  options.OOBDomain,
			HTTPUrl: options.OOBHttpUrl,
			ApiUrl:  options.OOBApiUrl,
		}); err == nil {
			OOB = oobAdapter
			OOBAlive = OOB.IsVaild()
		} else {
			OOBAlive = false
		}
		// if !OOBAlive {
		// 	gologger.Error().Msg("Using OOB Server: " + options.OOB + " is not vaild")
		// }
	}

	runner.printOOBStatus(reversePocs)

	options.Count += options.Targets.Len() * len(pocSlice)

	if options.Smart {
		options.SmartControl()
	}

	// 开始 普通POC 扫描 @edit 2024/05/30
	rwg := sync.WaitGroup{}
	rwg.Add(1)
	go func() {
		defer rwg.Done()

		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(options.RateLimit))
		var wg sync.WaitGroup

		p, _ := ants.NewPoolWithFunc(options.Concurrency, func(p any) {

			defer wg.Done()
			<-runner.engine.ticker.C

			tap := p.(*TransData)
			runner.exec(tap)

		})
		defer p.Release()

		for _, poc := range otherPocs {
			for _, t := range runner.options.Targets.List() {
				// check resume
				if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(poc.Id) {
					runner.NotVulCallback()
					continue
				}

				wg.Add(1)
				p.Invoke(&TransData{Target: t.(string), Poc: poc})
			}
			// Record PoC completion progress
			runner.ScanProgress.Increment(poc.Id)
		}

		wg.Wait()
	}()
	rwg.Wait()

	// 开始 OOB POC 扫描  @edit 2024/05/30
	rwg = sync.WaitGroup{}
	rwg.Add(1)
	go func() {
		defer rwg.Done()

		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(options.OOBRateLimit))
		var wg sync.WaitGroup

		p, _ := ants.NewPoolWithFunc(options.OOBConcurrency, func(p any) {

			defer wg.Done()
			<-runner.engine.ticker.C

			tap := p.(*TransData)
			runner.exec(tap)

		})
		defer p.Release()

		for _, poc := range reversePocs {
			for _, t := range runner.options.Targets.List() {
				if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(poc.Id) {
					runner.NotVulCallback()
					continue
				}

				wg.Add(1)
				p.Invoke(&TransData{Target: t.(string), Poc: poc})
			}
			// Record PoC completion progress
			runner.ScanProgress.Increment(poc.Id)
		}
		wg.Wait()

	}()
	rwg.Wait()
}

func (runner *Runner) exec(tap *TransData) {
	options := runner.options

	if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {
		if options.PocExecutionDurationMonitor {
			timeout := make(chan bool)
			go func(target string, poc poc.Poc) {
				runner.executeExpression(tap.Target, &tap.Poc)
				timeout <- true
			}(tap.Target, tap.Poc)

			select {
			case <-timeout:
				return
			case <-time.After(1 * time.Minute):
				gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, 1)))
				var num = 1
				for {
					select {
					case <-timeout:
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has completed execution, taking over [%d] minute.", tap.Target, tap.Poc.Id, num)))
						return
					case <-time.After(1 * time.Minute):
						num++
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, num)))
					}
				}
			}
		} else {
			runner.executeExpression(tap.Target, &tap.Poc)
		}
	}
}

func (runner *Runner) executeExpression(target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)

	defer func() {
		// https://github.com/zan8in/afrog/v3/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			runner.OnResult(c.Result)
		}
	}()

	c.Check(target, poc)
	runner.OnResult(c.Result)
}

func (runner *Runner) NotVulCallback() {
	runner.OnResult(&result.Result{IsVul: false})
}

type TransData struct {
	Target string
	Poc    poc.Poc
}

// 获取OOB状态信息
func (runner *Runner) getOOBStatus(reversePocs []poc.Poc) (bool, string) {
	if len(reversePocs) == 0 {
		return true, "Not required (no OOB PoCs)"
	}

	runner.options.SetOOBAdapter()

	// 从配置中获取当前OOB服务名称
	serviceName := strings.ToLower(runner.options.OOB)

	if OOB == nil {
		return false, fmt.Sprintf("%s (Not configured)", serviceName)
	}

	if !OOB.IsVaild() {
		return false, fmt.Sprintf("%s (Connection failed)", serviceName)
	}

	return true, fmt.Sprintf("%s (Active)", serviceName)
}

// 新增OOB状态显示函数
func (runner *Runner) printOOBStatus(reversePocs []poc.Poc) {
	status, msg := runner.getOOBStatus(reversePocs)

	if !status {
		config.PrintStatusLine(
			log.LogColor.Red(config.GetErrorSymbol()),
			"OOB: ",
			log.LogColor.Red(msg),
			"",
		)
		config.PrintSeparator()

		return
	}
	config.PrintStatusLine(
		log.LogColor.Low(config.GetOkSymbol()),
		"OOB: ",
		log.LogColor.Green(msg),
		"",
	)

	config.PrintSeparator()
}

// func parseElaspsedTime(time time.Duration) string {
// 	s := fmt.Sprintf("%v", time)
// 	if len(s) > 0 {
// 		if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ms") {
// 			t := strings.Replace(s, "s", "", -1)
// 			ts, err := strconv.ParseFloat(t, 64)
// 			if err != nil {
// 				return s
// 			}
// 			if ts >= 40 {
// 				return log.LogColor.Midium(s)
// 			}
// 		}
// 		if strings.HasSuffix(s, "m") {
// 			return log.LogColor.Red(s)
// 		}
// 	}
// 	return log.LogColor.Green(s)
// }

// func JndiTest() bool {
// 	url := "http://" + config.ReverseJndi + ":" + config.ReverseApiPort + "/?api=test"
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "no") || strings.Contains(string(resp), "yes") {
// 		return true
// 	}
// 	return false
// }

// func CeyeTest() bool {
// 	url := fmt.Sprintf("http://%s.%s", "test", config.ReverseCeyeDomain)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "\"meta\":") || strings.Contains(string(resp), "201") {
// 		return true
// 	}
// 	return false
// }

// func EyeTest() bool {
// 	index := strings.Index(config.ReverseEyeDomain, ".")
// 	domain := config.ReverseEyeDomain

// 	if index != -1 {
// 		domain = config.ReverseEyeDomain[:index]
// 	}

// 	url := fmt.Sprintf("http://%s/api/dns/%s/test/?token=%s", config.ReverseEyeHost, domain, config.ReverseEyeToken)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "False") {
// 		return true
// 	}
// 	return false
// }
