package runner

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/result"
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

	options.Count += options.Targets.Len() * len(pocSlice)

	if options.Smart {
		options.SmartControl()
	}

	runner.engine.ticker = time.NewTicker(time.Second / time.Duration(options.RateLimit))
	var wg sync.WaitGroup

	p, _ := ants.NewPoolWithFunc(options.Concurrency, func(p any) {

		defer wg.Done()
		<-runner.engine.ticker.C

		tap := p.(*TransData)

		// if options.MonitorPocExecution {
		// 	startTime := time.Now()

		// 	closeChan := make(chan bool)
		// 	defer func() {
		// 		closeChan <- true
		// 	}()

		// 	timerChan := make(chan bool)
		// 	go func() {
		// 		for {
		// 			select {
		// 			case <-timerChan:
		// 				fmt.Println("Timeout! 10 seconds have passed.")
		// 				ticker := time.NewTicker(1 * time.Minute)
		// 				for range ticker.C {
		// 					endTime := time.Now()
		// 					elapsedTime := endTime.Sub(startTime)
		// 					fmt.Printf(" [%s] [%s] TIME: %v\n", tap.Target, tap.Poc.Id, parseElaspsedTime(elapsedTime))
		// 				}
		// 			case <-closeChan:
		// 				return
		// 			}
		// 		}CVE-2023-25157
		// 	}()
		// 	go func() {
		// 		time.Sleep(200 * time.Millisecond)
		// 		timerChan <- true
		// 	}()
		// }

		if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {

			// timeout := make(chan bool)

			// go func(target string, poc poc.Poc) {

			// start := time.Now()

			runner.executeExpression(tap.Target, &tap.Poc)

			// elapsed := time.Since(start)
			// fmt.Printf(target, poc.Id, " Thread finished in %v seconds\n", elapsed.Seconds())
			// timeout <- true

			// }(tap.Target, tap.Poc)

			// // 设置整体的超时时间为1分钟
			// select {
			// case <-timeout:
			// 	return
			// case <-time.After(1 * time.Minute):
			// 	fmt.Println(tap.Target, tap.Poc.Id, " Timeout: 1 minute elapsed")

			// 	// 设置每30秒提醒一次，直到所有线程都结束
			// 	for {
			// 		select {
			// 		case <-timeout:
			// 			fmt.Println(tap.Target, tap.Poc.Id, "All threads finished")
			// 			return
			// 		case <-time.After(30 * time.Second):
			// 			fmt.Println(tap.Target, tap.Poc.Id, " Still waiting...")
			// 		}
			// 	}
			// }
		}

	})
	defer p.Release()

	for _, poc := range pocSlice {
		for _, t := range runner.options.Targets.List() {
			wg.Add(1)
			p.Invoke(&TransData{Target: t.(string), Poc: poc})
		}
	}

	wg.Wait()
}

func parseElaspsedTime(time time.Duration) string {
	s := fmt.Sprintf("%v", time)
	if len(s) > 0 {
		if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ms") {
			t := strings.Replace(s, "s", "", -1)
			ts, err := strconv.ParseFloat(t, 64)
			if err != nil {
				return s
			}
			if ts >= 40 {
				return log.LogColor.Midium(s)
			}
		}
		if strings.HasSuffix(s, "m") {
			return log.LogColor.Red(s)
		}
	}
	return log.LogColor.Green(s)
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

func JndiTest() bool {
	url := "http://" + config.ReverseJndi + ":" + config.ReverseApiPort + "/?api=test"
	resp, _, err := retryhttpclient.Get(url)
	if err != nil {
		return false
	}
	if strings.Contains(string(resp), "no") || strings.Contains(string(resp), "yes") {
		return true
	}
	return false
}

func CeyeTest() bool {
	url := fmt.Sprintf("http://%s.%s", "test", config.ReverseCeyeDomain)
	resp, _, err := retryhttpclient.Get(url)
	if err != nil {
		return false
	}
	if strings.Contains(string(resp), "\"meta\":") || strings.Contains(string(resp), "201") {
		return true
	}
	return false
}
