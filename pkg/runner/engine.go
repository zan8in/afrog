package runner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"strconv"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
	sliceutil "github.com/zan8in/pins/slice"
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
	options     *config.Options
	ticker      *time.Ticker
	mu          sync.Mutex
	paused      bool
	stopped     bool
	quit        chan struct{}
	activeTasks int64
}

func NewEngine(options *config.Options) *Engine {
	engine := &Engine{
		options: options,
		quit:    make(chan struct{}),
	}
	return engine
}

func (runner *Runner) Execute() {

	options := runner.options

	pocSlice := options.CreatePocList()

	reversePocs, otherPocs := options.ReversePoCs(pocSlice)

	// fmt.Println(len(reversePocs), len(otherPocs), len(pocSlice))
	// 如果无 OOB PoC 将跳过 OOB 存活检测
	// 在SDK模式下，只有明确启用OOB时才进行连接检测
	if len(reversePocs) > 0 {
		// 检查是否是SDK模式且未启用OOB
		if options.SDKMode && !options.EnableOOB {
			// SDK模式下未启用OOB，跳过连接检测
			OOB = nil
			OOBAlive = false
		} else {
			// 非SDK模式或已启用OOB，执行正常的连接检测
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
		}
		// if !OOBAlive {
		// 	gologger.Error().Msg("Using OOB Server: " + options.OOB + " is not vaild")
		// }
	}

	runner.printOOBStatus(reversePocs)

	// portscan pre-scan: run after OOB status output to ensure ordering
	if options.PortScan {
		hostSeen := make(map[string]struct{})
		hosts := make([]string, 0)
		normalizePreScanTarget := func(raw string) string {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				return ""
			}
			if strings.Contains(raw, "://") {
				return strings.TrimSpace(utils.ExtractHost(raw))
			}
			if strings.Contains(raw, "/") {
				if _, _, err := net.ParseCIDR(raw); err == nil {
					return raw
				}
				return strings.TrimSpace(utils.ExtractHost(raw))
			}
			if strings.Contains(raw, "-") {
				parts := strings.Split(raw, "-")
				if len(parts) == 2 && net.ParseIP(strings.TrimSpace(parts[0])) != nil && net.ParseIP(strings.TrimSpace(parts[1])) != nil {
					return raw
				}
			}
			return strings.TrimSpace(utils.ExtractHost(raw))
		}
		for _, t := range runner.options.Targets.List() {
			raw := strings.TrimSpace(fmt.Sprintf("%v", t))
			if raw == "" {
				continue
			}
			h := normalizePreScanTarget(raw)
			if h == "" {
				continue
			}
			if _, ok := hostSeen[h]; !ok {
				hostSeen[h] = struct{}{}
				hosts = append(hosts, h)
			}
		}
		if len(hosts) > 0 {
			psOpts := portscan.DefaultOptions()
			psOpts.Targets = hosts
			psOpts.Proxy = options.Proxy
			// Let portscan module handle its own output and progress
			psOpts.Debug = !options.Silent
			psOpts.Quiet = false
			if options.PSPorts != "" {
				psOpts.Ports = options.PSPorts
			}
			// Do not override module logging flags here
			if options.PSRateLimit > 0 {
				psOpts.RateLimit = options.PSRateLimit
			}
			if options.PSTimeout > 0 {
				psOpts.Timeout = time.Duration(options.PSTimeout) * time.Millisecond
			}
			if options.PSRetries > 0 {
				psOpts.Retries = options.PSRetries
			}
			if options.PSSkipDiscovery {
				psOpts.SkipDiscovery = true
			}
			if options.PSS4Chunk != 0 {
				psOpts.S4ChunkSize = options.PSS4Chunk
			}
			open := make(map[string][]int)
			psOpts.OnResult = func(r *portscan.ScanResult) {
				gologger.Print().Msgf("%s:%d", r.Host, r.Port)
				open[r.Host] = append(open[r.Host], r.Port)
			}
			if sc, err := portscan.NewScanner(psOpts); err == nil {
				_ = sc.Scan(context.Background())
				newTargets := make([]string, 0)
				for host, ports := range open {
					seenPort := make(map[int]struct{})
					for _, p := range ports {
						if _, ok := seenPort[p]; ok {
							continue
						}
						seenPort[p] = struct{}{}
						newTargets = append(newTargets, net.JoinHostPort(host, strconv.Itoa(p)))
					}
				}
				if len(newTargets) > 0 {
					options.Targets = sliceutil.SafeSlice{}
					for _, nt := range newTargets {
						options.Targets.Append(nt)
					}
				}
			}
		} else if !options.SDKMode {
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StageHostDiscovery, "skipped")
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StagePortScan, "skipped")
		}
	} else if !options.SDKMode {
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StageHostDiscovery, "skipped")
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StagePortScan, "skipped")
	}

	options.Count += options.Targets.Len() * len(pocSlice)

	if options.Smart {
		options.SmartControl()
	}

	if !options.SDKMode {
		gologger.Info().Msgf("%-9s | %-9s | targets=%d pocs=%d tasks=%d", utils.StageVulnScan, "started", options.Targets.Len(), len(pocSlice), options.Count)
	}

	// 开始 普通POC 扫描 @edit 2024/05/30
	rwg := sync.WaitGroup{}
	rwg.Add(1)
	go func() {
		defer rwg.Done()

		rate := options.RateLimit
		if rate <= 0 {
			rate = 1
		}
		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(rate))
		var wg sync.WaitGroup

		con := options.Concurrency
		if con <= 0 {
			con = 1
		}
		p, _ := ants.NewPoolWithFunc(con, func(p any) {

			defer wg.Done()
			runner.engine.waitTick()
			if runner.engine.stopped || runner.options.VulnerabilityScannerBreakpoint {
				return
			}

			tap := p.(*TransData)
			runner.exec(tap)

		})
		defer p.Release()

		for _, poc := range otherPocs {
			if options.VulnerabilityScannerBreakpoint {
				break
			}
			for _, t := range runner.options.Targets.List() {
				// check resume
				if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(poc.Id) {
					runner.NotVulCallback()
					continue
				}

				if options.VulnerabilityScannerBreakpoint {
					break
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

		oobRate := options.OOBRateLimit
		if oobRate <= 0 {
			baseRate := options.RateLimit
			if baseRate <= 0 {
				baseRate = 1
			}
			oobRate = baseRate
		}
		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(oobRate))
		var wg sync.WaitGroup

		oobCon := options.OOBConcurrency
		if oobCon <= 0 {
			baseCon := options.Concurrency
			if baseCon <= 0 {
				baseCon = 1
			}
			oobCon = baseCon
		}
		p, _ := ants.NewPoolWithFunc(oobCon, func(p any) {

			defer wg.Done()
			runner.engine.waitTick()
			if runner.engine.stopped || runner.options.VulnerabilityScannerBreakpoint {
				return
			}

			tap := p.(*TransData)
			runner.exec(tap)

		})
		defer p.Release()

		for _, poc := range reversePocs {
			if options.VulnerabilityScannerBreakpoint {
				break
			}
			for _, t := range runner.options.Targets.List() {
				if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(poc.Id) {
					runner.NotVulCallback()
					continue
				}

				if options.VulnerabilityScannerBreakpoint {
					break
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
		baseCtx := runner.ctx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		if baseCtx.Err() != nil {
			return
		}
		atomic.AddInt64(&runner.engine.activeTasks, 1)
		defer atomic.AddInt64(&runner.engine.activeTasks, -1)
		if options.PocExecutionDurationMonitor {
			done := make(chan struct{})
			go func() {
				runner.executeExpression(baseCtx, tap.Target, &tap.Poc)
				close(done)
			}()

			select {
			case <-done:
				return
			case <-baseCtx.Done():
				return
			case <-time.After(1 * time.Minute):
				gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, 1)))
				var num = 1
				for {
					select {
					case <-done:
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has completed execution, taking over [%d] minute.", tap.Target, tap.Poc.Id, num)))
						return
					case <-baseCtx.Done():
						return
					case <-time.After(1 * time.Minute):
						num++
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, num)))
					}
				}
			}
		} else {
			runner.executeExpression(baseCtx, tap.Target, &tap.Poc)
		}
	}
}

func (runner *Runner) executeExpression(ctx context.Context, target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)

	defer func() {
		// https://github.com/zan8in/afrog/v3/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			runner.OnResult(c.Result)
		}
	}()

	if ctx != nil {
		c.VariableMap[retryhttpclient.ContextVarKey] = ctx
	}
	c.Check(target, poc)
	runner.OnResult(c.Result)
}

func (e *Engine) waitTick() {
	if e.ticker == nil {
		return
	}
	start := time.Now()
	select {
	case <-e.ticker.C:
	case <-e.quit:
		return
	}
	retryhttpclient.AddTaskGateWait(time.Since(start))
	e.mu.Lock()
	for e.paused {
		e.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		e.mu.Lock()
	}
	e.mu.Unlock()
}

func (e *Engine) Pause() {
	e.mu.Lock()
	e.paused = true
	e.mu.Unlock()
	gologger.Debug().Msgf("engine paused: ticker gated")
}

func (e *Engine) Resume() {
	e.mu.Lock()
	e.paused = false
	e.mu.Unlock()
	gologger.Debug().Msgf("engine resumed: ticker released")
}

func (e *Engine) IsPaused() bool {
	e.mu.Lock()
	p := e.paused
	e.mu.Unlock()
	return p
}

func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.stopped {
		e.stopped = true
		if e.ticker != nil {
			e.ticker.Stop()
		}
		close(e.quit)
	}
	e.mu.Unlock()
	gologger.Debug().Msgf("engine stopped: ticker stopped and scheduling halted")
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
	// 在SDK模式下，不显示OOB状态信息，由SDK自己控制显示
	if runner.options.SDKMode {
		return
	}

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
