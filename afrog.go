package afrog

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/result"
	"github.com/zan8in/afrog/pkg/runner"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

type Scanner struct {
	Target             []string
	TargetsFile        string
	PocFile            string
	Output             string
	Json               string
	JsonAll            string
	Search             string
	Silent             bool
	Severity           string
	Update             bool
	DisableUpdateCheck bool
	MonitorTargets     bool
	RateLimit          int
	Concurrency        int
	Retries            int
	MaxHostError       int
	Timeout            int
	Proxy              string
	MaxRespBodySize    int
	DisableOutputHtml  bool
}

func NewScanner(target []string, opt Scanner) error {

	s := &Scanner{}

	s.Target = target
	s.TargetsFile = opt.WithTargetsFile()
	s.PocFile = opt.WithPocFile()
	s.Output = opt.WithOutput()
	s.Json = opt.WithJson()
	s.JsonAll = opt.WithJsonAll()
	s.Search = opt.WithSearch()
	s.Silent = opt.WithSilent()
	s.Severity = opt.WithSeverity()
	s.Update = opt.WithUpdate()
	s.DisableUpdateCheck = opt.WithDisableUpdateCheck()
	s.MonitorTargets = opt.WithMonitorTargets()
	s.RateLimit = opt.WithRateLimit()
	s.Concurrency = opt.WithConcurrency()
	s.Retries = opt.WithRetries()
	s.MaxHostError = opt.WithMaxHostError()
	s.Timeout = opt.WithTimeout()
	s.Proxy = opt.WithProxy()
	s.MaxRespBodySize = opt.WithMaxRespBodySize()
	s.DisableOutputHtml = opt.WithDisableOutputHtml()

	if err := s.verifyOptions(); err != nil {
		return err
	}

	options := &config.Options{
		Target:             s.Target,
		TargetsFile:        s.TargetsFile,
		PocFile:            s.PocFile,
		Output:             s.Output,
		Json:               s.Json,
		JsonAll:            s.JsonAll,
		Search:             s.Search,
		Silent:             s.Silent,
		Severity:           s.Severity,
		Update:             s.Update,
		DisableUpdateCheck: s.DisableUpdateCheck,
		MonitorTargets:     s.MonitorTargets,
		RateLimit:          s.RateLimit,
		Concurrency:        s.Concurrency,
		Retries:            s.Retries,
		MaxHostError:       s.MaxHostError,
		Timeout:            s.Timeout,
		Proxy:              s.Proxy,
		MaxRespBodySize:    s.MaxRespBodySize,
		DisableOutputHtml:  s.DisableOutputHtml,
	}

	config, err := config.NewConfig()
	if err != nil {
		return err
	}

	options.Config = config

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("Could not create runner: %s\n", err)
		os.Exit(0)
	}

	var (
		lock      = sync.Mutex{}
		starttime = time.Now()
		number    uint32
	)
	r.OnResult = func(result *result.Result) {

		if !options.Silent {
			defer func() {
				atomic.AddUint32(&options.CurrentCount, 1)
				if !options.Silent {
					fmt.Printf("\r%d%% (%d/%d), %s", int(options.CurrentCount)*100/int(options.Count), options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if result.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			if !options.DisableOutputHtml {
				r.Report.SetResult(result)
				r.Report.Append(utils.GetNumberText(int(number)))
			}

			if len(options.Json) > 0 || len(options.JsonAll) > 0 {
				r.JsonReport.SetResult(result)
				r.JsonReport.Append()
			}

			lock.Unlock()
		}

	}

	if err := r.Run(); err != nil {
		gologger.Error().Msgf("runner run err: %s\n", err)
		os.Exit(0)
	}

	if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
			os.Exit(0)
		}
	}

	time.Sleep(time.Second * 3)

	return nil
}

func (opt *Scanner) verifyOptions() error {

	if opt.Update {
		err := config.UpdateAfrogEngine()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		os.Exit(0)
	}

	upgrade, err := upgrade.NewUpgrade(true)
	if err != nil {
		return err
	}

	if !opt.DisableUpdateCheck {
		info, _ := upgrade.UpgradePocs()
		if len(info) > 0 {
			gologger.Info().Msg(info)
		}
	}

	if len(opt.Target) == 0 && len(opt.TargetsFile) == 0 {
		return fmt.Errorf("either `target` or `target-file` must be set")
	}

	config.ShowBanner(upgrade)

	return nil
}

func (s *Scanner) WithTargetsFile() string {
	if len(s.TargetsFile) > 0 {
		return s.TargetsFile
	}
	return ""
}

func (s *Scanner) WithPocFile() string {
	if len(s.PocFile) > 0 {
		return s.PocFile
	}
	return ""
}

func (s *Scanner) WithOutput() string {
	if len(s.Output) > 0 {
		return s.Output
	}
	return ""
}

func (s *Scanner) WithJson() string {
	if len(s.Json) > 0 {
		return s.Json
	}
	return ""
}
func (s *Scanner) WithJsonAll() string {
	if len(s.JsonAll) > 0 {
		return s.JsonAll
	}
	return ""
}
func (s *Scanner) WithSearch() string {
	if len(s.Search) > 0 {
		return s.Search
	}
	return ""
}

func (s *Scanner) WithSilent() bool {
	return s.Silent
}

func (s *Scanner) WithSeverity() string {
	if len(s.Search) > 0 {
		return s.Search
	}
	return ""
}

func (s *Scanner) WithUpdate() bool {
	return s.Update
}
func (s *Scanner) WithDisableUpdateCheck() bool {
	return s.DisableUpdateCheck
}
func (s *Scanner) WithMonitorTargets() bool {
	return s.MonitorTargets
}

func (s *Scanner) WithRateLimit() int {
	if s.RateLimit > 0 {
		return s.RateLimit
	}
	return 150
}
func (s *Scanner) WithConcurrency() int {
	if s.Concurrency > 0 {
		return s.Concurrency
	}
	return 25
}
func (s *Scanner) WithRetries() int {
	if s.Retries > 0 {
		return s.Retries
	}
	return 1
}
func (s *Scanner) WithMaxHostError() int {
	if s.MaxHostError > 0 {
		return s.MaxHostError
	}
	return 3
}
func (s *Scanner) WithTimeout() int {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 10
}
func (s *Scanner) WithProxy() string {
	if len(s.Proxy) > 0 {
		return s.Proxy
	}
	return ""
}
func (s *Scanner) WithMaxRespBodySize() int {
	if s.MaxRespBodySize > 0 {
		return s.MaxRespBodySize
	}
	return 2
}
func (s *Scanner) WithDisableOutputHtml() bool {
	return s.DisableOutputHtml
}
