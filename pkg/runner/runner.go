package runner

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/catalog"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/cyberspace"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/report"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/webhook/dingtalk"
	"github.com/zan8in/afrog/v3/pocs"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

type OnResult func(*result.Result)

var (
	OOB      *oobadapter.OOBAdapter
	OOBAlive bool
)

type Runner struct {
	options       *config.Options
	catalog       *catalog.Catalog
	Report        *report.Report
	JsonReport    *report.JsonReport
	OnResult      OnResult
	PocsYaml      utils.StringSlice
	PocsEmbedYaml utils.StringSlice
	engine        *Engine
	Ding          *dingtalk.Dingtalk
	ScanProgress  *ScanProgress
	Cyberspace    *cyberspace.Cyberspace
	// OOB           *oobadapter.OOBAdapter
}

func NewRunner(options *config.Options) (*Runner, error) {
	var err error

	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           options.Proxy,
		Timeout:         options.Timeout,
		Retries:         options.Retries,
		MaxRespBodySize: options.MaxRespBodySize,
	})

	runner := &Runner{options: options}

	runner.engine = NewEngine(options)

	if options.Dingtalk {
		runner.Ding, err = dingtalk.New(options.Config.Webhook.Dingtalk.Tokens,
			options.Config.Webhook.Dingtalk.AtMobiles,
			options.Config.Webhook.Dingtalk.Range,
			options.Config.Webhook.Dingtalk.AtAll)
		if err != nil {
			return nil, err
		}
	}

	// cyberspace
	if len(options.Cyberspace) > 0 && len(options.Query) > 0 {
		cyberspace, err := cyberspace.New(options.Config, options.Cyberspace, options.Query, options.QueryCount)
		if err != nil {
			return nil, err
		}
		runner.Cyberspace = cyberspace
	}

	// oobadapter
	// fmt.Println(options.OOB, options.OOBKey, options.OOBDomain, options.OOBApiUrl)

	if runner.ScanProgress, err = NewScanProgress(options.Resume); err != nil {
		return nil, fmt.Errorf("%s %s", options.Resume, err.Error())
	}

	// 在SDK模式下，不创建任何报告实例，避免自动创建reports目录
	if !options.SDKMode {
		jr, err := report.NewJsonReport(options.Json, options.JsonAll)
		if err != nil {
			return runner, fmt.Errorf("%s", err.Error())
		}
		runner.JsonReport = jr

		report, err := report.NewReport(options.Output, report.DefaultTemplate)
		if err != nil {
			return runner, fmt.Errorf("%s", err.Error())
		}
		runner.Report = report
	}

	seen := make(map[string]struct{}) // 避免重复添加

	if len(runner.options.Target) > 0 {
		for _, rawTarget := range runner.options.Target {
			trimmedTarget := strings.TrimSpace(rawTarget)
			if _, ok := seen[trimmedTarget]; !ok {
				seen[trimmedTarget] = struct{}{}
				if options.RestrictLocalNetworkAccess {
					if !utils.IsRestrictIP(trimmedTarget) {
						runner.options.Targets.Append(trimmedTarget)
					}
				} else {
					runner.options.Targets.Append(trimmedTarget)
				}
			}
		}

	}
	if len(runner.options.TargetsFile) > 0 {
		allTargets, err := utils.ReadFileLineByLine(runner.options.TargetsFile)
		if err != nil {
			return runner, err
		}
		for _, rawTarget := range allTargets {
			trimmedTarget := strings.TrimSpace(rawTarget)
			if len(trimmedTarget) > 0 {
				if _, ok := seen[trimmedTarget]; !ok {
					seen[trimmedTarget] = struct{}{}
					if options.RestrictLocalNetworkAccess {
						if !utils.IsRestrictIP(trimmedTarget) {
							runner.options.Targets.Append(trimmedTarget)
						}
					} else {
						runner.options.Targets.Append(trimmedTarget)
					}
				}
			}
		}
	}
	// cyberspace search
	if runner.Cyberspace != nil {
		cyberTargets, err := runner.Cyberspace.GetTargets()
		if err != nil {
			return runner, err
		}
		if len(cyberTargets) > 0 {
			for _, rawTarget := range cyberTargets {
				trimmedTarget := strings.TrimSpace(rawTarget)
				if len(trimmedTarget) > 0 {
					if _, ok := seen[trimmedTarget]; !ok {
						seen[trimmedTarget] = struct{}{}
						if options.RestrictLocalNetworkAccess {
							if !utils.IsRestrictIP(trimmedTarget) {
								runner.options.Targets.Append(trimmedTarget)
							}
						} else {
							runner.options.Targets.Append(trimmedTarget)
						}
					}
				}
			}
		}
	}
	if runner.options.Targets.Len() == 0 && runner.Cyberspace == nil {
		return runner, errors.New("target not found")
	}

	// init pocs
	if len(runner.options.PocFile) > 0 {
		runner.options.PocsDirectory.Set(runner.options.PocFile)
	} else {
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			runner.options.PocsDirectory.Set(pocsDir)
		}
		// append PoCs
		if len(runner.options.AppendPoc) > 0 {
			for _, p := range runner.options.AppendPoc {
				runner.options.PocsDirectory.Set(p)
			}
		}
	}

	allPocsYamlSlice := runner.catalog.GetPocsPath(runner.options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 && len(pocs.EmbedFileList) == 0 {
		return runner, errors.New("afrog-pocs not found")
	}

	runner.PocsYaml = allPocsYamlSlice
	runner.PocsEmbedYaml = pocs.EmbedFileList

	// checkReversePlatform()

	return runner, nil
}

func (runner *Runner) Run() error {

	if runner.options.MonitorTargets {
		go runner.monitorTargets()
	}

	runner.Execute()

	return nil
}

// func checkReversePlatform() {

// 	wg := sync.WaitGroup{}
// 	if len(config.ReverseJndi) > 0 && len(config.ReverseLdapPort) > 0 && len(config.ReverseApiPort) > 0 {
// 		wg.Add(1)

// 		go func() {
// 			defer wg.Done()

// 			if !JndiTest() {
// 				gologger.Info().Msg("Load of JNDI is failed")
// 				config.ReverseJndiLive = false
// 			} else {
// 				config.ReverseJndiLive = true
// 			}

// 		}()
// 	}

// 	if len(config.ReverseCeyeDomain) > 0 && len(config.ReverseCeyeApiKey) > 0 {
// 		wg.Add(1)

// 		go func() {
// 			defer wg.Done()

// 			if !CeyeTest() {
// 				gologger.Info().Msg("Load of CEYE is failed")
// 				config.ReverseCeyeLive = false
// 			} else {
// 				config.ReverseCeyeLive = true
// 			}

// 		}()

// 	}

// 	if len(config.ReverseEyeDomain) > 0 && len(config.ReverseEyeToken) > 0 {
// 		wg.Add(1)

// 		go func() {
// 			defer wg.Done()

// 			if !EyeTest() {
// 				gologger.Info().Msg("Load of EYE  is failed")
// 				config.ReverseEyeShLive = false
// 			} else {
// 				config.ReverseEyeShLive = true
// 			}

// 		}()

// 	} //else {
// 	// 	gologger.Info().Msg("Version 2.7.8 introduces the Eye.sh backlink configuration option. For more details, please refer to the afrog wiki.")
// 	// }

// 	wg.Wait()
// }
