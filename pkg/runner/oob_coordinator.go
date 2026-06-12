package runner

import (
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

// initOOB sets up the OOB adapter and manager for the current scan.
// Called from Execute() before the scan stages begin.
func (runner *Runner) initOOB(reversePocs []poc.Poc) {
	options := runner.options
	if runner.engine == nil {
		return
	}

	runner.engine.oobAdapter = nil
	runner.engine.oobAlive = false
	runner.engine.oobMgr = nil

	if len(reversePocs) == 0 {
		return
	}

	// SDK mode: only enable OOB if explicitly requested
	if options.SDKMode && !options.EnableOOB {
		runner.engine.oobAdapter = nil
		runner.engine.oobAlive = false
		return
	}

	runner.options.SetOOBAdapter()
	adapter, err := oobadapter.NewOOBAdapter(options.OOB, &oobadapter.ConnectorParams{
		Key:     options.OOBKey,
		Domain:  options.OOBDomain,
		HTTPUrl: options.OOBHttpUrl,
		ApiUrl:  options.OOBApiUrl,
	})
	if err == nil {
		runner.engine.oobAdapter = adapter
		runner.engine.oobAlive = adapter.IsVaild()
	}

	if runner.engine.oobAlive && runner.engine.oobAdapter != nil {
		pollInterval := time.Duration(options.OOBPollInterval) * time.Second
		hitRetention := time.Duration(options.OOBHitRetention) * time.Minute
		runner.engine.oobMgr = NewOOBManager(runner.ctx, runner.engine.oobAdapter, pollInterval, hitRetention)
	}
}

func (runner *Runner) getOOBStatus(reversePocs []poc.Poc) (bool, string) {
	if len(reversePocs) == 0 {
		return true, "Not required (no OOB PoCs)"
	}

	runner.options.SetOOBAdapter()

	serviceName := strings.ToLower(runner.options.OOB)

	if runner.engine == nil || runner.engine.oobAdapter == nil {
		return false, fmt.Sprintf("%s (Not configured)", serviceName)
	}

	if !runner.engine.oobAdapter.IsVaild() {
		return false, fmt.Sprintf("%s (Connection failed)", serviceName)
	}

	return true, fmt.Sprintf("%s (Active)", serviceName)
}

func (runner *Runner) printOOBStatus(reversePocs []poc.Poc) {
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
