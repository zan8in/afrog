package runner

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

type runnerFingerprintExecutor struct {
	runner *Runner
}

func (e runnerFingerprintExecutor) Exec(ctx context.Context, target string, p *poc.Poc) (matched bool, resolvedTarget string, err error) {
	if e.runner == nil || e.runner.engine == nil {
		return false, "", nil
	}
	if e.runner.options != nil && e.runner.options.Resume != "" && e.runner.ScanProgress != nil {
		fpID := "finger:" + p.Id
		if e.runner.ScanProgress.ContainsPoc(fpID) {
			if e.runner.options.ResumeDoneTasks == 0 {
				e.runner.NotVulCallback()
			}
			return false, "", nil
		}
		if e.runner.ScanProgress.ContainsTask(fpID, target) {
			if e.runner.options.ResumeDoneTasks == 0 {
				e.runner.NotVulCallback()
			}
			return false, "", nil
		}
	}
	c := e.runner.engine.AcquireChecker()
	defer e.runner.engine.ReleaseChecker(c)
	defer e.runner.NotVulCallback()
	if e.runner.ScanProgress != nil && p != nil && p.Id != "" && target != "" {
		fpID := "finger:" + p.Id
		defer e.runner.ScanProgress.IncrementTask(fpID, target)
	}

	var start time.Time
	var taskID uint64
	taskCtx := ctx
	cancel := func() {}
	hardTimeout := e.runner.engine.taskHardTimeout(p)
	if taskCtx == nil {
		taskCtx = context.Background()
	}
	if hardTimeout > 0 {
		taskCtx, cancel = context.WithTimeout(taskCtx, hardTimeout)
	}
	defer cancel()
	if e.runner.options != nil && e.runner.options.PocExecutionDurationMonitor {
		taskID = e.runner.engine.pedmStartTask("FINGER", p.Id, target)
		defer e.runner.engine.pedmDoneTask(taskID)
		start = time.Now()
	} else if hardTimeout > 0 {
		start = time.Now()
	}
	c.VariableMap[retryhttpclient.ContextVarKey] = taskCtx
	err = c.Check(target, p)
	if !start.IsZero() {
		dur := time.Since(start)
		if e.runner.options != nil && e.runner.options.PocExecutionDurationMonitor {
			e.runner.engine.pedmRecord(p.Id, dur)
			e.runner.engine.pedmRecordPair(target, p.Id, dur)
			e.runner.engine.pedmMaybeLogSlow(e.runner.options, "FINGER", p.Id, target, dur)
		}
		if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			e.runner.engine.taskTimeoutLog("FINGER", p.Id, target, dur, hardTimeout)
		}
	}
	if c.Result == nil {
		return false, "", err
	}
	if e.runner.options != nil && e.runner.options.Debug {
		pocID := ""
		if c.Result.PocInfo != nil {
			pocID = c.Result.PocInfo.Id
		}
		for i, pr := range c.Result.AllPocResult {
			idx := i + 1
			gologger.Info().Msgf("\r\n[%d][%s] Dumped Request\n", idx, pocID)
			if pr != nil && pr.ResultRequest != nil {
				gologger.Print().Msgf("%s\n", utils.Str2UTF8(string(pr.ResultRequest.GetRaw())))
			} else {
				gologger.Print().Msgf("%s\n", "")
			}
			gologger.Info().Msgf("\r\n[%d][%s] Dumped Response\n", idx, pocID)
			if pr != nil && pr.ResultResponse != nil {
				gologger.Print().Msgf("%s\n", utils.Str2UTF8(string(pr.ResultResponse.GetRaw())))
			} else {
				gologger.Print().Msgf("%s\n", "")
			}
		}
	}
	if c.Result.IsVul {
		key := keyFromTargetWithPath(c.Result.Target)
		if key == "" {
			key = keyFromTargetWithPath(target)
		}
		if key != "" {
			e.runner.setFingerprintResult(key, p.Id, c.Result)
			hit := fingerprint.Hit{
				ID:       p.Id,
				Name:     p.Info.Name,
				Tags:     p.Info.Tags,
				Severity: p.Info.Severity,
			}
			e.runner.fingerMu.Lock()
			e.runner.fingerByKey[key] = append(e.runner.fingerByKey[key], hit)
			e.runner.fingerMu.Unlock()
			if e.runner.OnFingerprint != nil {
				e.runner.OnFingerprint(key, []fingerprint.Hit{hit})
			}
		}
	}
	return c.Result.IsVul, c.Result.Target, err
}

func (runner *Runner) runFingerprintStage(ctx context.Context, targets []string, pocs []poc.Poc) {
	if runner == nil || runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 {
		return
	}
	if len(targets) == 0 || len(pocs) == 0 {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}

	e := &fingerprint.Engine{Rate: runner.options.RateLimit, Concurrency: runner.options.Concurrency}
	e.Run(ctx, targets, pocs, runnerFingerprintExecutor{runner: runner})
	if runner.ScanProgress != nil {
		for _, p := range pocs {
			if p.Id == "" {
				continue
			}
			runner.ScanProgress.MarkPocDone("finger:" + p.Id)
		}
	}
}

func (runner *Runner) fingerprintForTarget(target string) []fingerprint.Hit {
	key := keyFromTargetWithPath(target)
	if key == "" {
		return nil
	}
	runner.fingerMu.Lock()
	hits := runner.fingerByKey[key]
	runner.fingerMu.Unlock()
	if len(hits) == 0 {
		return nil
	}
	out := make([]fingerprint.Hit, len(hits))
	copy(out, hits)
	return out
}
