package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/report"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
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
	c.OOBAdapter = e.oobAdapter
	c.OOBAlive = e.oobAlive
	c.OOBMgr = e.oobMgr
	if c.CustomLib != nil {
		c.CustomLib.SetOOBManager(e.oobMgr)
	}
	return c
}

func (e *Engine) ReleaseChecker(c *Checker) {
	// *c.OriginalRequest = http.Request{}
	c.VariableMap = make(map[string]any)
	c.Result = &result.Result{}
	c.CustomLib = NewCustomLib()
	c.OOBAdapter = nil
	c.OOBAlive = false
	c.OOBMgr = nil
	CheckerPool.Put(c)
}

type Engine struct {
	options       *config.Options
	scanCtx       *ScanContext
	ticker        *time.Ticker
	mu            sync.Mutex
	paused        uint32
	stopped       uint32
	quit          chan struct{}
	activeTasks   int64
	queuedTasks   int64
	startedTasks  uint32
	slowLogged    uint32
	pedmMu        sync.Mutex
	pedmStatsByID map[string]*pedmStat
	pedmPairByID  map[string]*pedmStat
	pedmActiveMu  sync.Mutex
	pedmActive    map[uint64]*pedmActiveTask
	pedmTaskSeq   uint64
	pedmStop      chan struct{}
	oobAdapter    *oobadapter.OOBAdapter
	oobAlive      bool
	oobMgr        *OOBManager
}

// getScanCtx returns the ScanContext, initializing it if nil.
func (e *Engine) getScanCtx() *ScanContext {
	if e.scanCtx == nil {
		e.scanCtx = &ScanContext{}
	}
	return e.scanCtx
}

func NewEngine(options *config.Options) *Engine {
	engine := &Engine{
		options:       options,
		quit:          make(chan struct{}),
		pedmStatsByID: make(map[string]*pedmStat),
		pedmPairByID:  make(map[string]*pedmStat),
		pedmActive:    make(map[uint64]*pedmActiveTask),
	}
	return engine
}
func (runner *Runner) Execute() {

	options := runner.options
	if runner.engine != nil {
		runner.engine.scanCtx = runner.scanCtx
		runner.engine.pedmReset()
		defer runner.engine.pedmStopMonitor()
		if options.PocExecutionDurationMonitor {
			runner.engine.pedmStartMonitor(options)
		}
	}
	pocSlice := options.CreatePocList()
	fingerprintPocs, pocSlice := options.FingerprintPoCs(pocSlice)

	reversePocs, otherPocs := options.ReversePoCs(pocSlice)
	runner.initOOB(reversePocs)
	runner.startOOBResolver()
	defer runner.stopOOBResolver()
	runner.printOOBStatus(reversePocs)

	// portscan pre-scan: run after OOB status output to ensure ordering
	if options.PortScan {
		origTargets := runner.options.Targets.List()
		origSeen := make(map[string]struct{}, len(origTargets))
		for _, t := range origTargets {
			if s, ok := t.(string); ok && s != "" {
				origSeen[s] = struct{}{}
			}
		}

		var idx *targets.TargetIndex
		if runner.TargetIndex != nil {
			idx = runner.TargetIndex
		} else {
			seeds := runner.options.TargetStrings()
			idx = targets.BuildTargetIndex(seeds)
			runner.TargetIndex = idx
		}

		hosts := idx.PreScanTargets()
		if len(hosts) > 0 {
			psOpts := portscan.DefaultOptions()
			psOpts.Targets = hosts
			// Let portscan module handle its own output and progress
			psOpts.Debug = !options.Silent
			psOpts.LiveStats = options.LiveStats
			psOpts.Quiet = false
			if runner.getScanCtx().OnPhaseProgress != nil {
				psOpts.OnProgress = func(phase string, status string, finished int, total int, percent int) {
					runner.getScanCtx().OnPhaseProgress(phase, status, int64(finished), int64(total), percent)
				}
			}
			if runner.getScanCtx().OnHostDiscovered != nil {
				psOpts.OnDiscoveredHost = func(host string) {
					runner.getScanCtx().OnHostDiscovered(host)
				}
			}
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
			collector := newOpenPortsCollector()
			psOpts.OnResult = func(r *portscan.ScanResult) {
				if runner.getScanCtx().OnPortScanResult != nil {
					runner.getScanCtx().OnPortScanResult(r.Host, r.Port)
				}
				if !options.SDKMode {
					gologger.Print().Msgf("%s:%d", r.Host, r.Port)
				}
				collector.Add(r.Host, r.Port)
			}
			if sc, err := portscan.NewScanner(psOpts); err == nil {
				baseCtx := runner.ctx
				if baseCtx == nil {
					baseCtx = context.Background()
				}
				_ = sc.Scan(baseCtx)
				newTargets := make([]string, 0)
				for host, ports := range collector.Snapshot() {
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
					for _, nt := range newTargets {
						if _, ok := origSeen[nt]; ok {
							continue
						}
						origSeen[nt] = struct{}{}
						options.Targets.Append(nt)
						if runner.TargetIndex != nil {
							runner.TargetIndex.Add(nt)
						}
					}
				}
			}
		} else if !options.SDKMode {
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StageHostDiscovery, "skipped")
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StagePortScan, "skipped")
		} else if runner.getScanCtx().OnPhaseProgress != nil {
			runner.getScanCtx().OnPhaseProgress("host_discovery", "skipped", 0, 0, 0)
			runner.getScanCtx().OnPhaseProgress("portscan", "skipped", 0, 0, 0)
		}
	} else if !options.SDKMode {
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StageHostDiscovery, "skipped")
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StagePortScan, "skipped")
	} else if runner.getScanCtx().OnPhaseProgress != nil {
		runner.getScanCtx().OnPhaseProgress("host_discovery", "skipped", 0, 0, 0)
		runner.getScanCtx().OnPhaseProgress("portscan", "skipped", 0, 0, 0)
	}

	allTargets := runner.options.TargetStrings()

	idx := runner.TargetIndex

	if idx == nil {
		idx = targets.BuildTargetIndex(allTargets)
		runner.TargetIndex = idx
	}
	baseCtx := runner.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	netTargetsStrict := append([]string(nil), idx.HostPorts...)
	var webTargets []string
	if options.EnableWebProbe {
		webTargets = runner.webProbe(baseCtx, idx)
	}
	if !runner.options.SDKMode {
		webMetas := make([]WebMeta, 0, len(webTargets))
		runner.webMu.Lock()
		for _, u := range webTargets {
			key := fingerprint.KeyFromTarget(u)
			if key == "" {
				continue
			}
			meta, ok := runner.webMetaByKey[key]
			if !ok {
				continue
			}
			if strings.TrimSpace(meta.URL) == "" {
				meta.URL = u
			}
			webMetas = append(webMetas, meta)
		}
		runner.webMu.Unlock()
		if len(webMetas) > 0 {
			_, _ = sqlite.InsertWebProbeSummary(db2.TaskID, "webprobe", "webprobe", "webprobe", "webprobe", webMetas)
			if runner.Report != nil {
				entries := make([]report.WebProbeEntry, 0, len(webMetas))
				for i, meta := range webMetas {
					urlStr := strings.TrimSpace(meta.URL)
					if urlStr == "" {
						continue
					}
					number := utils.GetNumberText(i + 1)
					entries = append(entries, report.WebProbeEntry{
						Number:    number,
						URL:       urlStr,
						Title:     strings.TrimSpace(meta.Title),
						Server:    strings.TrimSpace(meta.Server),
						PoweredBy: strings.TrimSpace(meta.PoweredBy),
					})
				}
				_ = runner.Report.AppendWebProbeEntries(entries)
			}
		}
	}
	mergeTargets := func(parts ...[]string) []string {
		seen := make(map[string]struct{})
		out := make([]string, 0)
		for _, p := range parts {
			for _, t := range p {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				if _, ok := seen[t]; ok {
					continue
				}
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
		return out
	}
	resolvedHosts := make([]string, 0, len(idx.Hosts))
	runner.webMu.Lock()
	for _, h := range idx.Hosts {
		key := fingerprint.KeyFromTarget(h)
		if key != "" {
			if u := strings.TrimSpace(runner.webURLByKey[key]); u != "" {
				resolvedHosts = append(resolvedHosts, u)
				continue
			}
		}
		resolvedHosts = append(resolvedHosts, h)
	}
	runner.webMu.Unlock()

	keyForWebDedup := func(target string) string {
		target = strings.TrimSpace(target)
		if target == "" {
			return ""
		}
		if strings.Contains(target, "://") {
			return keyFromTargetWithPath(target)
		}
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}

	dedupWebTargets := func(in []string) []string {
		bestByKey := make(map[string]string)
		keysInOrder := make([]string, 0, len(in))
		out := make([]string, 0, len(in))
		seenLoose := make(map[string]struct{})
		for _, raw := range in {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			key := keyForWebDedup(raw)
			if key == "" {
				if _, ok := seenLoose[raw]; ok {
					continue
				}
				seenLoose[raw] = struct{}{}
				out = append(out, raw)
				continue
			}
			if prev, ok := bestByKey[key]; ok {
				prevIsURL := strings.Contains(prev, "://")
				rawIsURL := strings.Contains(raw, "://")
				if !prevIsURL && rawIsURL {
					bestByKey[key] = raw
				}
				continue
			}
			bestByKey[key] = raw
			keysInOrder = append(keysInOrder, key)
		}
		for _, k := range keysInOrder {
			if v, ok := bestByKey[k]; ok {
				out = append(out, v)
			}
		}
		return out
	}

	webScanTargets := dedupWebTargets(mergeTargets(idx.URLs, resolvedHosts, webTargets, idx.HostPorts))

	taskCount := 0
	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if p.IsNetOnly() {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 {
			taskCount += len(fingerNet) * len(netTargetsStrict)
		}
		if len(fingerWeb) > 0 {
			taskCount += len(fingerWeb) * len(webScanTargets)
		}
	}
	for _, p := range pocSlice {
		if !p.IsNetOnly() {
			taskCount += len(webScanTargets)
		} else {
			taskCount += len(netTargetsStrict)
		}
	}
	options.Count += taskCount
	if runner.getScanCtx().OnScanInfoUpdate != nil {
		pocTotal := len(pocSlice)
		if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
			pocTotal += len(fingerprintPocs)
		}
		oobEnabled, oobStatus := runner.getOOBStatus(reversePocs)
		runner.getScanCtx().OnScanInfoUpdate(config.ScanInfoUpdate{
			TotalTargets: len(webScanTargets),
			Targets:      append([]string(nil), webScanTargets...),
			TotalPocs:    pocTotal,
			TotalScans:   options.Count,
			OOBEnabled:   oobEnabled,
			OOBStatus:    oobStatus,
		})
	}

	if options.Smart {
		options.SmartControl()
	}

	if !options.SDKMode {
		pocTotal := len(pocSlice)
		if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
			pocTotal += len(fingerprintPocs)
		}
		gologger.Info().Msgf("%-9s | %-9s | targets=%d pocs=%d tasks=%d", utils.StageVulnScan, "started", options.Targets.Len(), pocTotal, options.Count)
	}

	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if p.IsNetOnly() {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 && len(netTargetsStrict) > 0 {
			runner.runFingerprintStage(baseCtx, netTargetsStrict, fingerNet)
		}
		if len(fingerWeb) > 0 && len(webScanTargets) > 0 {
			runner.runFingerprintStage(baseCtx, webScanTargets, fingerWeb)
		}
	}

	normalizeTags := func(tags string, skipFingerprint bool) map[string]struct{} {
		tags = strings.TrimSpace(tags)
		if tags == "" {
			return nil
		}
		out := make(map[string]struct{})
		for _, t := range strings.Split(strings.ToLower(tags), ",") {
			tt := strings.TrimSpace(t)
			if tt == "" {
				continue
			}
			if skipFingerprint && tt == "fingerprint" {
				continue
			}
			out[tt] = struct{}{}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	fingerTagsByKey := make(map[string]map[string]struct{})
	globalFingerTags := make(map[string]struct{})
	{
		runner.fingerMu.Lock()
		fingerSnap := make(map[string][]fingerprint.Hit, len(runner.fingerByKey))
		for k, v := range runner.fingerByKey {
			if len(v) == 0 {
				continue
			}
			vv := make([]fingerprint.Hit, len(v))
			copy(vv, v)
			fingerSnap[k] = vv
		}
		runner.fingerMu.Unlock()

		for k, hits := range fingerSnap {
			tagSet := make(map[string]struct{})
			for _, h := range hits {
				hs := normalizeTags(h.Tags, true)
				for t := range hs {
					tagSet[t] = struct{}{}
				}
			}
			if len(tagSet) == 0 {
				continue
			}
			fingerTagsByKey[k] = tagSet
			for t := range tagSet {
				globalFingerTags[t] = struct{}{}
			}
		}
	}

	pocTagsCache := make(map[string]map[string]struct{})
	shouldSkipFingerprintFiltered := func(target string, p poc.Poc) bool {
		if p.IsNetOnly() {
			return false
		}
		if len(globalFingerTags) == 0 {
			return false
		}
		pt, ok := pocTagsCache[p.Id]
		if !ok {
			pt = normalizeTags(p.Info.Tags, true)
			pocTagsCache[p.Id] = pt
		}
		if len(pt) == 0 {
			return false
		}
		appSpecific := false
		for t := range pt {
			if _, ok := globalFingerTags[t]; ok {
				appSpecific = true
				break
			}
		}
		if !appSpecific {
			return false
		}
		key := keyFromTargetWithPath(target)
		if key == "" {
			return false
		}
		tts := fingerTagsByKey[key]
		return shouldSkipFingerprintFilteredByMode(options.FingerprintFilterMode, globalFingerTags, tts, pt)
	}

	runStage := func(pocs []poc.Poc, rate, concurrency int) {
		if runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
			return
		}
		if rate <= 0 {
			rate = 1
		}
		if concurrency <= 0 {
			concurrency = 1
		}

		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(rate))
		defer func() {
			if runner.engine.ticker != nil {
				runner.engine.ticker.Stop()
				runner.engine.ticker = nil
			}
		}()

		type stageTask struct {
			tap   *TransData
			pocID string
		}

		tasks := make(chan stageTask, concurrency*4)
		var workers sync.WaitGroup

		var counters sync.Map // map[string]*atomic.Int64
		getCounter := func(pocID string) *atomic.Int64 {
			if v, ok := counters.Load(pocID); ok {
				return v.(*atomic.Int64)
			}
			c := &atomic.Int64{}
			actual, _ := counters.LoadOrStore(pocID, c)
			return actual.(*atomic.Int64)
		}
		finish := func(pocID string) {
			v, ok := counters.Load(pocID)
			if !ok {
				return
			}
			if v.(*atomic.Int64).Add(-1) == 0 {
				runner.ScanProgress.MarkPocDone(pocID)
			}
		}

		for i := 0; i < concurrency; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-runner.engine.quit:
						return
					case <-runner.ctx.Done():
						return
					case task, ok := <-tasks:
						if !ok {
							return
						}
						atomic.AddInt64(&runner.engine.queuedTasks, -1)
						runner.engine.waitTick()
						if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
							finish(task.pocID)
							continue
						}
						runner.exec(task.tap)
						finish(task.pocID)
					}
				}
			}()
		}

		for _, pocItem := range pocs {
			if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
				break
			}
			targetView := webScanTargets
			if pocItem.IsNetOnly() {
				targetView = netTargetsStrict
			}

			if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(pocItem.Id) {
				if runner.options.ResumeDoneTasks == 0 {
					for range targetView {
						runner.NotVulCallback()
					}
				}
				continue
			}

			scheduled := 0
			for _, t := range targetView {
				if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
					break
				}

				if len(runner.options.Resume) > 0 && runner.ScanProgress.ContainsTask(pocItem.Id, t) {
					if runner.options.ResumeDoneTasks == 0 {
						runner.NotVulCallback()
					}
					continue
				}

				if shouldSkipRequires(t, pocItem, keyFromTargetWithPath, fingerTagsByKey, runner.options.Test) {
					runner.ScanProgress.IncrementTask(pocItem.Id, t)
					runner.NotVulCallback()
					continue
				}

				if shouldSkipFingerprintFiltered(t, pocItem) {
					runner.ScanProgress.IncrementTask(pocItem.Id, t)
					runner.NotVulCallback()
					continue
				}

				getCounter(pocItem.Id).Add(1)
				scheduled++

				task := stageTask{tap: &TransData{Target: t, Poc: pocItem}, pocID: pocItem.Id}
				select {
				case <-runner.engine.quit:
					finish(task.pocID)
				case <-runner.ctx.Done():
					finish(task.pocID)
				case tasks <- task:
					atomic.AddInt64(&runner.engine.queuedTasks, 1)
				}
			}
			if scheduled == 0 {
				runner.ScanProgress.MarkPocDone(pocItem.Id)
			}
		}

		close(tasks)
		workers.Wait()
		atomic.StoreInt64(&runner.engine.queuedTasks, 0)
	}

	oobRate := options.OOBRateLimit
	if oobRate <= 0 {
		oobRate = options.RateLimit
	}
	oobCon := options.OOBConcurrency
	if oobCon <= 0 {
		oobCon = options.Concurrency
	}
	if runner.engine != nil && len(reversePocs) > 0 && (!runner.engine.oobAlive || runner.engine.oobAdapter == nil) {
		for _, pocItem := range reversePocs {
			if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
				break
			}
			targetView := webScanTargets
			if pocItem.IsNetOnly() {
				targetView = netTargetsStrict
			}

			if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(pocItem.Id) {
				if runner.options.ResumeDoneTasks == 0 {
					for range targetView {
						runner.NotVulCallback()
					}
				}
				continue
			}

			for range targetView {
				if runner.options.ResumeDoneTasks == 0 {
					runner.NotVulCallback()
				}
			}
			runner.ScanProgress.MarkPocDone(pocItem.Id)
		}
	} else {
		runStage(reversePocs, oobRate, oobCon)
	}

	runStage(otherPocs, options.RateLimit, options.Concurrency)

	runner.finalizeOOBPendings()

	if options.PocExecutionDurationMonitor && runner.engine != nil {
		runner.engine.pedmSummary(options)
	}
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
			limit := options.PedmLogLimit
			if limit < 0 {
				limit = 0
			}
			n := atomic.AddUint32(&runner.engine.startedTasks, 1)
			if limit > 0 && n <= uint32(limit) {
				runner.engine.pedmLog(options, fmt.Sprintf("POC-TASK #%d | VULN | %s | %s", n, tap.Poc.Id, tap.Target))
			}

			taskID := runner.engine.pedmStartTask("VULN", tap.Poc.Id, tap.Target)
			defer runner.engine.pedmDoneTask(taskID)

			taskCtx := baseCtx
			cancel := func() {}
			hardTimeout := runner.engine.taskHardTimeout(&tap.Poc)
			if hardTimeout > 0 {
				taskCtx, cancel = context.WithTimeout(baseCtx, hardTimeout)
			}
			defer cancel()

			start := time.Now()
			runner.executeExpression(taskCtx, tap.Target, &tap.Poc)
			dur := time.Since(start)
			runner.engine.pedmRecord(tap.Poc.Id, dur)
			runner.engine.pedmRecordPair(tap.Target, tap.Poc.Id, dur)
			runner.engine.pedmMaybeLogSlow(options, "VULN", tap.Poc.Id, tap.Target, dur)
			if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
				runner.engine.taskTimeoutLog("VULN", tap.Poc.Id, tap.Target, dur, hardTimeout)
			}
			return
		} else {
			taskCtx := baseCtx
			cancel := func() {}
			hardTimeout := runner.engine.taskHardTimeout(&tap.Poc)
			if hardTimeout > 0 {
				taskCtx, cancel = context.WithTimeout(baseCtx, hardTimeout)
			}
			defer cancel()
			start := time.Time{}
			if hardTimeout > 0 {
				start = time.Now()
			}
			runner.executeExpression(taskCtx, tap.Target, &tap.Poc)
			if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
				runner.engine.taskTimeoutLog("VULN", tap.Poc.Id, tap.Target, time.Since(start), hardTimeout)
			}
		}
	}
}

func (runner *Runner) executeExpression(ctx context.Context, target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)
	if runner.ScanProgress != nil && poc != nil && poc.Id != "" && target != "" {
		defer runner.ScanProgress.IncrementTask(poc.Id, target)
	}

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
	if c.Result != nil {
		c.Result.FingerResult = runner.fingerprintForTarget(c.Result.Target)
	}
	if c.CustomLib != nil && c.Result != nil {
		if pendings := c.CustomLib.TakeOOBPending(); len(pendings) > 0 {
			runner.registerOOBPendings(c.Result, pendings)
		}
	}
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
	for atomic.LoadUint32(&e.paused) != 0 {
		select {
		case <-e.quit:
			return
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *Engine) Pause() {
	atomic.StoreUint32(&e.paused, 1)
	gologger.Debug().Msgf("engine paused: ticker gated")
}

func (e *Engine) Resume() {
	atomic.StoreUint32(&e.paused, 0)
	gologger.Debug().Msgf("engine resumed: ticker released")
}

func (e *Engine) IsPaused() bool {
	return atomic.LoadUint32(&e.paused) != 0
}

func (e *Engine) Stop() {
	if !atomic.CompareAndSwapUint32(&e.stopped, 0, 1) {
		return
	}
	e.mu.Lock()
	if e.ticker != nil {
		e.ticker.Stop()
	}
	e.mu.Unlock()
	close(e.quit)
	gologger.Debug().Msgf("engine stopped: ticker stopped and scheduling halted")
}

func (runner *Runner) NotVulCallback() {
	runner.OnResult(&result.Result{IsVul: false})
}

type TransData struct {
	Target string
	Poc    poc.Poc
}
