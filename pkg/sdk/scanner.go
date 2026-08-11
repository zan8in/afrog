package sdk

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/curated/service"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

// Scan lifecycle states.
const (
	stateIdle int32 = iota
	stateRunning
	stateFinished
)

// Scanner runs a vulnerability scan.
//
// A Scanner is single-use: once a scan finishes the instance cannot be
// restarted. All methods are safe for concurrent use.
type Scanner struct {
	opts   *Options
	runner *runner.Runner
	// internal is the engine-level configuration derived from opts.
	internal *config.Options

	ctx    context.Context
	cancel context.CancelFunc

	state    atomic.Int32
	stopping atomic.Bool
	closed   atomic.Bool

	runDone     chan struct{}
	runDoneOnce sync.Once

	runErrMu sync.Mutex
	runErr   error

	resultsMu sync.Mutex
	results   []Result

	portsMu   sync.Mutex
	openPorts map[string]map[int]struct{}

	statsMu sync.RWMutex
	stats   Stats
	// completed and found are hot counters kept outside statsMu.
	completed atomic.Int64
	found     atomic.Int64

	phasesMu sync.Mutex
	phases   map[string]PhaseProgress
	lastVuln atomic.Int32

	resultEvents   *emitter[Result]
	portEvents     *emitter[PortEvent]
	hostEvents     *emitter[HostEvent]
	webProbeEvents *emitter[WebProbeEvent]
	progressEvents *emitter[PhaseProgress]
	scanInfoEvents *emitter[ScanInfo]

	pocs        []poc.Poc
	pocDiags    []config.PocLoadError
	curatedErr  error
	includeRR   bool
	maxStored   int
	redact      map[string]struct{}
	oobProbedMu sync.Mutex

	// curatedEnv restores the process environment that mountCurated changed,
	// so a second scanner in the same process is not affected by the first.
	curatedEnv []envEntry
}

// envEntry remembers an environment variable's prior state.
type envEntry struct {
	key   string
	value string
	set   bool
}

// New creates a Scanner from the given options.
//
// The parent context bounds the scanner's lifetime: cancelling it stops any
// running scan and releases every background goroutine.
func New(ctx context.Context, options ...Option) (*Scanner, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	opts := NewOptions()
	for _, apply := range options {
		if apply == nil {
			continue
		}
		if err := apply(opts); err != nil {
			return nil, err
		}
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	built, err := buildInternalOptions(opts)
	if err != nil {
		return nil, err
	}
	internal, curatedErr := built.options, built.curatedErr

	scanCtx, cancel := context.WithCancel(ctx)
	s := &Scanner{
		opts:           opts,
		internal:       internal,
		ctx:            scanCtx,
		cancel:         cancel,
		runDone:        make(chan struct{}),
		openPorts:      make(map[string]map[int]struct{}),
		phases:         make(map[string]PhaseProgress),
		curatedErr:     curatedErr,
		includeRR:      opts.IncludeRequestResponse,
		maxStored:      opts.MaxStoredResults,
		redact:         toSet(opts.RedactedHeaders),
		curatedEnv:     built.envRestore,
		resultEvents:   newEmitter(opts.StreamBuffer, opts.handlers.result),
		portEvents:     newEmitter(opts.StreamBuffer, opts.handlers.port),
		hostEvents:     newEmitter(opts.StreamBuffer, opts.handlers.host),
		webProbeEvents: newEmitter(opts.StreamBuffer, opts.handlers.webProbe),
		progressEvents: newEmitter(opts.StreamBuffer, opts.handlers.progress),
		scanInfoEvents: newEmitter(opts.StreamBuffer, opts.handlers.scanInfo),
	}
	s.stats.StartTime = time.Now()
	s.lastVuln.Store(-1)

	s.installEngineHooks()

	r, err := buildRunner(internal)
	if err != nil {
		s.abandon(cancel)
		return nil, err
	}
	s.runner = r
	s.installRunnerHooks()

	if err := s.loadPocs(); err != nil {
		s.abandon(cancel)
		return nil, err
	}

	return s, nil
}

// abandon releases everything a partially built scanner already owns. Without
// it a failed New would leak the runner's background goroutines and leave the
// curated environment variables pointing at this scanner's PoC directory.
func (s *Scanner) abandon(cancel context.CancelFunc) {
	cancel()
	s.closed.Store(true)
	s.runner.Release()
	s.restoreEnv()
}

// installEngineHooks wires the config-level callbacks. They must be installed
// before the runner is built because the engine captures them.
func (s *Scanner) installEngineHooks() {
	s.internal.OnPortScanResult = func(host string, port int) {
		s.recordOpenPort(host, port)
		s.portEvents.emit(s.ctx, PortEvent{Host: host, Port: port})
	}

	s.internal.OnHostDiscovered = func(host string) {
		if host = strings.TrimSpace(host); host == "" {
			return
		}
		s.hostEvents.emit(s.ctx, HostEvent{Host: host})
	}

	s.internal.OnPhaseProgress = func(phase, status string, finished, total int64, percent int) {
		phase = strings.ToLower(strings.TrimSpace(phase))
		if phase == "" {
			return
		}
		pp := PhaseProgress{
			Phase:    phase,
			Status:   strings.ToLower(strings.TrimSpace(status)),
			Finished: finished,
			Total:    total,
			Percent:  clampPercent(percent),
		}

		s.phasesMu.Lock()
		s.phases[phase] = pp
		s.phasesMu.Unlock()

		s.progressEvents.emit(s.ctx, pp)
	}

	// Always non-nil: the engine falls back to printing execution monitor
	// lines itself when this hook is missing, which would break the SDK's
	// promise to write nothing to the console.
	s.internal.OnPedmLog = func(line string) {
		for _, fn := range s.opts.handlers.monitor {
			fn(line)
		}
	}

	s.internal.OnScanInfoUpdate = func(info config.ScanInfoUpdate) {
		s.statsMu.Lock()
		s.stats.TotalTargets = info.TotalTargets
		s.stats.TotalPocs = info.TotalPocs
		s.stats.TotalScans = info.TotalScans
		s.statsMu.Unlock()

		s.scanInfoEvents.emit(s.ctx, ScanInfo{
			TotalTargets: info.TotalTargets,
			Targets:      append([]string(nil), info.Targets...),
			TotalPocs:    info.TotalPocs,
			TotalScans:   info.TotalScans,
			OOBEnabled:   info.OOBEnabled,
			OOBStatus:    info.OOBStatus,
		})
	}
}

// installRunnerHooks wires the runner-level callbacks.
func (s *Scanner) installRunnerHooks() {
	s.runner.OnWebProbe = func(meta runner.WebMeta) {
		s.webProbeEvents.emit(s.ctx, WebProbeEvent{
			URL:       strings.TrimSpace(meta.URL),
			Title:     strings.TrimSpace(meta.Title),
			Server:    strings.TrimSpace(meta.Server),
			PoweredBy: strings.TrimSpace(meta.PoweredBy),
		})
	}

	s.runner.OnFailure = func(target, pocID string, err error) {
		if err == nil {
			return
		}
		f := Failure{Target: target, PocID: pocID, Err: err}
		for _, fn := range s.opts.handlers.failure {
			fn(f)
		}
	}

	s.runner.OnResult = s.handleResult
	s.runner.OnFingerprint = s.handleFingerprint
}

// handleResult receives every executed task, whether it matched or not.
func (s *Scanner) handleResult(r *result.Result) {
	if r == nil || !r.SkipCount {
		s.completed.Add(1)
		// The checkpoint's "done tasks" counter lives on the engine options
		// and is pre-seeded when resuming, so it must be incremented rather
		// than overwritten.
		atomic.AddUint32(&s.internal.CurrentCount, 1)
	}
	s.emitVulnProgress()

	if r == nil || !r.IsVul {
		return
	}

	// Snapshot at the SDK boundary: the engine owns r and its protobuf
	// payloads, so handing that pointer to callers would tie their data to the
	// engine's object lifetime.
	snap := r.Snapshot()
	if !s.includeRR {
		snap.AllPocResult = nil
	}

	s.found.Add(1)
	out := newResultRedacted(snap, s.includeRR, time.Now(), s.redact)

	s.resultsMu.Lock()
	if s.maxStored <= 0 || len(s.results) < s.maxStored {
		s.results = append(s.results, out)
	}
	s.resultsMu.Unlock()

	for _, fn := range s.opts.handlers.rawResult {
		fn(snap)
	}
	s.resultEvents.emit(s.ctx, out)

	if s.opts.StopOnFirstMatch {
		s.Stop()
	}
}

// handleFingerprint turns fingerprint hits into results.
func (s *Scanner) handleFingerprint(targetKey string, hits []fingerprint.Hit) {
	for _, hit := range hits {
		severity := strings.TrimSpace(hit.Severity)
		if severity == "" {
			severity = "info"
		}
		name := strings.TrimSpace(hit.Name)
		if name == "" {
			name = strings.TrimSpace(hit.ID)
		}

		rst := s.runner.FingerprintResult(targetKey, hit.ID)
		if rst == nil {
			rst = &result.Result{
				Target:     targetKey,
				FullTarget: targetKey,
				PocInfo:    &poc.Poc{Id: hit.ID},
			}
		} else if rst.PocInfo == nil {
			rst.PocInfo = &poc.Poc{Id: hit.ID}
		} else {
			rst.PocInfo.Id = hit.ID
		}

		rst.IsVul = true
		rst.PocInfo.Info.Name = name
		rst.PocInfo.Info.Severity = severity
		rst.PocInfo.Info.Tags = hit.Tags
		rst.FingerResult = []fingerprint.Hit{hit}
		if strings.TrimSpace(rst.FullTarget) == "" {
			rst.FullTarget = rst.Target
		}

		s.handleResult(rst)
	}
}

// emitVulnProgress publishes vulnerability-stage progress, throttled to whole
// percentage points so that a large scan does not flood subscribers.
func (s *Scanner) emitVulnProgress() {
	if s.internal.OnPhaseProgress == nil {
		return
	}
	completed, total, percent := s.vulnProgress()
	if int32(percent) == s.lastVuln.Load() {
		return
	}
	s.lastVuln.Store(int32(percent))

	status := "running"
	if total == 0 || (completed >= total && percent >= 100) {
		status = "completed"
	}
	s.internal.OnPhaseProgress(PhaseVuln, status, completed, total, percent)
}

// vulnProgress reports how far the vulnerability stage has advanced. A scan
// with no estimated tasks counts as complete rather than as 0%.
func (s *Scanner) vulnProgress() (completed, total int64, percent int) {
	total = int64(s.totalScans())
	completed = s.completed.Load()
	percent = 100
	if total > 0 {
		percent = clampPercent(int(completed * 100 / total))
	}
	return completed, total, percent
}

// loadPocs resolves the PoC set once and reuses it for the scan statistics.
func (s *Scanner) loadPocs() error {
	pocs, diags := s.internal.CreatePocListWithDiagnostics()
	s.pocs = pocs
	s.pocDiags = diags

	fingerprintPocs, rest := s.internal.FingerprintPoCs(pocs)

	seeds := make([]string, 0, s.internal.Targets.Len())
	for _, t := range s.internal.Targets.List() {
		v, ok := t.(string)
		if !ok {
			continue
		}
		if v = strings.TrimSpace(v); v != "" {
			seeds = append(seeds, v)
		}
	}
	netTargets := targets.BuildTargetIndex(seeds).NetTargets()

	taskCount := 0
	if !s.internal.DisableFingerprint && len(fingerprintPocs) > 0 {
		taskCount += len(fingerprintPocs) * len(seeds)
	}
	for _, p := range rest {
		if isNetOnlyPoc(p) {
			taskCount += len(netTargets)
		} else {
			taskCount += len(seeds)
		}
	}

	totalPocs := len(rest)
	if !s.internal.DisableFingerprint && len(fingerprintPocs) > 0 {
		totalPocs += len(fingerprintPocs)
	}

	s.statsMu.Lock()
	s.stats.TotalTargets = len(seeds)
	s.stats.TotalPocs = totalPocs
	s.stats.TotalScans = taskCount
	s.statsMu.Unlock()

	if totalPocs == 0 {
		return ErrNoPocs
	}
	return nil
}

// isNetOnlyPoc reports whether a PoC only targets raw network protocols and so
// must not be scheduled against plain HTTP targets.
func isNetOnlyPoc(p poc.Poc) bool {
	var hasHTTP, hasNet, hasGo bool
	for _, rule := range p.Rules {
		switch strings.ToLower(strings.TrimSpace(rule.Value.Request.Type)) {
		case "", poc.HTTP_Type, poc.HTTPS_Type:
			hasHTTP = true
		case poc.TCP_Type, poc.UDP_Type, poc.SSL_Type:
			hasNet = true
		case poc.GO_Type:
			hasGo = true
		default:
			hasHTTP = true
		}
	}
	if hasGo {
		return false
	}
	return hasNet && !hasHTTP
}

// ---------------------------------------------------------------- lifecycle

// Execute runs the scan synchronously and returns when it finishes.
//
// Cancelling ctx stops the scan; Execute then returns the context error.
func (s *Scanner) Execute(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	return s.Wait(ctx)
}

// Start runs the scan asynchronously and returns immediately. Use Wait or Done
// to observe completion.
//
// Start returns ErrAlreadyRunning if a scan is in progress and
// ErrAlreadyFinished if this scanner has already been used.
func (s *Scanner) Start(ctx context.Context) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !s.state.CompareAndSwap(stateIdle, stateRunning) {
		if s.state.Load() == stateRunning {
			return ErrAlreadyRunning
		}
		return ErrAlreadyFinished
	}

	// Bridge the caller's context to the scan. The watcher exits when the scan
	// finishes, so it cannot outlive the scanner.
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				s.Stop()
			case <-s.runDone:
			}
		}()
	}

	go func() {
		// Deferred in reverse order: streams close first so that a subscriber
		// blocked in range is released, then runDone unblocks Wait, then the
		// state flips. All three must happen even if the scan panics,
		// otherwise a subscriber or a Wait would hang forever.
		defer s.state.Store(stateFinished)
		defer s.runDoneOnce.Do(func() { close(s.runDone) })
		defer s.closeStreams()

		defer func() {
			if r := recover(); r != nil {
				s.setRunErr(fmt.Errorf("afrog/sdk: scan panicked: %v", r))
			}
		}()

		s.printSummary()
		s.setRunErr(s.run())
	}()
	return nil
}

func (s *Scanner) setRunErr(err error) {
	s.runErrMu.Lock()
	s.runErr = err
	s.runErrMu.Unlock()
}

// run executes the scan and finalises the statistics.
func (s *Scanner) run() error {
	stopSaving := s.startCheckpointSaver()

	// Run rather than Execute: it additionally starts the target pre-probe
	// when TargetPreProbe is set. Without a pre-probe configured the two are
	// identical.
	_ = s.runner.Run()

	stopSaving()
	s.saveCheckpoint()

	s.emitFinalProgress()

	s.statsMu.Lock()
	s.stats.EndTime = time.Now()
	s.statsMu.Unlock()

	return s.ctx.Err()
}

// startCheckpointSaver rewrites the checkpoint file on a fixed interval and
// returns a function that stops it and waits for the goroutine to exit.
//
// The engine only reads the checkpoint; persisting it is the embedder's job,
// which is why the SDK has to run this loop itself.
func (s *Scanner) startCheckpointSaver() func() {
	if s.opts.Checkpoint.Path == "" || s.runner == nil || s.runner.ScanProgress == nil {
		return func() {}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.opts.Checkpoint.SaveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.saveCheckpoint()
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}

// saveCheckpoint writes the current progress so an interrupted scan can be
// resumed. Failures are reported through the failure handlers rather than
// aborting the scan: losing a checkpoint is not worth losing scan results.
func (s *Scanner) saveCheckpoint() {
	if s.opts.Checkpoint.Path == "" || s.runner == nil || s.runner.ScanProgress == nil {
		return
	}
	// The task total comes from the scanner's own guarded copy rather than
	// engine options.Count, which the engine writes unsynchronised while
	// scheduling.
	err := s.runner.ScanProgress.AtomicSave(
		s.opts.Checkpoint.Path,
		atomic.LoadUint32(&s.internal.CurrentCount),
		uint32(s.totalScans()),
	)
	if err == nil {
		return
	}
	for _, fn := range s.opts.handlers.failure {
		fn(Failure{Err: fmt.Errorf("afrog/sdk: checkpoint save failed: %w", err)})
	}
}

func (s *Scanner) emitFinalProgress() {
	if s.internal.OnPhaseProgress == nil {
		return
	}
	completed, total, percent := s.vulnProgress()

	status := "completed"
	if s.ctx.Err() != nil || (total > 0 && completed < total) {
		status = "interrupted"
	}
	if status == "completed" {
		percent = 100
		if total > 0 {
			completed = total
		}
	}
	s.internal.OnPhaseProgress(PhaseVuln, status, completed, total, percent)
}

// Wait blocks until the scan finishes and returns its error.
//
// Cancelling ctx makes Wait return ctx.Err() without stopping the scan; call
// Stop for that.
func (s *Scanner) Wait(ctx context.Context) error {
	if s.state.Load() == stateIdle {
		return ErrNotStarted
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.runDone:
		return s.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done returns a channel closed when the scan finishes.
func (s *Scanner) Done() <-chan struct{} { return s.runDone }

// Err returns the scan error, or nil while the scan is still running.
func (s *Scanner) Err() error {
	s.runErrMu.Lock()
	defer s.runErrMu.Unlock()
	return s.runErr
}

// Stop asks the scan to stop and returns immediately. It is safe to call
// concurrently and more than once. Use Wait or Close to block until the scan
// has actually stopped.
func (s *Scanner) Stop() {
	s.stopping.Store(true)
	s.cancel()
	if s.runner != nil {
		s.runner.Stop()
	}
}

// Close stops the scan, waits for the scan goroutine to exit and releases
// every resource held by the scanner.
//
// Close is idempotent and safe to defer immediately after New.
func (s *Scanner) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.Stop()

	// Only wait when a scan was actually started, otherwise runDone never
	// closes and Close would block forever.
	if s.state.Load() != stateIdle {
		<-s.runDone
	}

	s.closeStreams()

	if s.runner != nil {
		s.runner.Release()
	}
	s.restoreEnv()

	s.resultsMu.Lock()
	s.results = nil
	s.resultsMu.Unlock()

	return nil
}

// restoreEnv undoes the process-wide environment changes made when the curated
// PoC source was mounted.
func (s *Scanner) restoreEnv() {
	for _, e := range s.curatedEnv {
		if e.set {
			_ = os.Setenv(e.key, e.value)
		} else {
			_ = os.Unsetenv(e.key)
		}
	}
	s.curatedEnv = nil
}

func toSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func (s *Scanner) closeStreams() {
	s.resultEvents.close()
	s.portEvents.close()
	s.hostEvents.close()
	s.webProbeEvents.close()
	s.progressEvents.close()
	s.scanInfoEvents.close()
}

// Pause suspends task scheduling.
func (s *Scanner) Pause() {
	if s.runner != nil {
		s.runner.Pause()
	}
}

// Resume resumes a paused scan.
func (s *Scanner) Resume() {
	if s.runner != nil {
		s.runner.Resume()
	}
}

// IsPaused reports whether the scan is paused.
func (s *Scanner) IsPaused() bool {
	return s.runner != nil && s.runner.IsPaused()
}

// IsStopping reports whether Stop has been called.
func (s *Scanner) IsStopping() bool { return s.stopping.Load() }

// IsRunning reports whether a scan is currently in progress.
func (s *Scanner) IsRunning() bool { return s.state.Load() == stateRunning }

// ------------------------------------------------------------------ streams

// ResultStream returns a channel of findings, closed when the scan finishes.
//
// Nothing is published until the first call, so an unused stream costs
// nothing. Once subscribed the channel must be consumed: sends block when the
// buffer fills so that findings are never silently dropped.
func (s *Scanner) ResultStream() <-chan Result { return s.resultEvents.subscribe() }

// PortStream returns a channel of open ports found during the port pre-scan.
// The same subscription rules as ResultStream apply.
func (s *Scanner) PortStream() <-chan PortEvent { return s.portEvents.subscribe() }

// HostStream returns a channel of hosts found during discovery.
func (s *Scanner) HostStream() <-chan HostEvent { return s.hostEvents.subscribe() }

// WebProbeStream returns a channel of probed web services.
func (s *Scanner) WebProbeStream() <-chan WebProbeEvent { return s.webProbeEvents.subscribe() }

// ProgressStream returns a channel of phase progress updates.
func (s *Scanner) ProgressStream() <-chan PhaseProgress { return s.progressEvents.subscribe() }

// ScanInfoStream returns a channel of scan summary updates.
func (s *Scanner) ScanInfoStream() <-chan ScanInfo { return s.scanInfoEvents.subscribe() }

// ------------------------------------------------------------------ results

// Results returns a snapshot of the findings collected so far.
func (s *Scanner) Results() []Result {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	out := make([]Result, len(s.results))
	copy(out, s.results)
	return out
}

// ResultCount returns the number of findings, including any beyond
// MaxStoredResults.
func (s *Scanner) ResultCount() int { return int(s.found.Load()) }

// HasResults reports whether any vulnerability was found.
func (s *Scanner) HasResults() bool { return s.found.Load() > 0 }

// OpenPorts returns the open ports discovered by the port pre-scan.
func (s *Scanner) OpenPorts() map[string][]int {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()

	out := make(map[string][]int, len(s.openPorts))
	for host, ports := range s.openPorts {
		if len(ports) == 0 {
			continue
		}
		list := make([]int, 0, len(ports))
		for p := range ports {
			list = append(list, p)
		}
		out[host] = list
	}
	return out
}

func (s *Scanner) recordOpenPort(host string, port int) {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	ports, ok := s.openPorts[host]
	if !ok {
		ports = make(map[int]struct{})
		s.openPorts[host] = ports
	}
	ports[port] = struct{}{}
}

// -------------------------------------------------------------- diagnostics

// Stats returns a snapshot of the scan counters.
func (s *Scanner) Stats() Stats {
	s.statsMu.RLock()
	out := s.stats
	s.statsMu.RUnlock()
	out.CompletedScans = s.completed.Load()
	out.FoundVulns = s.found.Load()
	return out
}

func (s *Scanner) totalScans() int {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return s.stats.TotalScans
}

// Progress returns overall scan progress in the range [0, 100], weighting the
// port pre-scan and web probe stages when they are enabled.
func (s *Scanner) Progress() float64 {
	// TotalScans is an estimate made before execution, and the engine may run
	// slightly fewer tasks than estimated (deduplication, protocol-specific
	// skips). Reporting the raw ratio would leave a completed scan stuck just
	// below 100, so a scan that finished without being interrupted is 100%
	// by definition.
	if s.state.Load() == stateFinished && !s.stopping.Load() && s.Err() == nil {
		return 100
	}

	vuln := 100.0
	if total := s.totalScans(); total > 0 {
		vuln = float64(s.completed.Load()) / float64(total) * 100
	}

	weightPort, weightWeb := 0.0, 0.0
	portStage, webStage := 100.0, 100.0

	if s.opts.EnablePortSan {
		weightPort = 0.2
		discovery := s.phasePercent(PhaseHostDiscovery)
		portscan := s.phasePercent(PhasePortScan)
		if discovery == 0 && portscan == 0 {
			portStage = 0
		} else {
			portStage = float64(discovery+portscan) / 2
		}
	}
	if s.opts.EnableWebProbe {
		weightWeb = 0.2
		webStage = float64(s.phasePercent(PhaseWebProbe))
	}

	weightVuln := 1.0 - weightPort - weightWeb
	if weightVuln < 0 {
		weightVuln = 0
	}

	return clampFloat(weightPort*portStage + weightWeb*webStage + weightVuln*clampFloat(vuln))
}

func (s *Scanner) phasePercent(name string) int {
	s.phasesMu.Lock()
	defer s.phasesMu.Unlock()
	pp, ok := s.phases[name]
	if !ok {
		return 0
	}
	return clampPercent(pp.Percent)
}

// Pocs returns the PoCs loaded for this scan.
func (s *Scanner) Pocs() []poc.Poc {
	out := make([]poc.Poc, len(s.pocs))
	copy(out, s.pocs)
	return out
}

// PocCount returns how many PoCs were loaded.
func (s *Scanner) PocCount() int { return len(s.pocs) }

// PocDiagnostics returns the PoCs skipped during loading and the reason for
// each. These used to be printed to the console and were invisible to callers.
func (s *Scanner) PocDiagnostics() []config.PocLoadError {
	out := make([]config.PocLoadError, len(s.pocDiags))
	copy(out, s.pocDiags)
	return out
}

// CuratedError reports why the optional curated PoC source failed to mount.
// It is never fatal; nil means the source mounted or was disabled.
func (s *Scanner) CuratedError() error { return s.curatedErr }

// Info returns a summary of the scan without writing anything to the console.
//
// When OOB is enabled this performs a live connectivity probe against the OOB
// service.
func (s *Scanner) Info() ScanInfo {
	stats := s.Stats()

	list := make([]string, 0, stats.TotalTargets)
	for _, t := range s.internal.Targets.List() {
		if v, ok := t.(string); ok {
			list = append(list, v)
		}
	}

	info := ScanInfo{
		TotalTargets: stats.TotalTargets,
		TotalPocs:    stats.TotalPocs,
		TotalScans:   stats.TotalScans,
		Targets:      list,
		OOBStatus:    "disabled",
	}
	if s.opts.OOB.Enabled {
		info.OOBEnabled, info.OOBStatus = s.OOBStatus()
	}
	return info
}

// OOBStatus reports whether out-of-band detection is usable, together with a
// human-readable description. It performs a live probe against the configured
// OOB service.
func (s *Scanner) OOBStatus() (bool, string) {
	if !s.opts.OOB.Enabled {
		return false, "disabled"
	}

	adapter := strings.ToLower(strings.TrimSpace(s.opts.OOB.Adapter))
	if adapter == "" {
		return false, "not configured"
	}
	if s.internal.OOBKey == "" && s.internal.OOBDomain == "" {
		return false, fmt.Sprintf("%s (incomplete configuration)", adapter)
	}

	// Serialise probes: concurrent callers would otherwise open redundant
	// connections to the OOB service.
	s.oobProbedMu.Lock()
	defer s.oobProbedMu.Unlock()

	client, err := oobadapter.NewOOBAdapter(s.internal.OOB, &oobadapter.ConnectorParams{
		Key:     s.internal.OOBKey,
		Domain:  s.internal.OOBDomain,
		HTTPUrl: s.internal.OOBHttpUrl,
		ApiUrl:  s.internal.OOBApiUrl,
	})
	if err != nil {
		return false, fmt.Sprintf("%s (initialisation failed: %v)", adapter, err)
	}
	if !client.IsVaild() {
		return false, fmt.Sprintf("%s (unreachable)", adapter)
	}
	return true, fmt.Sprintf("%s (ok)", adapter)
}

// printSummary writes the scan summary to stdout, but only when the caller
// opted in with WithVerbose. The SDK is otherwise completely silent.
func (s *Scanner) printSummary() {
	if !s.opts.Verbose {
		return
	}
	info := s.Info()

	fmt.Printf("\n========== afrog scan ==========\n")
	fmt.Printf("targets : %d\n", info.TotalTargets)
	fmt.Printf("pocs    : %d\n", info.TotalPocs)
	fmt.Printf("tasks   : %d\n", info.TotalScans)

	const preview = 3
	if len(info.Targets) <= 5 {
		fmt.Printf("scope   : %s\n", strings.Join(info.Targets, ", "))
	} else {
		fmt.Printf("scope   : %s ... (+%d)\n", strings.Join(info.Targets[:preview], ", "), len(info.Targets)-preview)
	}
	fmt.Printf("oob     : %s\n", info.OOBStatus)
	fmt.Printf("================================\n")
}

// ------------------------------------------------------------------ helpers

func clampPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func clampFloat(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// -------------------------------------------------- internal option plumbing

// builtConfig is the outcome of translating SDK options into engine options.
//
// curatedErr is kept separate from the function's error result because the two
// have different severities: a curated mount failure degrades the PoC set but
// must not prevent the scan from running.
type builtConfig struct {
	options    *config.Options
	curatedErr error
	// envRestore undoes the process-wide environment changes made while
	// mounting the curated PoC source.
	envRestore []envEntry
}

// buildInternalOptions converts the SDK options into the engine configuration.
func buildInternalOptions(opts *Options) (*builtConfig, error) {
	internal := &config.Options{
		TargetsFile:                    opts.TargetsFile,
		PocPaths:                       opts.PocPaths,
		PocPathsOnly:                   opts.PocPathsOnly,
		Search:                         opts.Search,
		Severity:                       opts.Severity,
		ExcludePocs:                    opts.ExcludePocs,
		ExcludePocsFile:                opts.ExcludePocsFile,
		RateLimit:                      opts.RateLimit,
		Concurrency:                    opts.Concurrency,
		Retries:                        opts.Retries,
		Timeout:                        opts.Timeout,
		MaxHostError:                   opts.MaxHostError,
		MaxRespBodySize:                opts.MaxRespBodySize,
		BruteMaxRequests:               opts.BruteMaxRequests,
		ReqLimitPerTarget:              opts.ReqLimitPerTarget,
		AutoReqLimit:                   opts.AutoReqLimit,
		Polite:                         opts.Polite,
		Balanced:                       opts.Balanced,
		Aggressive:                     opts.Aggressive,
		Smart:                          opts.Smart,
		DefaultAccept:                  opts.DefaultAccept,
		DisableFingerprint:             opts.DisableFingerprint,
		EnableWebProbe:                 opts.EnableWebProbe,
		FingerprintFilterMode:          opts.FingerprintFilterMode,
		VulnerabilityScannerBreakpoint: opts.StopOnFirstMatch,
		Proxy:                          opts.Proxy,
		Header:                         opts.Headers,
		Dingtalk:                       opts.Dingtalk,
		Wecom:                          opts.Wecom,

		PortScan:        opts.EnablePortSan,
		PSPorts:         opts.PortScan.Ports,
		PSRateLimit:     opts.PortScan.RateLimit,
		PSTimeout:       opts.PortScan.TimeoutMs,
		PSRetries:       opts.PortScan.Retries,
		PSSkipDiscovery: opts.PortScan.SkipDiscovery,
		PSS4Chunk:       opts.PortScan.ChunkSize,

		OOBRateLimit:       opts.OOB.RateLimit,
		OOBConcurrency:     opts.OOB.Concurrency,
		OOBFinalizeTimeout: opts.OOB.FinalizeTimeout,
		OOBPollInterval:    opts.OOB.PollInterval,
		OOBHitRetention:    opts.OOB.HitRetention,

		TaskHardTimeoutSec:       opts.TaskTimeout.HardSec,
		TaskSmartTimeout:         opts.TaskTimeout.Smart,
		TaskTimeoutVisibleCapSec: opts.TaskTimeout.VisibleCapSec,
		TaskTimeoutNetCapSec:     opts.TaskTimeout.NetCapSec,
		TaskTimeoutGoCapSec:      opts.TaskTimeout.GoCapSec,

		Cyberspace: opts.Cyberspace.Engine,
		Query:      opts.Cyberspace.Query,
		QueryCount: opts.Cyberspace.Count,

		MonitorTargets: opts.TargetPreProbe,
		Resume:         opts.Checkpoint.Path,

		PocExecutionDurationMonitor: opts.EnableMonitor,
		PedmLogLimit:                opts.Monitor.LogLimit,
		PedmSlowThresholdSec:        opts.Monitor.SlowThresholdSec,
		PedmSlowLogLimit:            opts.Monitor.SlowLogLimit,
		PedmSummaryTop:              opts.Monitor.SummaryTop,
		PedmSummaryBy:               opts.Monitor.SummaryBy,

		CuratedEnabled:     opts.Curated.Enabled,
		CuratedEndpoint:    opts.Curated.Endpoint,
		CuratedTimeout:     opts.Curated.TimeoutSec,
		CuratedForceUpdate: opts.Curated.ForceUpdate,
	}

	internal.Target = append(internal.Target, opts.Targets...)

	// SDK mode: silent, no update checks, no report files.
	internal.SDKMode = true
	internal.Silent = true
	internal.DisableUpdateCheck = true
	internal.DisableOutputHtml = true
	internal.Json = ""
	internal.JsonAll = ""
	internal.Output = ""

	// Read the user configuration without touching the filesystem. A library
	// constructor must not create directories, write files, or rewrite an
	// existing user config.
	cfg, err := config.LoadConfigReadOnly("")
	if err != nil {
		cfg = &config.Config{}
	}
	internal.Config = cfg

	if v := strings.TrimSpace(opts.Curated.Enabled); v != "" {
		cfg.Curated.Enabled = v
	}
	if v := strings.TrimSpace(opts.Curated.Endpoint); v != "" {
		cfg.Curated.Endpoint = v
	}
	if opts.Curated.TimeoutSec > 0 {
		cfg.Curated.TimeoutSec = opts.Curated.TimeoutSec
	}

	if err := applyOOB(internal, opts, cfg); err != nil {
		return nil, err
	}
	if err := validateWebhooks(internal); err != nil {
		return nil, err
	}
	if inputs := opts.pocInputs(); len(inputs) > 0 {
		if err := config.ValidatePocInputs(inputs); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPocPathNotFound, err)
		}
	}

	var envRestore []envEntry
	curatedErr := mountCurated(internal, &envRestore)
	return &builtConfig{options: internal, curatedErr: curatedErr, envRestore: envRestore}, nil
}

// applyOOB resolves the OOB configuration, falling back to the user config
// file when the caller did not supply credentials.
func applyOOB(internal *config.Options, opts *Options, cfg *config.Config) error {
	if !opts.OOB.Enabled {
		return nil
	}

	internal.EnableOOB = true
	internal.OOB = opts.OOB.Adapter
	internal.OOBKey = opts.OOB.Key
	internal.OOBDomain = opts.OOB.Domain
	internal.OOBApiUrl = opts.OOB.ApiURL
	internal.OOBHttpUrl = opts.OOB.HttpURL

	noCredentials := internal.OOBKey == "" && internal.OOBDomain == "" &&
		internal.OOBApiUrl == "" && internal.OOBHttpUrl == ""
	if noCredentials {
		reverse := cfg.Reverse
		switch strings.ToLower(internal.OOB) {
		case "ceyeio":
			internal.OOBKey = reverse.Ceye.ApiKey
			internal.OOBDomain = reverse.Ceye.Domain
		case "dnslogcn":
			internal.OOBDomain = reverse.Dnslogcn.Domain
		case "alphalog":
			internal.OOBDomain = reverse.Alphalog.Domain
			internal.OOBApiUrl = reverse.Alphalog.ApiUrl
		case "xray":
			internal.OOBKey = reverse.Xray.XToken
			internal.OOBDomain = reverse.Xray.Domain
			internal.OOBApiUrl = reverse.Xray.ApiUrl
		case "revsuit":
			internal.OOBKey = reverse.Revsuit.Token
			internal.OOBDomain = reverse.Revsuit.DnsDomain
			internal.OOBApiUrl = reverse.Revsuit.ApiUrl
			internal.OOBHttpUrl = reverse.Revsuit.HttpUrl
		}
	}

	if strings.EqualFold(internal.OOB, "dnslogcn") && internal.OOBDomain == "" {
		internal.OOBDomain = "dnslog.cn"
	}
	return nil
}

func validateWebhooks(internal *config.Options) error {
	if internal.Config == nil {
		return nil
	}
	empty := func(tokens []string) bool {
		for _, t := range tokens {
			if strings.TrimSpace(t) != "" {
				return false
			}
		}
		return true
	}
	if internal.Dingtalk && empty(internal.Config.Webhook.Dingtalk.Tokens) {
		return fmt.Errorf("%w: dingtalk", ErrWebhookTokenRequired)
	}
	if internal.Wecom && empty(internal.Config.Webhook.Wecom.Tokens) {
		return fmt.Errorf("%w: wecom", ErrWebhookTokenRequired)
	}
	return nil
}

// Environment variables through which the PoC repository learns about the
// curated source.
const (
	envCuratedDisabled = "AFROG_CURATED_DISABLED"
	envCuratedDir      = "AFROG_POCS_CURATED_DIR"
)

// setEnv changes an environment variable and records how to undo it.
func setEnv(restore *[]envEntry, key, value string) {
	prev, ok := os.LookupEnv(key)
	*restore = append(*restore, envEntry{key: key, value: prev, set: ok})
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

// mountCurated mounts the optional curated PoC source. Failures are reported
// but never abort the scan.
//
// It communicates with the PoC repository through process-wide environment
// variables, so it records the previous values for Close to restore. Without
// that, a later scanner in the same process would inherit this one's curated
// directory and silently scan with the wrong PoC set.
func mountCurated(internal *config.Options, restore *[]envEntry) error {
	cur := internal.Config.Curated
	enabled := strings.ToLower(strings.TrimSpace(cur.Enabled))
	endpoint := strings.TrimSpace(cur.Endpoint)

	if enabled == "off" || enabled == "false" || enabled == "0" || endpoint == "" {
		setEnv(restore, envCuratedDisabled, "1")
		setEnv(restore, envCuratedDir, "")
		return nil
	}
	setEnv(restore, envCuratedDisabled, "")

	svc := service.New(service.Config{
		Endpoint:      endpoint,
		Channel:       strings.TrimSpace(cur.Channel),
		LicenseKey:    strings.TrimSpace(cur.LicenseKey),
		NoUpdate:      cur.AutoUpdate != nil && !*cur.AutoUpdate && !internal.CuratedForceUpdate,
		ForceUpdate:   internal.CuratedForceUpdate,
		ClientVersion: config.Version,
	})

	ctx := context.Background()
	var cancel context.CancelFunc
	if cur.TimeoutSec > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cur.TimeoutSec)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	dir, err := svc.Mount(ctx)
	if err != nil {
		return &CuratedMountError{Err: err}
	}
	if strings.TrimSpace(dir) != "" {
		setEnv(restore, envCuratedDir, dir)
	}
	return nil
}

// buildRunner initialises the HTTP client, resolves the target set and builds
// the scan engine.
func buildRunner(internal *config.Options) (*runner.Runner, error) {
	if err := retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:             internal.Proxy,
		Timeout:           internal.Timeout,
		Retries:           internal.Retries,
		MaxRespBodySize:   internal.MaxRespBodySize,
		ReqLimitPerTarget: internal.ReqLimitPerTarget,
		DefaultAccept:     internal.DefaultAccept,
	}); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	appendTargets := func(raws []string) {
		for _, raw := range raws {
			t := strings.TrimSpace(raw)
			if t == "" {
				continue
			}
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			internal.Targets.Append(t)
		}
	}

	appendTargets(internal.Target)
	if internal.TargetsFile != "" {
		lines, err := utils.ReadFileLineByLine(internal.TargetsFile)
		if err != nil {
			return nil, err
		}
		appendTargets(lines)
	}

	// A cyberspace query resolves to targets inside NewRunner, so the target
	// set can legitimately still be empty at this point.
	fromCyberspace := strings.TrimSpace(internal.Cyberspace) != "" && strings.TrimSpace(internal.Query) != ""
	if internal.Targets.Len() == 0 && !fromCyberspace {
		return nil, ErrNoTargets
	}

	for _, p := range internal.PocPaths {
		if v := strings.TrimSpace(p); v != "" {
			internal.PocsDirectory.Set(v)
		}
	}

	// NewRunner would otherwise re-append these to Targets.
	internal.Target = nil

	r, err := runner.NewRunner(internal)
	if err != nil {
		return nil, err
	}
	// A search that matched nothing leaves the runner with no work to do. The
	// CLI tolerates that; a library caller is better served by an error.
	if internal.Targets.Len() == 0 {
		r.Release()
		return nil, ErrNoTargets
	}
	return r, nil
}
