// Package afrog is the backward-compatible facade over the afrog scanner.
//
// It preserves the original SDK surface — [NewSDKOptions], [NewSDKScanner] and
// the [SDKScanner] methods — so existing integrations keep compiling and
// behaving as before. Everything here delegates to [pkg/sdk], which is the
// current, context-aware API; new code should prefer that package directly.
//
// The facade exists so the two can coexist: one implementation, two entry
// points. Fixes and features added to pkg/sdk reach callers of this package
// automatically.
package afrog

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

// OOBAdapter reports whether an out-of-band service is reachable.
type OOBAdapter interface {
	IsVaild() bool
}

// PortScanResult is an open port found during the port pre-scan.
type PortScanResult struct {
	Host string
	Port int
}

// HostDiscoveryResult is a live host found during discovery.
type HostDiscoveryResult struct {
	Host string
}

// WebProbeResult is the metadata of a probed web service.
type WebProbeResult struct {
	URL       string
	Title     string
	Server    string
	PoweredBy string
}

// PhaseProgress is the progress of one scan phase.
type PhaseProgress struct {
	Phase    string
	Status   string
	Finished int64
	Total    int64
	Percent  int
}

// ScanInfoUpdate summarises the scan as the engine resolves it.
type ScanInfoUpdate struct {
	TotalTargets int
	Targets      []string
	TotalPocs    int
	TotalScans   int
	OOBEnabled   bool
	OOBStatus    string
}

// ScanStats holds the scan counters.
type ScanStats struct {
	StartTime      time.Time
	EndTime        time.Time
	TotalTargets   int
	TotalPocs      int
	TotalScans     int
	CompletedScans int32
	FoundVulns     int32
}

// SDKOptions is the scanner configuration.
//
// The fields up to and including the curated section are the original ones and
// keep their original meaning. The block at the end exposes capabilities added
// after this facade was introduced; leaving them zero reproduces the previous
// behaviour exactly.
type SDKOptions struct {
	Targets     []string
	TargetsFile string

	// PocFile restricts the scan to the given file or directory, hiding the
	// built-in PoCs. AppendPoc adds to the built-in set instead.
	//
	// Specifying both used to silently drop AppendPoc; both are now honoured.
	PocFile   string
	AppendPoc []string

	Search          string
	Severity        string
	ExcludePocs     []string
	ExcludePocsFile string

	RateLimit         int
	ReqLimitPerTarget int
	AutoReqLimit      bool
	Polite            bool
	Balanced          bool
	Aggressive        bool
	Concurrency       int
	Retries           int
	Timeout           int
	MaxHostError      int
	Smart             bool

	DisableFingerprint    bool
	EnableWebProbe        bool
	FingerprintFilterMode string

	MaxRespBodySize  int
	BruteMaxRequests int
	DefaultAccept    bool

	// VulnerabilityScannerBreakpoint stops the scan on the first finding.
	VulnerabilityScannerBreakpoint bool

	PortScan        bool
	PSPorts         string
	PSRateLimit     int
	PSTimeout       int
	PSRetries       int
	PSSkipDiscovery bool
	PSS4Chunk       int

	Proxy   string
	Headers []string

	EnableOOB          bool
	OOB                string
	OOBKey             string
	OOBDomain          string
	OOBApiUrl          string
	OOBHttpUrl         string
	OOBRateLimit       int
	OOBConcurrency     int
	OOBFinalizeTimeout int

	// EnableStream allocates the SDKScanner channels. Without it the channels
	// stay nil and only the callbacks fire.
	EnableStream bool

	Dingtalk bool
	Wecom    bool

	CuratedEnabled     string
	CuratedEndpoint    string
	CuratedTimeout     int
	CuratedForceUpdate bool

	// --- added after the original SDK; zero values keep the old behaviour ---

	// Silent suppresses the scan summary Run prints before starting. The
	// original SDK always printed it.
	Silent bool

	// PocPaths accepts files, directories and glob patterns such as
	// "dir/*.yaml". Entries are appended to the built-in PoCs unless
	// PocPathsOnly is set.
	PocPaths     []string
	PocPathsOnly bool

	// IncludeRequestResponse keeps the raw request and response on every
	// result. It defaults to true; set DisableRequestResponse to opt out on
	// large scans.
	DisableRequestResponse bool
	// MaxStoredResults caps how many results accumulate in memory. Zero means
	// unlimited.
	MaxStoredResults int
	// RedactedHeaders masks these headers in stored results. Use
	// [sdk.DefaultRedactedHeaders] for the usual credential-bearing set.
	RedactedHeaders []string

	// OOBPollInterval is the out-of-band poll interval in seconds and
	// OOBHitRetention how long a hit is kept, in minutes. Zero uses the same
	// defaults as the command line.
	OOBPollInterval int
	OOBHitRetention int

	// TaskHardTimeoutSec caps a single target+PoC task, in seconds.
	// TaskSmartTimeout derives that cap from the PoC's content instead; when
	// both are set the larger wins.
	TaskHardTimeoutSec int
	TaskSmartTimeout   bool

	// ResumeFile makes the scan resumable: finished target/PoC pairs are
	// recorded there and skipped on a later run.
	ResumeFile string

	// Cyberspace sources targets from a search engine instead of, or in
	// addition to, Targets. Only "zoomeye" is implemented.
	Cyberspace string
	Query      string
	QueryCount int

	// MonitorTargets probes each target's protocol and liveness in parallel
	// with the scan.
	MonitorTargets bool

	// OnFailure reports PoC executions that failed. These used to be
	// discarded, leaving no way to tell a clean scan from a broken one.
	OnFailure func(target string, pocID string, err error)
}

// NewSDKOptions returns the default configuration.
func NewSDKOptions() *SDKOptions {
	return &SDKOptions{
		RateLimit:             150,
		Concurrency:           25,
		Retries:               1,
		Timeout:               50,
		MaxHostError:          3,
		MaxRespBodySize:       2,
		BruteMaxRequests:      5000,
		DefaultAccept:         true,
		FingerprintFilterMode: "strict",
		PSPorts:               "top",
		PSS4Chunk:             1000,
		OOBRateLimit:          25,
		OOBConcurrency:        25,
		OOBFinalizeTimeout:    -1,
	}
}

// SDKScanner runs a vulnerability scan.
//
// Assign the On* callbacks and read the channels exactly as before. The
// channels are only allocated when SDKOptions.EnableStream is set, and a send
// to a full channel is dropped rather than blocking the scan, which is what
// the original implementation did.
type SDKScanner struct {
	// OnResult receives every finding, as the engine's own result type.
	OnResult func(*result.Result)
	// OnPort receives every open port found by the port pre-scan.
	OnPort func(host string, port int)
	// OnWebProbe receives every probed web service.
	OnWebProbe func(r WebProbeResult)

	ResultChan        chan *result.Result
	PortChan          chan PortScanResult
	HostChan          chan HostDiscoveryResult
	WebProbeChan      chan WebProbeResult
	PhaseProgressChan chan PhaseProgress
	ScanInfoChan      chan ScanInfoUpdate

	opts *SDKOptions

	// scanner is rebuilt when one of the Set* methods changes the
	// configuration after construction, because the underlying scanner takes
	// its options once, at creation.
	mu      sync.Mutex
	scanner *sdk.Scanner
	dirty   bool

	resultsMu sync.Mutex
	results   []*result.Result

	stats ScanStats

	ctx    context.Context
	cancel context.CancelFunc

	closeChansOnce sync.Once
	runDoneOnce    sync.Once
	runDone        chan struct{}
	started        atomic.Bool
	closed         atomic.Bool
}

// NewSDKScanner creates a scanner from the given options. A nil opts uses the
// defaults.
func NewSDKScanner(opts *SDKOptions) (*SDKScanner, error) {
	if opts == nil {
		opts = NewSDKOptions()
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &SDKScanner{
		opts:    opts,
		ctx:     ctx,
		cancel:  cancel,
		runDone: make(chan struct{}),
	}

	if opts.EnableStream {
		s.ResultChan = make(chan *result.Result, 100)
		s.PortChan = make(chan PortScanResult, 100)
		s.HostChan = make(chan HostDiscoveryResult, 256)
		s.WebProbeChan = make(chan WebProbeResult, 100)
		s.PhaseProgressChan = make(chan PhaseProgress, 64)
		s.ScanInfoChan = make(chan ScanInfoUpdate, 16)
	}

	// Build eagerly so configuration errors surface here rather than at Run,
	// which is where the original SDK reported them.
	scanner, err := s.build()
	if err != nil {
		cancel()
		return nil, err
	}
	s.scanner = scanner
	s.refreshStats()

	return s, nil
}

// build translates the options into the current SDK and creates a scanner.
func (s *SDKScanner) build() (*sdk.Scanner, error) {
	o := s.opts

	options := []sdk.Option{
		sdk.WithTargets(o.Targets...),
		sdk.WithConcurrency(orDefault(o.Concurrency, 25)),
		sdk.WithRateLimit(orDefault(o.RateLimit, 150)),
		sdk.WithTimeout(orDefault(o.Timeout, 50)),
		sdk.WithMaxRespBodySize(orDefault(o.MaxRespBodySize, 2)),

		sdk.WithResultHandler(func(sdk.Result) {}), // keeps the result path warm
		sdk.WithRawResultHandler(s.handleRawResult),
		sdk.WithPortHandler(s.handlePort),
		sdk.WithHostHandler(s.handleHost),
		sdk.WithWebProbeHandler(s.handleWebProbe),
		sdk.WithProgressHandler(s.handleProgress),
		sdk.WithScanInfoHandler(s.handleScanInfo),
		sdk.WithFailureHandler(s.handleFailure),
	}

	if o.Retries >= 0 {
		options = append(options, sdk.WithRetries(o.Retries))
	}
	if o.MaxHostError >= 0 {
		options = append(options, sdk.WithMaxHostError(o.MaxHostError))
	}
	if strings.TrimSpace(o.TargetsFile) != "" {
		options = append(options, sdk.WithTargetsFile(o.TargetsFile))
	}

	// PocFile keeps its exclusive meaning; PocPaths and AppendPoc append.
	// Combining them used to drop AppendPoc silently.
	var pocPaths []string
	if v := strings.TrimSpace(o.PocFile); v != "" {
		pocPaths = append(pocPaths, v)
	}
	pocPaths = append(pocPaths, o.PocPaths...)
	pocPaths = append(pocPaths, o.AppendPoc...)
	if len(pocPaths) > 0 {
		options = append(options, sdk.WithPocPaths(pocPaths...))
	}
	if o.PocPathsOnly || strings.TrimSpace(o.PocFile) != "" {
		options = append(options, sdk.WithPocPathsOnly())
	}

	if v := strings.TrimSpace(o.Search); v != "" {
		options = append(options, sdk.WithSearch(v))
	}
	if v := strings.TrimSpace(o.Severity); v != "" {
		options = append(options, sdk.WithSeverity(v))
	}
	if len(o.ExcludePocs) > 0 {
		options = append(options, sdk.WithExcludePocs(o.ExcludePocs...))
	}
	if v := strings.TrimSpace(o.ExcludePocsFile); v != "" {
		options = append(options, sdk.WithExcludePocsFile(v))
	}

	if o.ReqLimitPerTarget > 0 {
		options = append(options, sdk.WithRequestLimitPerTarget(o.ReqLimitPerTarget))
	}
	if o.AutoReqLimit {
		options = append(options, sdk.WithAutoRequestLimit())
	}
	if o.Polite {
		options = append(options, sdk.WithPolite())
	}
	if o.Balanced {
		options = append(options, sdk.WithBalanced())
	}
	if o.Aggressive {
		options = append(options, sdk.WithAggressive())
	}
	if o.Smart {
		options = append(options, sdk.WithSmartConcurrency())
	}
	if o.VulnerabilityScannerBreakpoint {
		options = append(options, sdk.WithStopOnFirstMatch())
	}

	if o.DisableFingerprint {
		options = append(options, sdk.WithFingerprintDisabled())
	}
	if v := strings.TrimSpace(o.FingerprintFilterMode); v != "" {
		options = append(options, sdk.WithFingerprintFilterMode(v))
	}
	if o.EnableWebProbe {
		options = append(options, sdk.WithWebProbe())
	}

	if v := strings.TrimSpace(o.Proxy); v != "" {
		options = append(options, sdk.WithProxy(v))
	}
	if len(o.Headers) > 0 {
		options = append(options, sdk.WithHeaders(o.Headers...))
	}

	if o.PortScan {
		options = append(options, sdk.WithPortScan(sdk.PortScanOptions{
			Ports:         o.PSPorts,
			RateLimit:     o.PSRateLimit,
			TimeoutMs:     o.PSTimeout,
			Retries:       o.PSRetries,
			SkipDiscovery: o.PSSkipDiscovery,
			ChunkSize:     o.PSS4Chunk,
		}))
	}

	if o.EnableOOB && strings.TrimSpace(o.OOB) != "" {
		options = append(options, sdk.WithOOB(sdk.OOBOptions{
			Adapter:         o.OOB,
			Key:             o.OOBKey,
			Domain:          o.OOBDomain,
			ApiURL:          o.OOBApiUrl,
			HttpURL:         o.OOBHttpUrl,
			RateLimit:       o.OOBRateLimit,
			Concurrency:     o.OOBConcurrency,
			FinalizeTimeout: o.OOBFinalizeTimeout,
			PollInterval:    o.OOBPollInterval,
			HitRetention:    o.OOBHitRetention,
		}))
	}

	if o.Dingtalk {
		options = append(options, sdk.WithDingtalk())
	}
	if o.Wecom {
		options = append(options, sdk.WithWecom())
	}

	if strings.TrimSpace(o.CuratedEnabled) != "" || strings.TrimSpace(o.CuratedEndpoint) != "" ||
		o.CuratedTimeout > 0 || o.CuratedForceUpdate {
		options = append(options, sdk.WithCurated(sdk.CuratedOptions{
			Enabled:     o.CuratedEnabled,
			Endpoint:    o.CuratedEndpoint,
			TimeoutSec:  o.CuratedTimeout,
			ForceUpdate: o.CuratedForceUpdate,
		}))
	}

	if o.DisableRequestResponse {
		options = append(options, sdk.WithRequestResponse(false))
	}
	if o.MaxStoredResults > 0 {
		options = append(options, sdk.WithMaxStoredResults(o.MaxStoredResults))
	}
	if len(o.RedactedHeaders) > 0 {
		options = append(options, sdk.WithRedactedHeaders(o.RedactedHeaders...))
	}

	if o.TaskHardTimeoutSec > 0 || o.TaskSmartTimeout {
		options = append(options, sdk.WithTaskTimeout(sdk.TaskTimeoutOptions{
			HardSec: o.TaskHardTimeoutSec,
			Smart:   o.TaskSmartTimeout,
		}))
	}
	if v := strings.TrimSpace(o.ResumeFile); v != "" {
		options = append(options, sdk.WithCheckpoint(sdk.CheckpointOptions{Path: v}))
	}
	if strings.TrimSpace(o.Cyberspace) != "" {
		options = append(options, sdk.WithCyberspace(sdk.CyberspaceOptions{
			Engine: o.Cyberspace,
			Query:  o.Query,
			Count:  o.QueryCount,
		}))
	}
	if o.MonitorTargets {
		options = append(options, sdk.WithTargetPreProbe())
	}

	return sdk.New(s.ctx, options...)
}

func orDefault(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

// --- event plumbing ---------------------------------------------------------
//
// The callbacks and channels are public fields that callers assign after
// construction, so every handler reads them at call time rather than
// capturing them when the scanner is built.

func (s *SDKScanner) handleRawResult(r *result.Result) {
	if r == nil {
		return
	}
	s.resultsMu.Lock()
	s.results = append(s.results, r)
	s.resultsMu.Unlock()
	atomic.AddInt32(&s.stats.FoundVulns, 1)

	if fn := s.OnResult; fn != nil {
		fn(r)
	}
	sendOrDrop(s.ctx, s.ResultChan, r)
}

func (s *SDKScanner) handlePort(e sdk.PortEvent) {
	if fn := s.OnPort; fn != nil {
		fn(e.Host, e.Port)
	}
	sendOrDrop(s.ctx, s.PortChan, PortScanResult{Host: e.Host, Port: e.Port})
}

func (s *SDKScanner) handleHost(e sdk.HostEvent) {
	sendOrDrop(s.ctx, s.HostChan, HostDiscoveryResult{Host: e.Host})
}

func (s *SDKScanner) handleWebProbe(e sdk.WebProbeEvent) {
	r := WebProbeResult{URL: e.URL, Title: e.Title, Server: e.Server, PoweredBy: e.PoweredBy}
	if fn := s.OnWebProbe; fn != nil {
		fn(r)
	}
	sendOrDrop(s.ctx, s.WebProbeChan, r)
}

func (s *SDKScanner) handleProgress(p sdk.PhaseProgress) {
	if p.Phase == sdk.PhaseVuln {
		atomic.StoreInt32(&s.stats.CompletedScans, int32(p.Finished))
	}
	sendOrDrop(s.ctx, s.PhaseProgressChan, PhaseProgress{
		Phase:    p.Phase,
		Status:   p.Status,
		Finished: p.Finished,
		Total:    p.Total,
		Percent:  p.Percent,
	})
}

func (s *SDKScanner) handleScanInfo(i sdk.ScanInfo) {
	sendOrDrop(s.ctx, s.ScanInfoChan, ScanInfoUpdate{
		TotalTargets: i.TotalTargets,
		Targets:      i.Targets,
		TotalPocs:    i.TotalPocs,
		TotalScans:   i.TotalScans,
		OOBEnabled:   i.OOBEnabled,
		OOBStatus:    i.OOBStatus,
	})
}

func (s *SDKScanner) handleFailure(f sdk.Failure) {
	if fn := s.opts.OnFailure; fn != nil {
		fn(f.Target, f.PocID, f.Err)
	}
}

// sendOrDrop mirrors the original streaming behaviour: a full channel drops
// the value instead of stalling the scan. Callers that never drain a channel
// would otherwise deadlock the whole scan, which is why this cannot become a
// blocking send.
func sendOrDrop[T any](ctx context.Context, ch chan T, v T) {
	if ch == nil {
		return
	}
	// A send racing closeChans would panic; the scan must not die for that.
	defer func() { _ = recover() }()
	select {
	case ch <- v:
	case <-ctx.Done():
	default:
	}
}

func (s *SDKScanner) closeChans() {
	s.closeChansOnce.Do(func() {
		for _, c := range []func(){
			func() { closeChan(s.ResultChan) },
			func() { closeChan(s.PortChan) },
			func() { closeChan(s.HostChan) },
			func() { closeChan(s.WebProbeChan) },
			func() { closeChan(s.PhaseProgressChan) },
			func() { closeChan(s.ScanInfoChan) },
		} {
			c()
		}
	})
}

func closeChan[T any](ch chan T) {
	if ch != nil {
		close(ch)
	}
}

// --- lifecycle --------------------------------------------------------------

// Run executes the scan synchronously and returns when it finishes.
func (s *SDKScanner) Run() error {
	sc, err := s.current()
	if err != nil {
		return err
	}
	s.started.Store(true)
	s.printScanInfo()

	runErr := sc.Execute(s.ctx)

	s.refreshStats()
	s.stats.EndTime = time.Now()
	s.closeChans()
	s.runDoneOnce.Do(func() { close(s.runDone) })
	return runErr
}

// RunAsync starts the scan in the background and returns immediately.
func (s *SDKScanner) RunAsync() error {
	sc, err := s.current()
	if err != nil {
		return err
	}
	s.started.Store(true)
	go func() {
		s.printScanInfo()
		_ = sc.Execute(s.ctx)
		s.refreshStats()
		s.stats.EndTime = time.Now()
		s.closeChans()
		s.runDoneOnce.Do(func() { close(s.runDone) })
	}()
	return nil
}

// current returns the scanner to run, rebuilding it when a Set* call changed
// the configuration after construction.
func (s *SDKScanner) current() (*sdk.Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return s.scanner, nil
	}
	rebuilt, err := s.build()
	if err != nil {
		return nil, err
	}
	if s.scanner != nil {
		_ = s.scanner.Close()
	}
	s.scanner = rebuilt
	s.dirty = false
	s.refreshStatsLocked()
	return s.scanner, nil
}

// Stop asks the scan to stop and returns immediately.
func (s *SDKScanner) Stop() {
	s.mu.Lock()
	sc := s.scanner
	s.mu.Unlock()
	if sc != nil {
		sc.Stop()
	}
	s.cancel()
}

// Close stops the scan, waits for it to finish and releases every resource.
// It is safe to call more than once.
func (s *SDKScanner) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.Stop()
	if s.started.Load() {
		<-s.runDone
	}
	s.closeChans()

	s.mu.Lock()
	sc := s.scanner
	s.mu.Unlock()
	if sc != nil {
		_ = sc.Close()
	}

	s.resultsMu.Lock()
	s.results = nil
	s.resultsMu.Unlock()
}

// Pause suspends task scheduling.
func (s *SDKScanner) Pause() {
	if sc := s.peek(); sc != nil {
		sc.Pause()
	}
}

// Resume resumes a paused scan.
func (s *SDKScanner) Resume() {
	if sc := s.peek(); sc != nil {
		sc.Resume()
	}
}

// IsPaused reports whether the scan is paused.
func (s *SDKScanner) IsPaused() bool {
	sc := s.peek()
	return sc != nil && sc.IsPaused()
}

// IsStopping reports whether Stop has been called.
func (s *SDKScanner) IsStopping() bool {
	sc := s.peek()
	return sc != nil && sc.IsStopping()
}

func (s *SDKScanner) peek() *sdk.Scanner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanner
}

// --- results ----------------------------------------------------------------

// GetResults returns the findings collected so far.
func (s *SDKScanner) GetResults() []*result.Result {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	out := make([]*result.Result, len(s.results))
	copy(out, s.results)
	return out
}

// GetOpenPorts returns the open ports discovered by the port pre-scan.
func (s *SDKScanner) GetOpenPorts() map[string][]int {
	if sc := s.peek(); sc != nil {
		return sc.OpenPorts()
	}
	return map[string][]int{}
}

// HasVulnerabilities reports whether any vulnerability was found.
func (s *SDKScanner) HasVulnerabilities() bool {
	return s.GetVulnerabilityCount() > 0
}

// GetVulnerabilityCount returns the number of findings.
func (s *SDKScanner) GetVulnerabilityCount() int {
	if sc := s.peek(); sc != nil {
		return sc.ResultCount()
	}
	return 0
}

// GetStats returns a snapshot of the scan counters.
func (s *SDKScanner) GetStats() ScanStats {
	s.refreshStats()
	out := s.stats
	out.CompletedScans = atomic.LoadInt32(&s.stats.CompletedScans)
	out.FoundVulns = atomic.LoadInt32(&s.stats.FoundVulns)
	return out
}

func (s *SDKScanner) refreshStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshStatsLocked()
}

func (s *SDKScanner) refreshStatsLocked() {
	if s.scanner == nil {
		return
	}
	st := s.scanner.Stats()
	s.stats.StartTime = st.StartTime
	if !st.EndTime.IsZero() {
		s.stats.EndTime = st.EndTime
	}
	s.stats.TotalTargets = st.TotalTargets
	s.stats.TotalPocs = st.TotalPocs
	s.stats.TotalScans = st.TotalScans
	atomic.StoreInt32(&s.stats.CompletedScans, int32(st.CompletedScans))
	atomic.StoreInt32(&s.stats.FoundVulns, int32(st.FoundVulns))
}

// GetProgress returns overall scan progress in the range [0, 100].
func (s *SDKScanner) GetProgress() float64 {
	if sc := s.peek(); sc != nil {
		return sc.Progress()
	}
	return 0
}

// --- runtime adjustment -----------------------------------------------------

// SetProxy sets the HTTP or SOCKS5 proxy. Call it before Run.
func (s *SDKScanner) SetProxy(proxy string) {
	s.mu.Lock()
	s.opts.Proxy = proxy
	s.dirty = true
	timeout, retries := s.opts.Timeout, s.opts.Retries
	maxBody, reqLimit := s.opts.MaxRespBodySize, s.opts.ReqLimitPerTarget
	accept := s.opts.DefaultAccept
	s.mu.Unlock()

	// The HTTP client is process-wide, so the proxy takes effect immediately
	// as it did before.
	_ = retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:             proxy,
		Timeout:           timeout,
		Retries:           retries,
		MaxRespBodySize:   maxBody,
		ReqLimitPerTarget: reqLimit,
		DefaultAccept:     accept,
	})
}

// SetRateLimit sets the requests-per-second cap. Call it before Run.
func (s *SDKScanner) SetRateLimit(rateLimit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts.RateLimit = rateLimit
	s.dirty = true
}

// SetConcurrency sets the number of concurrent workers. Call it before Run.
func (s *SDKScanner) SetConcurrency(concurrency int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts.Concurrency = concurrency
	s.dirty = true
}

// --- out-of-band ------------------------------------------------------------

// IsOOBEnabled reports whether out-of-band detection is configured.
func (s *SDKScanner) IsOOBEnabled() bool {
	if s.opts == nil {
		return false
	}
	if s.opts.EnableOOB {
		return true
	}
	return s.opts.OOB != "" && (s.opts.OOBKey != "" || s.opts.OOBDomain != "")
}

// GetOOBStatus reports whether out-of-band detection is usable, together with
// a human-readable description. It probes the configured service.
func (s *SDKScanner) GetOOBStatus() (bool, string) {
	if s.opts == nil || !s.opts.EnableOOB {
		return false, "OOB未配置或未启用"
	}
	sc := s.peek()
	if sc == nil {
		return false, "扫描器未初始化"
	}
	return sc.OOBStatus()
}

// Scanner exposes the underlying [sdk.Scanner] for callers that want the
// current API's streams, diagnostics and typed results without giving up this
// facade. It is nil only before construction succeeds.
func (s *SDKScanner) Scanner() *sdk.Scanner { return s.peek() }

// printScanInfo writes the pre-scan summary. The original SDK always printed
// it, so it stays on unless SDKOptions.Silent is set.
func (s *SDKScanner) printScanInfo() {
	if s.opts != nil && s.opts.Silent {
		return
	}
	sc := s.peek()
	if sc == nil {
		return
	}
	info := sc.Info()

	fmt.Printf("\n========== 扫描信息 ==========\n")
	fmt.Printf("目标数量: %d\n", info.TotalTargets)
	fmt.Printf("POC数量: %d\n", info.TotalPocs)
	fmt.Printf("总扫描任务: %d\n", info.TotalScans)

	if len(info.Targets) <= 5 {
		fmt.Printf("扫描目标: %s\n", strings.Join(info.Targets, ", "))
	} else {
		fmt.Printf("目标过多，仅显示前3个: %s...\n", strings.Join(info.Targets[:3], ", "))
	}

	if s.opts.EnableOOB {
		if ok, status := info.OOBEnabled, info.OOBStatus; ok {
			fmt.Printf("OOB状态: ✓ %s\n", status)
		} else {
			fmt.Printf("OOB状态: ✗ %s\n", status)
		}
	} else {
		fmt.Printf("OOB状态: ✗ OOB未配置或未启用\n")
	}

	fmt.Printf("=============================\n")
}
