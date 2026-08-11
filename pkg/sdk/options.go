package sdk

import (
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
)

// Default values for Options. These constants are the single source of truth
// for the SDK defaults, so documentation and code cannot drift apart.
const (
	DefaultRateLimit        = 150
	DefaultConcurrency      = 25
	DefaultRetries          = 1
	DefaultTimeout          = 50 // seconds
	DefaultMaxHostError     = 3
	DefaultMaxRespBodySize  = 2 // MB
	DefaultBruteMaxRequests = 5000
	DefaultStreamBuffer     = 256
	DefaultOOBRateLimit     = 25
	DefaultOOBConcurrency   = 25

	// DefaultOOBPollInterval and DefaultOOBHitRetention mirror the CLI
	// defaults. Leaving them at zero would make the engine fall back to a
	// one-second poll, hitting the out-of-band provider twice as often as the
	// command line does.
	DefaultOOBPollInterval = 2  // seconds
	DefaultOOBHitRetention = 10 // minutes

	// Smart task-timeout estimation caps, mirroring the CLI defaults. They
	// bound the timeout the engine derives from a PoC's content.
	DefaultTaskTimeoutVisibleCapSec = 300 // plain HTTP PoCs
	DefaultTaskTimeoutNetCapSec     = 360 // tcp/udp/ssl PoCs
	DefaultTaskTimeoutGoCapSec      = 420 // go PoCs

	// Execution monitor defaults, mirroring the CLI.
	DefaultMonitorSlowThresholdSec = 30
	DefaultMonitorSlowLogLimit     = 20
	DefaultMonitorSummaryTop       = 10
)

// DefaultCheckpointSaveInterval matches the CLI's auto-save cadence.
const DefaultCheckpointSaveInterval = 10 * time.Second

// Execution monitor summary sort keys.
const (
	MonitorSummaryByMax = "max"
	MonitorSummaryByAvg = "avg"
)

// FingerprintFilterMode values.
const (
	FingerprintStrict        = "strict"
	FingerprintOpportunistic = "opportunistic"
)

// Options is the complete scanner configuration.
//
// Build it with NewOptions and the With* functions rather than filling the
// struct by hand: the option functions validate their input.
type Options struct {
	// --- targets ---

	Targets     []string
	TargetsFile string

	// Cyberspace sources targets from an internet-wide search engine instead
	// of, or in addition to, the explicit target list.
	Cyberspace CyberspaceOptions

	// TargetPreProbe probes every target's protocol and liveness in parallel
	// alongside the scan.
	TargetPreProbe bool

	// --- pocs ---

	// PocPaths accepts single files, directories (searched recursively) and
	// glob patterns such as "dir/*.yaml". Paths are merged with the built-in
	// PoCs unless PocPathsOnly is set.
	PocPaths []string
	// PocPathsOnly restricts the scan to PocPaths, hiding the built-in,
	// curated, my and local PoC sources.
	PocPathsOnly bool

	Search          string
	Severity        string
	ExcludePocs     []string
	ExcludePocsFile string

	// --- performance ---

	RateLimit         int
	Concurrency       int
	Retries           int
	Timeout           int
	MaxHostError      int
	MaxRespBodySize   int
	BruteMaxRequests  int
	ReqLimitPerTarget int
	AutoReqLimit      bool
	Polite            bool
	Balanced          bool
	Aggressive        bool
	Smart             bool

	// --- fingerprinting and probing ---

	DisableFingerprint    bool
	EnableWebProbe        bool
	FingerprintFilterMode string
	DefaultAccept         bool

	// StopOnFirstMatch stops the scan as soon as a vulnerability is found.
	StopOnFirstMatch bool

	// --- per-task timeout ---

	TaskTimeout TaskTimeoutOptions

	// --- execution monitor ---

	Monitor       ExecutionMonitorOptions
	EnableMonitor bool

	// --- network ---

	Proxy   string
	Headers []string

	// --- port pre-scan ---

	PortScan      PortScanOptions
	EnablePortSan bool

	// --- OOB ---

	OOB OOBOptions

	// --- output ---

	// IncludeRequestResponse controls whether results carry the raw request
	// and response messages. Enabled by default; disable it on large scans to
	// keep memory bounded.
	IncludeRequestResponse bool
	// MaxStoredResults caps how many results accumulate in memory. Zero means
	// unlimited. Exceeding the cap does not suppress handlers or streams.
	MaxStoredResults int
	// StreamBuffer is the capacity of each subscribed stream channel.
	StreamBuffer int
	// RedactedHeaders holds the lower-case header names masked in results.
	// Empty means no redaction.
	RedactedHeaders []string
	// Verbose prints a scan summary to stdout before the scan starts. The SDK
	// produces no console output otherwise.
	Verbose bool

	// --- notifications ---

	Dingtalk bool
	Wecom    bool

	// --- resume ---

	Checkpoint CheckpointOptions

	// --- curated poc source ---

	Curated CuratedOptions

	// --- handlers ---

	handlers handlers
}

// PortScanOptions configures the port pre-scan stage.
type PortScanOptions struct {
	// Ports accepts "top", "full", "all", "80,443" or "1-1024".
	Ports         string
	RateLimit     int
	TimeoutMs     int
	Retries       int
	SkipDiscovery bool
	ChunkSize     int
}

// CyberspaceEngine values accepted by CyberspaceOptions.Engine.
const (
	// CyberspaceZoomEye is currently the only implemented engine. Its API key
	// is read from the afrog configuration file (cyberspace.zoom_eyes).
	CyberspaceZoomEye = "zoomeye"
)

// CyberspaceOptions sources scan targets from an internet-wide search engine.
//
// Targets found this way are added to any explicitly configured ones, so a
// scan may be driven entirely by a search query.
type CyberspaceOptions struct {
	// Engine is currently only CyberspaceZoomEye.
	Engine string
	// Query is the engine's own search syntax, for example `app:"tomcat"`.
	Query string
	// Count caps how many results are turned into targets.
	Count int
}

// CheckpointOptions makes a scan resumable, the SDK equivalent of the CLI's
// -resume.
//
// Path is read when the scanner starts, so already-finished target/PoC pairs
// are skipped, and rewritten periodically while the scan runs. Resuming only
// works when the target and PoC sets are unchanged, because progress is keyed
// by PoC id and target.
//
// This is unrelated to Scanner.Resume, which lifts a Pause.
type CheckpointOptions struct {
	// Path is the checkpoint file. It is created on the first save.
	Path string
	// SaveInterval is how often the file is rewritten. Zero uses
	// DefaultCheckpointSaveInterval.
	SaveInterval time.Duration
}

// TaskTimeoutOptions bounds how long a single target+PoC task may run.
//
// This is separate from the per-request Timeout: a PoC with many rules can
// keep a worker busy far longer than any single request.
type TaskTimeoutOptions struct {
	// HardSec is a fixed ceiling in seconds. Zero disables it.
	HardSec int
	// Smart derives the ceiling from the PoC's content (rule count, sleeps,
	// brute force, payloads). When HardSec is also set, the larger of the two
	// wins, so HardSec acts as a floor rather than an override.
	Smart bool

	// The Cap fields bound the smart estimate per protocol family. They have
	// no effect unless Smart is set. Zero uses the defaults.
	VisibleCapSec int
	NetCapSec     int
	GoCapSec      int
}

// ExecutionMonitorOptions configures the PoC execution duration monitor, the
// SDK equivalent of the CLI's -pedm. It reports slow and stuck PoCs while the
// scan runs, and a slowest-PoC summary when it ends.
//
// Output is delivered to the handlers registered with WithMonitorHandler. The
// SDK never prints it.
type ExecutionMonitorOptions struct {
	// LogLimit reports the first N started tasks. Zero disables it.
	LogLimit int
	// SlowThresholdSec is the number of seconds after which a task counts as
	// slow. Zero disables slow reporting entirely, including the background
	// monitor goroutine.
	SlowThresholdSec int
	// SlowLogLimit caps how many completed slow tasks are reported. Zero
	// disables those reports; in-flight slow tasks are still reported.
	SlowLogLimit int
	// SummaryTop reports the N slowest PoCs when the scan ends. Zero disables
	// the summary.
	SummaryTop int
	// SummaryBy is MonitorSummaryByMax or MonitorSummaryByAvg.
	SummaryBy string
}

// OOBOptions configures out-of-band detection.
type OOBOptions struct {
	Enabled bool
	// Adapter is one of ceyeio, dnslogcn, alphalog, xray, revsuit.
	Adapter         string
	Key             string
	Domain          string
	ApiURL          string
	HttpURL         string
	RateLimit       int
	Concurrency     int
	FinalizeTimeout int
	// PollInterval is how often the out-of-band service is polled, in
	// seconds. Zero uses DefaultOOBPollInterval.
	PollInterval int
	// HitRetention is how long a recorded hit stays available, in minutes.
	// Zero uses DefaultOOBHitRetention.
	HitRetention int
}

// CuratedOptions configures the optional curated PoC source.
type CuratedOptions struct {
	Enabled     string
	Endpoint    string
	TimeoutSec  int
	ForceUpdate bool
}

// handlers holds the callbacks registered through the With*Handler options.
type handlers struct {
	result    []func(Result)
	rawResult []func(*result.Result)
	failure   []func(Failure)
	port      []func(PortEvent)
	host      []func(HostEvent)
	webProbe  []func(WebProbeEvent)
	progress  []func(PhaseProgress)
	scanInfo  []func(ScanInfo)
	monitor   []func(string)
}

// NewOptions returns Options populated with the SDK defaults.
func NewOptions() *Options {
	return &Options{
		RateLimit:              DefaultRateLimit,
		Concurrency:            DefaultConcurrency,
		Retries:                DefaultRetries,
		Timeout:                DefaultTimeout,
		MaxHostError:           DefaultMaxHostError,
		MaxRespBodySize:        DefaultMaxRespBodySize,
		BruteMaxRequests:       DefaultBruteMaxRequests,
		DefaultAccept:          true,
		FingerprintFilterMode:  FingerprintStrict,
		IncludeRequestResponse: true,
		StreamBuffer:           DefaultStreamBuffer,
		PortScan: PortScanOptions{
			Ports:     "top",
			ChunkSize: 1000,
		},
		TaskTimeout: TaskTimeoutOptions{
			VisibleCapSec: DefaultTaskTimeoutVisibleCapSec,
			NetCapSec:     DefaultTaskTimeoutNetCapSec,
			GoCapSec:      DefaultTaskTimeoutGoCapSec,
		},
		Monitor: ExecutionMonitorOptions{
			SlowThresholdSec: DefaultMonitorSlowThresholdSec,
			SlowLogLimit:     DefaultMonitorSlowLogLimit,
			SummaryTop:       DefaultMonitorSummaryTop,
			SummaryBy:        MonitorSummaryByMax,
		},
		OOB: OOBOptions{
			RateLimit:       DefaultOOBRateLimit,
			Concurrency:     DefaultOOBConcurrency,
			FinalizeTimeout: -1,
			PollInterval:    DefaultOOBPollInterval,
			HitRetention:    DefaultOOBHitRetention,
		},
	}
}

// validate normalises the options and reports invalid combinations.
func (o *Options) validate() error {
	// A cyberspace query is a target source in its own right, so it satisfies
	// the "must have targets" requirement on its own.
	if len(o.Targets) == 0 && strings.TrimSpace(o.TargetsFile) == "" && strings.TrimSpace(o.Cyberspace.Query) == "" {
		return ErrNoTargets
	}

	if strings.TrimSpace(o.Checkpoint.Path) != "" && o.Checkpoint.SaveInterval <= 0 {
		o.Checkpoint.SaveInterval = DefaultCheckpointSaveInterval
	}

	limitModes := 0
	for _, on := range []bool{o.ReqLimitPerTarget > 0, o.AutoReqLimit, o.Polite, o.Balanced, o.Aggressive} {
		if on {
			limitModes++
		}
	}
	if limitModes > 1 {
		return fmt.Errorf("%w: only one of ReqLimitPerTarget, AutoReqLimit, Polite, Balanced and Aggressive may be set", ErrInvalidOptions)
	}
	if o.ReqLimitPerTarget < 0 {
		return fmt.Errorf("%w: ReqLimitPerTarget must be >= 0", ErrInvalidOptions)
	}

	if o.MaxRespBodySize <= 0 {
		o.MaxRespBodySize = DefaultMaxRespBodySize
	}
	if o.StreamBuffer <= 0 {
		o.StreamBuffer = DefaultStreamBuffer
	}
	if o.OOB.RateLimit <= 0 {
		o.OOB.RateLimit = DefaultOOBRateLimit
	}
	if o.OOB.Concurrency <= 0 {
		o.OOB.Concurrency = DefaultOOBConcurrency
	}
	if o.OOB.PollInterval <= 0 {
		o.OOB.PollInterval = DefaultOOBPollInterval
	}
	if o.OOB.HitRetention <= 0 {
		o.OOB.HitRetention = DefaultOOBHitRetention
	}

	switch strings.ToLower(strings.TrimSpace(o.FingerprintFilterMode)) {
	case FingerprintOpportunistic:
		o.FingerprintFilterMode = FingerprintOpportunistic
	default:
		o.FingerprintFilterMode = FingerprintStrict
	}

	if o.OOB.Enabled && strings.TrimSpace(o.OOB.Adapter) == "" {
		return fmt.Errorf("%w: OOB adapter must not be empty when OOB is enabled", ErrInvalidOptions)
	}

	// A zero cap would silently collapse the smart estimate to a 60 second
	// ceiling deep inside the engine, so fill the documented default instead.
	if o.TaskTimeout.VisibleCapSec <= 0 {
		o.TaskTimeout.VisibleCapSec = DefaultTaskTimeoutVisibleCapSec
	}
	if o.TaskTimeout.NetCapSec <= 0 {
		o.TaskTimeout.NetCapSec = DefaultTaskTimeoutNetCapSec
	}
	if o.TaskTimeout.GoCapSec <= 0 {
		o.TaskTimeout.GoCapSec = DefaultTaskTimeoutGoCapSec
	}

	switch strings.ToLower(strings.TrimSpace(o.Monitor.SummaryBy)) {
	case MonitorSummaryByAvg:
		o.Monitor.SummaryBy = MonitorSummaryByAvg
	default:
		o.Monitor.SummaryBy = MonitorSummaryByMax
	}

	o.applyRequestLimitPreset()
	return nil
}

// applyRequestLimitPreset derives ReqLimitPerTarget from the selected preset.
func (o *Options) applyRequestLimitPreset() {
	if o.ReqLimitPerTarget != 0 {
		return
	}
	switch {
	case o.Polite:
		o.ReqLimitPerTarget = 5
	case o.Balanced:
		o.ReqLimitPerTarget = 15
	case o.Aggressive:
		o.ReqLimitPerTarget = 50
	case o.AutoReqLimit:
		rate := o.RateLimit
		if rate <= 0 {
			rate = DefaultRateLimit
		}
		limit := rate / 10
		if limit < 5 {
			limit = 5
		}
		if limit > 15 {
			limit = 15
		}
		switch con := o.Concurrency; {
		case con >= 100 && limit > 8:
			limit = 8
		case con >= 50 && limit > 12:
			limit = 12
		}
		o.ReqLimitPerTarget = limit
	}
}

// pocInputs returns every explicitly configured PoC path.
func (o *Options) pocInputs() []string {
	out := make([]string, 0, len(o.PocPaths))
	for _, p := range o.PocPaths {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Option configures a Scanner.
//
// Functional options can be applied incrementally, validate their own input,
// and let new options be added without breaking existing callers.
type Option func(*Options) error

// WithOptions replaces the whole configuration. Later options still apply on
// top of it, which makes it a useful escape hatch for callers that keep their
// own Options value.
func WithOptions(opts *Options) Option {
	return func(o *Options) error {
		if opts == nil {
			return fmt.Errorf("%w: options must not be nil", ErrInvalidOptions)
		}
		handlers := o.handlers
		*o = *opts
		o.handlers = handlers
		return nil
	}
}

// --- targets ---

// WithTargets appends scan targets.
func WithTargets(targets ...string) Option {
	return func(o *Options) error {
		o.Targets = append(o.Targets, targets...)
		return nil
	}
}

// WithTargetsFile reads targets from a file, one per line.
func WithTargetsFile(path string) Option {
	return func(o *Options) error {
		o.TargetsFile = path
		return nil
	}
}

// WithCyberspace sources targets from an internet-wide search engine, so a
// scan can be driven by a query instead of an explicit target list.
//
// The engine's API key must be present in the afrog configuration file.
func WithCyberspace(cfg CyberspaceOptions) Option {
	return func(o *Options) error {
		engine := strings.ToLower(strings.TrimSpace(cfg.Engine))
		if engine == "" {
			return fmt.Errorf("%w: cyberspace engine must not be empty", ErrInvalidOptions)
		}
		if engine != CyberspaceZoomEye {
			return fmt.Errorf("%w: unsupported cyberspace engine %q, only %q is implemented",
				ErrInvalidOptions, cfg.Engine, CyberspaceZoomEye)
		}
		if strings.TrimSpace(cfg.Query) == "" {
			return fmt.Errorf("%w: cyberspace query must not be empty", ErrInvalidOptions)
		}
		if cfg.Count < 0 {
			return fmt.Errorf("%w: cyberspace count must be >= 0, got %d", ErrInvalidOptions, cfg.Count)
		}
		cfg.Engine = engine
		o.Cyberspace = cfg
		return nil
	}
}

// WithTargetPreProbe probes each target's protocol and liveness in parallel
// with the scan, blacklisting hosts that exceed MaxHostError.
//
// This is the CLI's -mt flag. Despite the flag's name it does not watch the
// targets file for changes.
func WithTargetPreProbe() Option {
	return func(o *Options) error { o.TargetPreProbe = true; return nil }
}

// --- resume ---

// WithCheckpoint makes the scan resumable by recording finished target/PoC
// pairs to a file and skipping them on a later run.
//
// See [CheckpointOptions] for the constraints. This is unrelated to
// Scanner.Resume, which lifts a Pause.
func WithCheckpoint(cfg CheckpointOptions) Option {
	return func(o *Options) error {
		if strings.TrimSpace(cfg.Path) == "" {
			return fmt.Errorf("%w: checkpoint path must not be empty", ErrInvalidOptions)
		}
		if cfg.SaveInterval < 0 {
			return fmt.Errorf("%w: checkpoint save interval must be >= 0, got %v", ErrInvalidOptions, cfg.SaveInterval)
		}
		if cfg.SaveInterval == 0 {
			cfg.SaveInterval = DefaultCheckpointSaveInterval
		}
		o.Checkpoint = cfg
		return nil
	}
}

// --- pocs ---

// WithPocPaths appends PoC inputs. Each entry may be a single file, a
// directory searched recursively, or a glob pattern such as "dir/*.yaml".
func WithPocPaths(paths ...string) Option {
	return func(o *Options) error {
		o.PocPaths = append(o.PocPaths, paths...)
		return nil
	}
}

// WithPocPathsOnly restricts the scan to the explicitly configured PoCs,
// hiding the built-in and user-directory sources.
func WithPocPathsOnly() Option {
	return func(o *Options) error {
		o.PocPathsOnly = true
		return nil
	}
}

// WithSearch filters PoCs by keyword, for example "tomcat,phpinfo".
func WithSearch(keyword string) Option {
	return func(o *Options) error {
		o.Search = keyword
		return nil
	}
}

// WithSeverity filters PoCs by severity, for example "high,critical".
func WithSeverity(severity string) Option {
	return func(o *Options) error {
		o.Severity = severity
		return nil
	}
}

// WithExcludePocs excludes PoCs by id.
func WithExcludePocs(pocs ...string) Option {
	return func(o *Options) error {
		o.ExcludePocs = append(o.ExcludePocs, pocs...)
		return nil
	}
}

// WithExcludePocsFile excludes the PoCs listed in a file.
func WithExcludePocsFile(path string) Option {
	return func(o *Options) error {
		o.ExcludePocsFile = path
		return nil
	}
}

// --- performance ---

// WithConcurrency sets the number of concurrent scan workers.
func WithConcurrency(n int) Option {
	return func(o *Options) error {
		if n <= 0 {
			return fmt.Errorf("%w: concurrency must be > 0, got %d", ErrInvalidOptions, n)
		}
		o.Concurrency = n
		return nil
	}
}

// WithRateLimit sets the maximum number of requests per second.
func WithRateLimit(n int) Option {
	return func(o *Options) error {
		if n <= 0 {
			return fmt.Errorf("%w: rate limit must be > 0, got %d", ErrInvalidOptions, n)
		}
		o.RateLimit = n
		return nil
	}
}

// WithTimeout sets the per-request timeout in seconds.
func WithTimeout(seconds int) Option {
	return func(o *Options) error {
		if seconds <= 0 {
			return fmt.Errorf("%w: timeout must be > 0, got %d", ErrInvalidOptions, seconds)
		}
		o.Timeout = seconds
		return nil
	}
}

// WithRetries sets how many times a failed request is retried.
func WithRetries(n int) Option {
	return func(o *Options) error {
		if n < 0 {
			return fmt.Errorf("%w: retries must be >= 0, got %d", ErrInvalidOptions, n)
		}
		o.Retries = n
		return nil
	}
}

// WithMaxHostError sets how many errors a host may produce before it is
// skipped.
func WithMaxHostError(n int) Option {
	return func(o *Options) error {
		if n < 0 {
			return fmt.Errorf("%w: max host error must be >= 0, got %d", ErrInvalidOptions, n)
		}
		o.MaxHostError = n
		return nil
	}
}

// WithMaxRespBodySize sets the response body read limit in megabytes.
// Responses beyond the limit are truncated and Exchange.BodyTruncated is set.
func WithMaxRespBodySize(mb int) Option {
	return func(o *Options) error {
		if mb <= 0 {
			return fmt.Errorf("%w: max response body size must be > 0, got %d", ErrInvalidOptions, mb)
		}
		o.MaxRespBodySize = mb
		return nil
	}
}

// WithRequestLimitPerTarget caps concurrent requests per target.
func WithRequestLimitPerTarget(n int) Option {
	return func(o *Options) error {
		if n < 0 {
			return fmt.Errorf("%w: request limit per target must be >= 0, got %d", ErrInvalidOptions, n)
		}
		o.ReqLimitPerTarget = n
		return nil
	}
}

// WithPolite applies the conservative per-target request preset.
func WithPolite() Option {
	return func(o *Options) error { o.Polite = true; return nil }
}

// WithBalanced applies the balanced per-target request preset.
func WithBalanced() Option {
	return func(o *Options) error { o.Balanced = true; return nil }
}

// WithAggressive applies the aggressive per-target request preset.
func WithAggressive() Option {
	return func(o *Options) error { o.Aggressive = true; return nil }
}

// WithAutoRequestLimit derives the per-target request limit from the rate
// limit and concurrency.
func WithAutoRequestLimit() Option {
	return func(o *Options) error { o.AutoReqLimit = true; return nil }
}

// WithSmartConcurrency adjusts concurrency based on the target count.
func WithSmartConcurrency() Option {
	return func(o *Options) error { o.Smart = true; return nil }
}

// WithStopOnFirstMatch stops the scan as soon as a vulnerability is found.
func WithStopOnFirstMatch() Option {
	return func(o *Options) error { o.StopOnFirstMatch = true; return nil }
}

// --- per-task timeout ---

// WithTaskTimeout bounds how long a single target+PoC task may run, so that
// one pathological PoC cannot hold a worker indefinitely.
//
// Zero-valued cap fields keep the current defaults.
func WithTaskTimeout(cfg TaskTimeoutOptions) Option {
	return func(o *Options) error {
		if cfg.HardSec < 0 {
			return fmt.Errorf("%w: task hard timeout must be >= 0, got %d", ErrInvalidOptions, cfg.HardSec)
		}
		for name, v := range map[string]int{
			"VisibleCapSec": cfg.VisibleCapSec,
			"NetCapSec":     cfg.NetCapSec,
			"GoCapSec":      cfg.GoCapSec,
		} {
			if v < 0 {
				return fmt.Errorf("%w: task timeout %s must be >= 0, got %d", ErrInvalidOptions, name, v)
			}
		}
		if cfg.VisibleCapSec <= 0 {
			cfg.VisibleCapSec = o.TaskTimeout.VisibleCapSec
		}
		if cfg.NetCapSec <= 0 {
			cfg.NetCapSec = o.TaskTimeout.NetCapSec
		}
		if cfg.GoCapSec <= 0 {
			cfg.GoCapSec = o.TaskTimeout.GoCapSec
		}
		o.TaskTimeout = cfg
		return nil
	}
}

// --- execution monitor ---

// WithExecutionMonitor enables the PoC execution duration monitor, which
// surfaces slow and stuck PoCs during the scan and a slowest-PoC summary at
// the end.
//
// Register at least one WithMonitorHandler to receive the reports; the SDK
// never writes them to the console. Zero-valued fields keep the defaults.
func WithExecutionMonitor(cfg ExecutionMonitorOptions) Option {
	return func(o *Options) error {
		for name, v := range map[string]int{
			"LogLimit":         cfg.LogLimit,
			"SlowThresholdSec": cfg.SlowThresholdSec,
			"SlowLogLimit":     cfg.SlowLogLimit,
			"SummaryTop":       cfg.SummaryTop,
		} {
			if v < 0 {
				return fmt.Errorf("%w: monitor %s must be >= 0, got %d", ErrInvalidOptions, name, v)
			}
		}
		if strings.TrimSpace(cfg.SummaryBy) == "" {
			cfg.SummaryBy = o.Monitor.SummaryBy
		}
		switch strings.ToLower(strings.TrimSpace(cfg.SummaryBy)) {
		case MonitorSummaryByMax, MonitorSummaryByAvg:
		default:
			return fmt.Errorf("%w: unknown monitor summary key %q", ErrInvalidOptions, cfg.SummaryBy)
		}
		if cfg.SlowThresholdSec == 0 {
			cfg.SlowThresholdSec = o.Monitor.SlowThresholdSec
		}
		if cfg.SlowLogLimit == 0 {
			cfg.SlowLogLimit = o.Monitor.SlowLogLimit
		}
		if cfg.SummaryTop == 0 {
			cfg.SummaryTop = o.Monitor.SummaryTop
		}
		o.Monitor = cfg
		o.EnableMonitor = true
		return nil
	}
}

// --- fingerprinting ---

// WithFingerprintDisabled skips the fingerprinting stage.
func WithFingerprintDisabled() Option {
	return func(o *Options) error { o.DisableFingerprint = true; return nil }
}

// WithFingerprintFilterMode selects how fingerprint gating filters PoCs.
// Valid values are FingerprintStrict and FingerprintOpportunistic.
func WithFingerprintFilterMode(mode string) Option {
	return func(o *Options) error {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case FingerprintStrict, FingerprintOpportunistic:
			o.FingerprintFilterMode = strings.ToLower(strings.TrimSpace(mode))
			return nil
		default:
			return fmt.Errorf("%w: unknown fingerprint filter mode %q", ErrInvalidOptions, mode)
		}
	}
}

// WithWebProbe enables the web probing stage.
func WithWebProbe() Option {
	return func(o *Options) error { o.EnableWebProbe = true; return nil }
}

// --- network ---

// WithProxy sets an HTTP or SOCKS5 proxy.
func WithProxy(proxy string) Option {
	return func(o *Options) error {
		o.Proxy = proxy
		return nil
	}
}

// WithHeaders appends custom request headers in "Name: value" form.
func WithHeaders(headers ...string) Option {
	return func(o *Options) error {
		for _, h := range headers {
			if !strings.Contains(h, ":") {
				return fmt.Errorf("%w: header %q must be in \"Name: value\" form", ErrInvalidOptions, h)
			}
		}
		o.Headers = append(o.Headers, headers...)
		return nil
	}
}

// --- port pre-scan ---

// WithPortScan runs a port pre-scan before the PoC scan. Discovered open ports
// are appended to the target set as host:port.
func WithPortScan(cfg PortScanOptions) Option {
	return func(o *Options) error {
		if cfg.Ports == "" {
			cfg.Ports = o.PortScan.Ports
		}
		if cfg.ChunkSize <= 0 {
			cfg.ChunkSize = o.PortScan.ChunkSize
		}
		o.EnablePortSan = true
		o.PortScan = cfg
		return nil
	}
}

// --- OOB ---

// WithOOB enables out-of-band detection.
func WithOOB(cfg OOBOptions) Option {
	return func(o *Options) error {
		if strings.TrimSpace(cfg.Adapter) == "" {
			return fmt.Errorf("%w: OOB adapter must not be empty", ErrInvalidOptions)
		}
		if cfg.RateLimit <= 0 {
			cfg.RateLimit = o.OOB.RateLimit
		}
		if cfg.Concurrency <= 0 {
			cfg.Concurrency = o.OOB.Concurrency
		}
		if cfg.FinalizeTimeout == 0 {
			cfg.FinalizeTimeout = o.OOB.FinalizeTimeout
		}
		if cfg.PollInterval <= 0 {
			cfg.PollInterval = o.OOB.PollInterval
		}
		if cfg.HitRetention <= 0 {
			cfg.HitRetention = o.OOB.HitRetention
		}
		cfg.Enabled = true
		o.OOB = cfg
		return nil
	}
}

// --- curated ---

// WithCurated configures the optional curated PoC source.
func WithCurated(cfg CuratedOptions) Option {
	return func(o *Options) error {
		o.Curated = cfg
		return nil
	}
}

// --- notifications ---

// WithDingtalk enables DingTalk webhook notifications. The token must be
// present in the afrog configuration file.
func WithDingtalk() Option {
	return func(o *Options) error { o.Dingtalk = true; return nil }
}

// WithWecom enables WeCom webhook notifications. The token must be present in
// the afrog configuration file.
func WithWecom() Option {
	return func(o *Options) error { o.Wecom = true; return nil }
}

// --- output ---

// WithRequestResponse controls whether results carry raw request and response
// messages. Enabled by default.
func WithRequestResponse(include bool) Option {
	return func(o *Options) error {
		o.IncludeRequestResponse = include
		return nil
	}
}

// WithMaxStoredResults caps how many results accumulate in memory. Zero means
// unlimited. Handlers and streams still receive every result.
func WithMaxStoredResults(n int) Option {
	return func(o *Options) error {
		if n < 0 {
			return fmt.Errorf("%w: max stored results must be >= 0, got %d", ErrInvalidOptions, n)
		}
		o.MaxStoredResults = n
		return nil
	}
}

// WithStreamBuffer sets the capacity of each subscribed stream channel.
func WithStreamBuffer(n int) Option {
	return func(o *Options) error {
		if n <= 0 {
			return fmt.Errorf("%w: stream buffer must be > 0, got %d", ErrInvalidOptions, n)
		}
		o.StreamBuffer = n
		return nil
	}
}

// WithVerbose prints a scan summary to stdout before the scan starts.
func WithVerbose() Option {
	return func(o *Options) error { o.Verbose = true; return nil }
}

// WithRedactedHeaders masks the given headers in the raw request and response
// of every [Exchange], as well as in the structured header maps.
//
// Calling it with no arguments uses [DefaultRedactedHeaders], which covers the
// usual credential-bearing headers such as Authorization and Cookie.
//
// Redaction is opt-in because the raw messages are the point of Exchange, and
// masking them by default would quietly weaken the SDK's main debugging aid.
// Enable it whenever results are logged, persisted or returned over an API,
// especially when scanning authenticated targets or using WithHeaders to send
// credentials.
func WithRedactedHeaders(names ...string) Option {
	return func(o *Options) error {
		if len(names) == 0 {
			names = DefaultRedactedHeaders
		}
		for _, n := range names {
			if v := strings.ToLower(strings.TrimSpace(n)); v != "" {
				o.RedactedHeaders = append(o.RedactedHeaders, v)
			}
		}
		return nil
	}
}

// --- handlers ---

// WithResultHandler registers a result callback. It may be used several times.
//
// Handlers are invoked concurrently from scan workers, so implementations must
// synchronise their own shared state.
func WithResultHandler(fn func(Result)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.result = append(o.handlers.result, fn)
		}
		return nil
	}
}

// WithRawResultHandler registers a callback that receives the engine's own
// result type.
//
// This is an escape hatch for advanced integrations that need fields the
// stable [Result] view does not expose, such as persisting the full internal
// structure. Unlike Result, the shape of result.Result is an internal detail
// and may change between releases. Prefer WithResultHandler.
//
// The value passed to the handler is a snapshot owned by the caller.
func WithRawResultHandler(fn func(*result.Result)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.rawResult = append(o.handlers.rawResult, fn)
		}
		return nil
	}
}

// WithFailureHandler registers a callback for PoC execution failures such as
// request errors, expression errors and recovered panics.
func WithFailureHandler(fn func(Failure)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.failure = append(o.handlers.failure, fn)
		}
		return nil
	}
}

// WithPortHandler registers a callback for open ports found during the port
// pre-scan.
func WithPortHandler(fn func(PortEvent)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.port = append(o.handlers.port, fn)
		}
		return nil
	}
}

// WithHostHandler registers a callback for hosts found during discovery.
func WithHostHandler(fn func(HostEvent)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.host = append(o.handlers.host, fn)
		}
		return nil
	}
}

// WithWebProbeHandler registers a callback for probed web services.
func WithWebProbeHandler(fn func(WebProbeEvent)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.webProbe = append(o.handlers.webProbe, fn)
		}
		return nil
	}
}

// WithProgressHandler registers a callback for phase progress updates.
func WithProgressHandler(fn func(PhaseProgress)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.progress = append(o.handlers.progress, fn)
		}
		return nil
	}
}

// WithScanInfoHandler registers a callback for scan summary updates.
func WithScanInfoHandler(fn func(ScanInfo)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.scanInfo = append(o.handlers.scanInfo, fn)
		}
		return nil
	}
}

// WithMonitorHandler registers a callback for execution monitor reports. Each
// call receives one preformatted line.
//
// Without a handler the monitor still runs but its output goes nowhere, which
// is why WithExecutionMonitor is only useful together with this option.
func WithMonitorHandler(fn func(line string)) Option {
	return func(o *Options) error {
		if fn != nil {
			o.handlers.monitor = append(o.handlers.monitor, fn)
		}
		return nil
	}
}
