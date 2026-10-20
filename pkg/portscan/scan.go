package portscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// Scanner is the main entry point for port scanning
type Scanner struct {
	options           *Options
	pool              *ants.PoolWithFunc
	mu                sync.Mutex
	consecutiveErrors int32
	currentProgress   uint64
	resultsCount      uint64
	adaptiveDelay     int32 // Current delay in milliseconds
	hostStats         sync.Map
	hostSems          sync.Map // host -> chan struct{} (per-target concurrency gate)
	scanPortTotal     uint64
	scanStageMajor    uint32
}

// NewScanner creates a new scanner instance
func NewScanner(opt *Options) (*Scanner, error) {
	if opt == nil {
		opt = DefaultOptions()
	}

	scanner := &Scanner{
		options: opt,
	}

	return scanner, nil
}

// Scan starts the scanning process
func (s *Scanner) Scan(ctx context.Context) error {
	normalizedPorts := strings.ToLower(strings.TrimSpace(s.options.Ports))
	stageMajor := normalizedPorts == "full" || normalizedPorts == "all"
	if stageMajor {
		atomic.StoreUint32(&s.scanStageMajor, 1)
	} else {
		atomic.StoreUint32(&s.scanStageMajor, 0)
	}

	type stagePlan struct {
		label     string
		ports     []int
		s4Chunk   int
		s4Chunks  int
		isS4Chunk bool
	}

	var (
		portIter    *PortIterator
		stagePlans  []stagePlan
		portTotal   int
		stageCursor atomic.Value
	)

	if stageMajor {
		s1, s2, s3Parts, s4 := buildStagePortsWithS3Parts(nil)
		stagePlans = append(stagePlans, stagePlan{label: "S1", ports: s1})
		stagePlans = append(stagePlans, stagePlan{label: "S2", ports: s2})
		for i, part := range s3Parts {
			stagePlans = append(stagePlans, stagePlan{label: fmt.Sprintf("S3-%d", i+1), ports: part})
		}

		s4Chunks := ChunkPorts(s4, s.options.S4ChunkSize)
		for i, chunk := range s4Chunks {
			stagePlans = append(stagePlans, stagePlan{
				label:     "S4",
				ports:     chunk,
				s4Chunk:   i + 1,
				s4Chunks:  len(s4Chunks),
				isS4Chunk: true,
			})
		}
		s3Total := 0
		for _, p := range s3Parts {
			s3Total += len(p)
		}
		portTotal = len(s1) + len(s2) + s3Total + len(s4)
	} else {
		// Parse ports
		var err error
		portIter, err = NewPortIterator(s.options.Ports)
		if err != nil {
			return err
		}
		portTotal = portIter.Total()
	}
	atomic.StoreUint64(&s.scanPortTotal, uint64(portTotal))

	// Parse hosts (placeholder for now, assuming options.Targets are just IPs)
	hostIter := NewHostIterator(s.options.Targets)

	// Pre-scan Host Discovery. Discovery is only worthwhile for larger target
	// sets (CIDR blocks, big ranges). A small explicit host/IP list is treated as
	// alive (nmap -Pn semantics) so that live hosts whose ICMP/TCP discovery
	// probes are filtered are never dropped. -Pn forces skipping discovery even
	// for large target sets.
	if hostIter.Total() > discoveryMinHosts && !s.options.SkipDiscovery {
		origHosts := hostIter.GetHosts()
		discCtx, discStop := signal.NotifyContext(ctx, os.Interrupt)
		discStart := time.Now()
		if !s.options.Quiet {
			gologger.Info().Msgf("%-9s | %-9s | targets=%d method=%s", utils.StageHostDiscovery, "started", len(origHosts), s.options.DiscoveryMethod)
		}
		aliveHosts, derr := DiscoverAliveHosts(discCtx, s.options, origHosts)
		if derr != nil {
			return derr
		}
		if discCtx.Err() != nil {
			if !s.options.Quiet {
				gologger.Warning().Msgf("%-9s | %-9s | alive=%d", utils.StageHostDiscovery, "interrupted", len(aliveHosts))
			}
		}
		discStop()
		if !s.options.Quiet {
			gologger.Info().Msgf("%-9s | %-9s | alive=%d/%d duration=%s", utils.StageHostDiscovery, "completed", len(aliveHosts), len(origHosts), time.Since(discStart).Truncate(time.Second))
		}
		hostIter = NewHostIterator(aliveHosts)
	} else if s.options.OnProgress != nil {
		s.options.OnProgress("host_discovery", "skipped", 0, 0, 0)
	}

	// Shuffle hosts to avoid sequential scanning detection
	hostIter.Shuffle()
	hosts := hostIter.GetHosts()

	total := hostIter.Total() * portTotal
	startTime := time.Now()

	if !s.options.Quiet {
		if !s.options.LiveStats {
			if isBuiltinPortsSpec(s.options.Ports) {
				gologger.Info().Msgf("%-9s | %-9s | port-ranking=%s", utils.StagePortScan, "ports", getPortRankingVersion())
			}
			gologger.Info().Msgf("%-9s | %-9s | hosts=%d ports=%s", utils.StagePortScan, "started", hostIter.Total(), s.options.Ports)
		}
	}

	printEnabled := (s.options.Debug || s.options.LiveStats) && !s.options.Quiet && total > 0
	callbackEnabled := s.options.OnProgress != nil && total > 0
	var progressDone chan struct{}
	var lastPercent int32 = -1
	var lastCallbackPercent int32 = -1
	renderProgress := func(final bool) {
		curr := atomic.LoadUint64(&s.currentProgress)
		if int(curr) > total {
			curr = uint64(total)
		}
		percent := 0
		if total > 0 {
			percent = int(curr) * 100 / total
		}
		if final {
			percent = 100
			curr = uint64(total)
		}
		if callbackEnabled {
			if final || int32(percent) != atomic.LoadInt32(&lastCallbackPercent) {
				atomic.StoreInt32(&lastCallbackPercent, int32(percent))
				status := "running"
				if final {
					status = "completed"
				}
				s.options.OnProgress("portscan", status, int(curr), total, percent)
			}
		}
		if !printEnabled {
			return
		}
		if !final {
			if int32(percent) == atomic.LoadInt32(&lastPercent) {
				return
			}
			atomic.StoreInt32(&lastPercent, int32(percent))
		}
		elapsed := strings.Split(time.Since(startTime).String(), ".")[0] + "s"
		suffix := ""
		if s.options.LiveStats {
			if v := stageCursor.Load(); v != nil {
				if cur, ok := v.(string); ok && cur != "" {
					suffix = " " + cur
				}
			}
		}
		fmt.Fprint(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\r[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(percent, 0), percent, curr, total, elapsed, suffix)
	}

	if printEnabled || callbackEnabled {
		progressDone = make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-progressDone:
					return
				case <-ticker.C:
					renderProgress(false)
				}
			}
		}()
	}

	var wg sync.WaitGroup

	// Use ants for goroutine pooling
	scanCtx, scanStop := signal.NotifyContext(ctx, os.Interrupt)
	pool, err := ants.NewPoolWithFunc(s.options.RateLimit, func(i interface{}) {
		defer wg.Done()
		task := i.(scanTask)

		// Check context
		select {
		case <-scanCtx.Done():
			return
		default:
		}

		// Per-target concurrency gate: bound the probes in flight against a
		// single host so the global pool is not concentrated on one target.
		release := s.acquireHostSlot(scanCtx, task.host)
		if release == nil {
			return
		}
		defer release()

		s.scanTarget(scanCtx, task.host, task.port)

		atomic.AddUint64(&s.currentProgress, 1)
	})
	if err != nil {
		return err
	}
	defer pool.Release()

	// Iterate and submit tasks
	if stageMajor {
	StageLoop:
		for _, st := range stagePlans {
			select {
			case <-scanCtx.Done():
				break StageLoop
			default:
			}

			if st.isS4Chunk {
				stageCursor.Store(fmt.Sprintf("stage=%s chunk=%d/%d", st.label, st.s4Chunk, st.s4Chunks))
			} else {
				stageCursor.Store(fmt.Sprintf("stage=%s", st.label))
			}

		SubmitLoop:
			for _, host := range hosts {
				select {
				case <-scanCtx.Done():
					break SubmitLoop
				default:
				}

				for _, port := range st.ports {
					select {
					case <-scanCtx.Done():
						break SubmitLoop
					default:
					}

					if s.isHostSuspicious(host) {
						break
					}

					s.maybeAdaptiveDelay()
					wg.Add(1)
					err := pool.Invoke(scanTask{host: host, port: port})
					if err != nil {
						wg.Done()
						time.Sleep(10 * time.Millisecond)
					}
				}
			}

			wg.Wait()
			if scanCtx.Err() != nil {
				break StageLoop
			}
		}
	} else {
		for _, host := range hosts {
			select {
			case <-scanCtx.Done():
				break
			default:
			}

			portIter.Reset()
			for {
				select {
				case <-scanCtx.Done():
					break
				default:
				}

				if s.isHostSuspicious(host) {
					break
				}

				s.maybeAdaptiveDelay()
				port, ok := portIter.Next()
				if !ok {
					break
				}

				wg.Add(1)
				err := pool.Invoke(scanTask{host: host, port: port})
				if err != nil {
					wg.Done()
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
	}

	wg.Wait()

	if scanCtx.Err() != nil && !s.options.Quiet {
		if printEnabled {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		if v := stageCursor.Load(); v != nil {
			if cur, ok := v.(string); ok && cur != "" {
				gologger.Warning().Msgf("%-9s | %-9s | %s partial results", utils.StagePortScan, "interrupted", cur)
			} else {
				gologger.Warning().Msgf("%-9s | %-9s | partial results", utils.StagePortScan, "interrupted")
			}
		} else {
			gologger.Warning().Msgf("%-9s | %-9s | partial results", utils.StagePortScan, "interrupted")
		}
	}
	scanStop()

	if progressDone != nil {
		close(progressDone)
		progressDone = nil
	}
	if printEnabled || callbackEnabled {
		renderProgress(true)
		if printEnabled {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
	}
	if !s.options.Quiet {
		if !s.options.LiveStats {
			gologger.Info().Msgf("%-9s | %-9s | hosts=%d tasks=%d open=%d duration=%s",
				utils.StagePortScan,
				"completed",
				hostIter.Total(),
				total,
				atomic.LoadUint64(&s.resultsCount),
				time.Since(startTime).Truncate(time.Second),
			)
		}
	}

	return nil
}

// discoveryMinHosts is the minimum number of expanded targets before a host
// discovery phase is performed. Smaller target sets are scanned directly so
// that live hosts whose ICMP/TCP discovery probes are filtered are never
// silently dropped.
const discoveryMinHosts = 8

type scanTask struct {
	host string
	port int
}

func (s *Scanner) isHostSuspicious(host string) bool {
	stAny, ok := s.hostStats.Load(host)
	if !ok {
		return false
	}
	st := stAny.(*hostScanStat)
	return atomic.LoadUint32(&st.mode) == hostModeSuspicious
}

type hostScanStat struct {
	scanned    uint64
	open       uint64
	timeouts   uint64
	srttNs     int64 // smoothed round-trip time in nanoseconds (0 = unknown)
	mode       uint32
	verifying  uint32
	warned     uint32
	mu         sync.Mutex
	verified   map[int]struct{}
	discovered map[int]struct{}
	pending    []int
}

func newHostScanStat() *hostScanStat {
	return &hostScanStat{
		verified:   make(map[int]struct{}),
		discovered: make(map[int]struct{}),
		pending:    make([]int, 0, 256),
	}
}

const (
	hostModeUndecided  uint32 = 0
	hostModeNormal     uint32 = 1
	hostModeSuspicious uint32 = 2
	hostModeDeciding   uint32 = 3
)

func (s *Scanner) maybeAdaptiveDelay() {
	errCount := atomic.LoadInt32(&s.consecutiveErrors)
	currentDelay := atomic.LoadInt32(&s.adaptiveDelay)

	if errCount > 20 {
		newDelay := currentDelay + 100
		if newDelay > 1000 {
			newDelay = 1000
		}
		atomic.StoreInt32(&s.adaptiveDelay, newDelay)

		if s.options.Debug && errCount%10 == 0 {
			gologger.Warning().Msgf("High error rate (%d). Increasing delay to %dms", errCount, newDelay)
		}
		time.Sleep(time.Duration(newDelay) * time.Millisecond)
		return
	}

	if errCount > 5 {
		atomic.CompareAndSwapInt32(&s.adaptiveDelay, 0, 10)
		time.Sleep(time.Duration(atomic.LoadInt32(&s.adaptiveDelay)) * time.Millisecond)
		return
	}

	if currentDelay > 0 && atomic.LoadUint64(&s.currentProgress)%50 == 0 {
		atomic.AddInt32(&s.adaptiveDelay, -10)
		if atomic.LoadInt32(&s.adaptiveDelay) < 0 {
			atomic.StoreInt32(&s.adaptiveDelay, 0)
		}
	}
}

// acquireHostSlot bounds how many probes are in flight against a single
// target. Concentrating the whole global pool on one host can trip its
// SYN-flood protection and make live ports look closed. It returns a release
// function, or nil if the context was cancelled before a slot was free.
func (s *Scanner) acquireHostSlot(ctx context.Context, host string) func() {
	limit := s.options.MaxHostConcurrency
	if limit <= 0 {
		return func() {}
	}
	v, ok := s.hostSems.Load(host)
	if !ok {
		actual, _ := s.hostSems.LoadOrStore(host, make(chan struct{}, limit))
		v = actual
	}
	sem := v.(chan struct{})
	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
		return nil
	}
}

// attemptTimeoutFor scales the connect timeout with the round trip time
// measured for this host. A fast host does not need a full second of patience,
// so shortening the first attempt speeds up large scans; a slow host keeps
// enough headroom that its open ports are not mistaken for closed. Retries
// always use the full user budget (see checkPortOpen).
func (s *Scanner) attemptTimeoutFor(st *hostScanStat, base time.Duration) time.Duration {
	if !s.options.AdaptiveTimeout {
		return base
	}
	srtt := atomic.LoadInt64(&st.srttNs)
	if srtt <= 0 {
		return base
	}
	t := time.Duration(srtt) * 4
	const floor = 200 * time.Millisecond
	if t < floor {
		t = floor
	}
	if t > base {
		t = base
	}
	return t
}

// observeRTT folds a measured round trip into the host's smoothed RTT
// estimate (EWMA, alpha = 1/8). Only non-timeout outcomes are recorded so a
// dropped probe does not inflate the estimate and slow later attempts.
func (s *Scanner) observeRTT(st *hostScanStat, d time.Duration) {
	if !s.options.AdaptiveTimeout || d <= 0 {
		return
	}
	ns := d.Nanoseconds()
	for {
		cur := atomic.LoadInt64(&st.srttNs)
		var next int64
		if cur == 0 {
			next = ns
		} else {
			next = cur - cur/8 + ns/8
		}
		if atomic.CompareAndSwapInt64(&st.srttNs, cur, next) {
			return
		}
	}
}

// checkPortOpen attempts to establish a connection to the target
// It handles proxy, timeout, and retries.
// Returns the open connection (if successful) or error.
// Caller is responsible for closing the connection.
func (s *Scanner) checkPortOpen(st *hostScanStat, host string, port int) (net.Conn, error) {
	// net.JoinHostPort brackets IPv6 literals; fmt.Sprintf("%s:%d") does not
	// and produces an address net.Dial cannot parse.
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var err error

	for i := 0; i <= s.options.Retries; i++ {
		// First attempt uses the RTT-adaptive budget; retries use the full user
		// budget and escalate, since a first-attempt timeout is often just
		// congestion/loss and giving the retry more time recovers slow or
		// rate-limited hosts instead of marking the port closed.
		attemptTimeout := s.options.Timeout
		if i == 0 {
			attemptTimeout = s.attemptTimeoutFor(st, s.options.Timeout)
		} else {
			attemptTimeout = s.options.Timeout + time.Duration(i)*s.options.Timeout/2
		}
		start := time.Now()
		conn, err = net.DialTimeout("tcp", address, attemptTimeout)

		if err == nil {
			s.observeRTT(st, time.Since(start))
			return conn, nil
		}

		// A "refused" reply also measured a real round trip; a timeout did not.
		isTimeout := false
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			isTimeout = true
		}
		if !isTimeout {
			s.observeRTT(st, time.Since(start))
		}

		// Retry logic
		if isConnRefused(err) {
			return nil, err // Connection refused usually means host is up but port closed
		}

		if i < s.options.Retries {
			time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
		}
	}
	return nil, err
}

func (s *Scanner) scanTarget(ctx context.Context, host string, port int) {
	stAny, _ := s.hostStats.LoadOrStore(host, newHostScanStat())
	st := stAny.(*hostScanStat)
	if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
		return
	}

	// 1. Check if port is open using shared logic
	conn, err := s.checkPortOpen(st, host, port)

	if err != nil {
		scanned := atomic.AddUint64(&st.scanned, 1)
		isTimeout := false
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			isTimeout = true
		}
		switch {
		case isTimeout:
			// A timeout usually means the port is filtered (packet dropped by a
			// firewall) rather than closed; treat it as a distinct signal and
			// never let it be mistaken for a hard error.
			atomic.AddUint64(&st.timeouts, 1)
			atomic.StoreInt32(&s.consecutiveErrors, 0)
		case isConnRefused(err):
			atomic.StoreInt32(&s.consecutiveErrors, 0)
		default:
			atomic.AddInt32(&s.consecutiveErrors, 1)
		}
		s.maybeDecideHost(ctx, host, st, scanned)
		s.maybeWarnFiltered(host, st, scanned)
		return
	}

	// Connection successful
	atomic.StoreInt32(&s.consecutiveErrors, 0)
	defer conn.Close()

	scanned := atomic.AddUint64(&st.scanned, 1)
	atomic.AddUint64(&st.open, 1)

	st.mu.Lock()
	st.discovered[port] = struct{}{}
	st.mu.Unlock()

	s.maybeDecideHost(ctx, host, st, scanned)
	if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
		return
	}

	if s.shouldBufferHost(st) {
		st.mu.Lock()
		mode := atomic.LoadUint32(&st.mode)
		if (mode == hostModeUndecided || mode == hostModeDeciding) && len(st.pending) < 2048 {
			st.pending = append(st.pending, port)
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()
		if atomic.LoadUint32(&st.mode) == hostModeSuspicious {
			return
		}
	}

	s.emitOpen(host, port, "")
}

func (s *Scanner) shouldBufferHost(st *hostScanStat) bool {
	if atomic.LoadUint32(&s.scanStageMajor) != 1 {
		return false
	}
	if atomic.LoadUint64(&s.scanPortTotal) < 5000 {
		return false
	}
	mode := atomic.LoadUint32(&st.mode)
	return mode == hostModeUndecided || mode == hostModeDeciding
}

func (s *Scanner) maybeDecideHost(ctx context.Context, host string, st *hostScanStat, scanned uint64) {
	if atomic.LoadUint32(&s.scanStageMajor) != 1 {
		return
	}
	if atomic.LoadUint64(&s.scanPortTotal) < 5000 {
		return
	}
	if scanned < 50 {
		return
	}
	mode := atomic.LoadUint32(&st.mode)
	if mode != hostModeUndecided && mode != hostModeDeciding {
		return
	}
	if !atomic.CompareAndSwapUint32(&st.mode, hostModeUndecided, hostModeDeciding) && atomic.LoadUint32(&st.mode) != hostModeDeciding {
		return
	}

	open := atomic.LoadUint64(&st.open)
	openRate := float64(open) / float64(scanned)
	if openRate >= 0.98 {
		// Everything answers: almost certainly a security device/proxy instead of
		// real listeners. Keep the state so ports already discovered are still
		// verified below (verifyAndEmit also re-checks every discovered port),
		// instead of silently dropping them.
		st.mu.Lock()
		atomic.StoreUint32(&st.mode, hostModeSuspicious)
		st.mu.Unlock()
		if !s.options.Quiet {
			gologger.Warning().Msgf("%-9s | %-9s | host=%s open-rate=%.2f%% (%d/%d) verify-only", utils.StagePortScan, "suspected", host, openRate*100, open, scanned)
		}
		if atomic.CompareAndSwapUint32(&st.verifying, 0, 1) {
			go s.verifyAndEmit(ctx, host, st)
		}
		return
	}

	if openRate > 0.90 && scanned < 200 {
		atomic.StoreUint32(&st.mode, hostModeUndecided)
		return
	}
	if openRate > 0.95 && scanned < 500 {
		atomic.StoreUint32(&st.mode, hostModeUndecided)
		return
	}

	var pending []int
	st.mu.Lock()
	if len(st.pending) > 0 {
		pending = append(pending, st.pending...)
		st.pending = st.pending[:0]
	}
	atomic.StoreUint32(&st.mode, hostModeNormal)
	st.mu.Unlock()
	for _, p := range pending {
		s.emitOpen(host, p, "")
	}
}

// maybeWarnFiltered surfaces (once per host, full-port scans only) the case
// where a host drops almost every probe. That normally means a packet-filtering
// firewall, and the result set for such a host may be incomplete. It never
// discards data; it only makes the condition visible instead of silently
// reporting every port as closed.
func (s *Scanner) maybeWarnFiltered(host string, st *hostScanStat, scanned uint64) {
	if atomic.LoadUint32(&s.scanStageMajor) != 1 {
		return
	}
	if atomic.LoadUint64(&s.scanPortTotal) < 5000 {
		return
	}
	if scanned < 200 {
		return
	}
	if atomic.LoadUint32(&st.warned) == 1 {
		return
	}
	timeouts := atomic.LoadUint64(&st.timeouts)
	if float64(timeouts)/float64(scanned) < 0.95 {
		return
	}
	if !atomic.CompareAndSwapUint32(&st.warned, 0, 1) {
		return
	}
	if !s.options.Quiet {
		gologger.Warning().Msgf("%-9s | %-9s | host=%s drop-rate=%.2f%% (%d/%d) filtered, results may be incomplete",
			utils.StagePortScan, "filtered", host, float64(timeouts)/float64(scanned)*100, timeouts, scanned)
	}
}

func (s *Scanner) emitOpen(host string, port int, banner string) {
	atomic.AddUint64(&s.resultsCount, 1)

	res := &ScanResult{
		Host:   host,
		Port:   port,
		State:  PortStateOpen,
		Banner: cleanBanner(banner),
	}
	if res.Banner != "" {
		if fp := IdentifyService(res.Banner, port); fp != nil {
			res.Fingerprint = fp
			res.Service = fp.Name
			res.Version = fp.Version
		}
	}

	if s.options.OnResult != nil {
		if s.options.Debug && !s.options.Quiet {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		s.options.OnResult(res)
	}
}

func (s *Scanner) verifyAndEmit(ctx context.Context, host string, st *hostScanStat) {
	// Verify the common-ports baseline plus every port already discovered as
	// open, so a host that answers everything (proxy/firewall) does not lose the
	// real services we already found.
	base := []int{80, 443, 22, 21, 25, 110, 143, 445, 3389, 135, 139, 3306, 5432, 6379, 27017, 8080, 8443, 8000, 8888, 9200}
	seen := make(map[int]struct{}, len(base)+16)
	ports := make([]int, 0, len(base)+16)
	for _, p := range base {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	st.mu.Lock()
	for p := range st.discovered {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	st.mu.Unlock()

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ok, banner := s.verifyPort(ctx, host, port)
		if !ok {
			continue
		}

		st.mu.Lock()
		if _, exists := st.verified[port]; exists {
			st.mu.Unlock()
			continue
		}
		st.verified[port] = struct{}{}
		st.mu.Unlock()

		s.emitOpen(host, port, banner)
	}
}

func (s *Scanner) verifyPort(ctx context.Context, host string, port int) (bool, string) {
	timeout := 800 * time.Millisecond
	if s.options.Timeout > 0 && s.options.Timeout < timeout {
		timeout = s.options.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	baseDeadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(baseDeadline)

	if isLikelyTLSPort(port) {
		serverName := ""
		if net.ParseIP(host) == nil {
			serverName = host
		}
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			_ = tlsConn.Close()
			return true, "tls"
		}
		return false, ""
	}

	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	early := make([]byte, 128)
	nEarly, _ := conn.Read(early)
	_ = conn.SetReadDeadline(baseDeadline)
	if nEarly > 0 {
		sEarly := string(early[:nEarly])
		if strings.HasPrefix(sEarly, "SSH-") || strings.HasPrefix(sEarly, "HTTP/") {
			return true, sEarly
		}
		if strings.HasPrefix(sEarly, "220") || strings.HasPrefix(sEarly, "200") {
			return true, sEarly
		}
		if nEarly >= 1 && early[0] == 0x0a {
			return true, "mysql"
		}
		if strings.Contains(sEarly, "PONG") {
			return true, sEarly
		}
	}

	reader := bufio.NewReader(conn)

	if port == 6379 {
		_, _ = conn.Write([]byte("PING\r\n"))
		buf := make([]byte, 32)
		n, _ := reader.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), "PONG") {
			return true, string(buf[:n])
		}
		return false, ""
	}

	if port == 3306 {
		b := make([]byte, 1)
		n, _ := io.ReadFull(reader, b)
		if n == 1 && b[0] == 0x0a {
			return true, "mysql"
		}
		return false, ""
	}

	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	line, _ := reader.ReadString('\n')
	if strings.HasPrefix(line, "HTTP/") {
		return true, line
	}

	buf := make([]byte, 64)
	n, _ := reader.Read(buf)
	if n > 0 {
		return true, string(buf[:n])
	}
	return false, ""
}

func isLikelyTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 993, 995, 465:
		return true
	default:
		return false
	}
}

func cleanBanner(banner string) string {
	// Remove newlines and non-printable chars
	return strings.TrimSpace(banner)
}
