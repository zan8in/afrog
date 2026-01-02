package portscan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/gologger"
	"golang.org/x/net/proxy"
)

// Scanner is the main entry point for port scanning
type Scanner struct {
	options           *Options
	pool              *ants.PoolWithFunc
	mu                sync.Mutex
	consecutiveErrors int32
	currentProgress   uint64
	resultsCount      uint64
	dialer            proxy.Dialer
	adaptiveDelay     int32 // Current delay in milliseconds
}

// NewScanner creates a new scanner instance
func NewScanner(opt *Options) (*Scanner, error) {
	if opt == nil {
		opt = DefaultOptions()
	}

	scanner := &Scanner{
		options: opt,
	}

	if opt.Proxy != "" {
		proxyURL, err := url.Parse(opt.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}

		switch proxyURL.Scheme {
		case "http":
			scanner.dialer = NewHttpProxyDialer(proxyURL)
		case "socks5":
			dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
			}
			scanner.dialer = dialer
		default:
			// Try default for others
			dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
			}
			scanner.dialer = dialer
		}
	}

	return scanner, nil
}

type httpProxyDialer struct {
	proxyAddr string
}

func NewHttpProxyDialer(proxyURL *url.URL) *httpProxyDialer {
	return &httpProxyDialer{
		proxyAddr: proxyURL.Host,
	}
}

func (h *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", h.proxyAddr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	// Basic implementation, no auth support yet
	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy refused connection: %s", resp.Status)
	}

	return &bufferedConn{Conn: conn, r: br}, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// Scan starts the scanning process
func (s *Scanner) Scan(ctx context.Context) error {
	// Parse ports
	portIter, err := NewPortIterator(s.options.Ports)
	if err != nil {
		return err
	}

	// Parse hosts (placeholder for now, assuming options.Targets are just IPs)
	hostIter := NewHostIterator(s.options.Targets)

	// Pre-scan Host Discovery (for CIDR/List optimization)
	// If we have more than 1 host, let's filter dead ones first
	if hostIter.Total() > 1 && !s.options.SkipDiscovery {
		origHosts := hostIter.GetHosts()
		discCtx, discStop := signal.NotifyContext(ctx, os.Interrupt)
		discStart := time.Now()
		if !s.options.Quiet {
			gologger.Info().Msgf("%-18s | %-9s | targets=%d method=%s", "Host discovery", "started", len(origHosts), s.options.DiscoveryMethod)
		}
		aliveHosts, derr := DiscoverAliveHosts(discCtx, s.options, origHosts)
		if derr != nil {
			return derr
		}
		if discCtx.Err() != nil {
			if !s.options.Quiet {
				gologger.Warning().Msgf("%-18s | %-9s | alive=%d", "Host discovery", "interrupted", len(aliveHosts))
			}
		}
		discStop()
		if !s.options.Quiet {
			gologger.Info().Msgf("%-18s | %-9s | alive=%d/%d duration=%s", "Host discovery", "completed", len(aliveHosts), len(origHosts), time.Since(discStart).Truncate(time.Second))
		}
		hostIter = NewHostIterator(aliveHosts)
	}

	// Shuffle hosts to avoid sequential scanning detection
	hostIter.Shuffle()

	total := hostIter.Total() * portIter.Total()
	startTime := time.Now()

	if !s.options.Quiet {
		gologger.Info().Msgf("%-18s | %-9s | hosts=%d ports=%s", "Port scan", "started", hostIter.Total(), s.options.Ports)
	}

	progressEnabled := s.options.Debug && !s.options.Quiet && total > 0
	var progressDone chan struct{}
	var lastPercent int32 = -1
	renderProgress := func(final bool) {
		if !progressEnabled {
			return
		}
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
		} else {
			if int32(percent) == atomic.LoadInt32(&lastPercent) {
				return
			}
			atomic.StoreInt32(&lastPercent, int32(percent))
		}
		elapsed := strings.Split(time.Since(startTime).String(), ".")[0] + "s"
		suffix := ""
		fmt.Fprint(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\r[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(percent, 0), percent, curr, total, elapsed, suffix)
		if final {
			fmt.Fprint(os.Stderr, "\n")
		}
	}

	if progressEnabled {
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

		s.scanTarget(scanCtx, task.host, task.port)

		atomic.AddUint64(&s.currentProgress, 1)
	})
	if err != nil {
		return err
	}
	defer pool.Release()

	// Iterate and submit tasks
	for {
		host, ok := hostIter.Next()
		if !ok {
			break
		}

		// Reset port iterator for each host
		portIter.Reset()
		for {
			// Check for high error rate (Adaptive Mode)
			// Dynamic Rate Adjustment:
			// 1. If errors > 20, increase delay significantly (up to 1s)
			// 2. If errors > 5, increase delay slightly
			// 3. If NO errors for a while (successes), decrease delay (recover speed)

			errCount := atomic.LoadInt32(&s.consecutiveErrors)
			currentDelay := atomic.LoadInt32(&s.adaptiveDelay)

			if errCount > 20 {
				// Severe network congestion or block
				newDelay := currentDelay + 100
				if newDelay > 1000 {
					newDelay = 1000
				}
				atomic.StoreInt32(&s.adaptiveDelay, newDelay)

				if s.options.Debug && errCount%10 == 0 { // Don't spam logs
					gologger.Warning().Msgf("High error rate (%d). Increasing delay to %dms", errCount, newDelay)
				}
				time.Sleep(time.Duration(newDelay) * time.Millisecond)
			} else if errCount > 5 {
				// Mild congestion
				atomic.CompareAndSwapInt32(&s.adaptiveDelay, 0, 10) // Init delay if 0
				time.Sleep(time.Duration(atomic.LoadInt32(&s.adaptiveDelay)) * time.Millisecond)
			} else {
				// Healthy network, try to recover speed
				if currentDelay > 0 && atomic.LoadUint64(&s.currentProgress)%50 == 0 {
					atomic.AddInt32(&s.adaptiveDelay, -10)
					if atomic.LoadInt32(&s.adaptiveDelay) < 0 {
						atomic.StoreInt32(&s.adaptiveDelay, 0)
					}
				}
			}

			port, ok := portIter.Next()
			if !ok {
				break
			}

			wg.Add(1)
			err := pool.Invoke(scanTask{host: host, port: port})
			if err != nil {
				wg.Done()
				// Handle pool overload or error
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	wg.Wait()

	if scanCtx.Err() != nil && !s.options.Quiet {
		gologger.Warning().Msgf("%-18s | %-9s | partial results", "Port scan", "interrupted")
	}
	scanStop()

	if progressDone != nil {
		close(progressDone)
		progressDone = nil
	}
	if progressEnabled {
		renderProgress(true)
	}
	if !s.options.Quiet {
		gologger.Info().Msgf("%-18s | %-9s | hosts=%d tasks=%d open=%d duration=%s",
			"Port scan",
			"completed",
			hostIter.Total(),
			total,
			atomic.LoadUint64(&s.resultsCount),
			time.Since(startTime).Truncate(time.Second),
		)
	}

	return nil
}

type scanTask struct {
	host string
	port int
}

// checkPortOpen attempts to establish a connection to the target
// It handles proxy, timeout, and retries.
// Returns the open connection (if successful) or error.
// Caller is responsible for closing the connection.
func (s *Scanner) checkPortOpen(host string, port int) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	var conn net.Conn
	var err error

	for i := 0; i <= s.options.Retries; i++ {
		if s.dialer != nil {
			// Proxy Dialing
			type dialRes struct {
				c net.Conn
				e error
			}
			ch := make(chan dialRes, 1)
			go func() {
				c, e := s.dialer.Dial("tcp", address)
				ch <- dialRes{c, e}
			}()

			select {
			case res := <-ch:
				conn, err = res.c, res.e
			case <-time.After(s.options.Timeout):
				err = fmt.Errorf("timeout")
			}
		} else {
			// Direct Dialing
			conn, err = net.DialTimeout("tcp", address, s.options.Timeout)
		}

		if err == nil {
			return conn, nil
		}

		// Retry logic
		if strings.Contains(err.Error(), "refused") {
			return nil, err // Connection refused usually means host is up but port closed
		}

		if i < s.options.Retries {
			time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
		}
	}
	return nil, err
}

func (s *Scanner) scanTarget(ctx context.Context, host string, port int) {
	// 1. Check if port is open using shared logic
	conn, err := s.checkPortOpen(host, port)

	if err != nil {
		// Error handling and adaptive rate limiting logic...
		errStr := err.Error()
		if !strings.Contains(errStr, "refused") && !os.IsTimeout(err) {
			atomic.AddInt32(&s.consecutiveErrors, 1)
		} else {
			atomic.StoreInt32(&s.consecutiveErrors, 0)
		}
		return
	}

	// Connection successful
	atomic.StoreInt32(&s.consecutiveErrors, 0)
	defer conn.Close()

	atomic.AddUint64(&s.resultsCount, 1)

	result := &ScanResult{
		Host:  host,
		Port:  port,
		State: PortStateOpen,
	}

	// Callback
	if s.options.OnResult != nil {
		if s.options.Debug && !s.options.Quiet {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		s.options.OnResult(result)
	}
}

func cleanBanner(banner string) string {
	// Remove newlines and non-printable chars
	return strings.TrimSpace(banner)
}
