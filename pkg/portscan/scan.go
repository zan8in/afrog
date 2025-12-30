package portscan

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
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
	// Parse ports
	portIter, err := NewPortIterator(s.options.Ports)
	if err != nil {
		return err
	}

	// Parse hosts (placeholder for now, assuming options.Targets are just IPs)
	hostIter := NewHostIterator(s.options.Targets)

	total := hostIter.Total() * portIter.Total()
	startTime := time.Now()

	if s.options.Debug {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					curr := atomic.LoadUint64(&s.currentProgress)
					if int(curr) >= total {
						// Wait for main thread to print 100% and stats
						return
					}
					fmt.Fprintf(os.Stderr, "\rScanning ports (%d/%d) %.2f%%", curr, total, float64(curr)/float64(total)*100)
				}
			}
		}()
	}

	var wg sync.WaitGroup

	// Use ants for goroutine pooling
	pool, err := ants.NewPoolWithFunc(s.options.RateLimit, func(i interface{}) {
		defer wg.Done()
		task := i.(scanTask)

		// Check context
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.scanTarget(ctx, task.host, task.port)

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
			if atomic.LoadInt32(&s.consecutiveErrors) > 20 {
				if s.options.Debug {
					gologger.Warning().Msgf("High error rate detected (%d consecutive errors). Pausing for 100ms...", atomic.LoadInt32(&s.consecutiveErrors))
				}
				time.Sleep(100 * time.Millisecond)
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

	if s.options.Debug {
		fmt.Fprintf(os.Stderr, "\rScanning ports (%d/%d) 100.00%%\n", total, total)
		fmt.Fprintf(os.Stderr, "Scan Statistics:\n")
		fmt.Fprintf(os.Stderr, "  - Total Targets: %d\n", hostIter.Total())
		fmt.Fprintf(os.Stderr, "  - Total Ports:   %d\n", total)
		fmt.Fprintf(os.Stderr, "  - Open Ports:    %d\n", atomic.LoadUint64(&s.resultsCount))
		fmt.Fprintf(os.Stderr, "  - Duration:      %s\n", time.Since(startTime))
	}

	return nil
}

type scanTask struct {
	host string
	port int
}

func (s *Scanner) scanTarget(ctx context.Context, host string, port int) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Basic Connect Scan
	conn, err := net.DialTimeout("tcp", address, s.options.Timeout)
	if err != nil {
		// Only increment consecutiveErrors if it's NOT a standard port closed/filtered error.
		// "refused" means port is closed (host is up).
		// "timeout" means port is filtered (firewall) or host is down.
		// We only want to slow down if there are system resource issues or other unexpected errors.
		errStr := err.Error()
		if !strings.Contains(errStr, "refused") && !os.IsTimeout(err) {
			atomic.AddInt32(&s.consecutiveErrors, 1)
		} else {
			// If it's just a closed/filtered port, we might want to reset the counter
			// or at least not increment it.
			// Resetting it ensures we only throttle on burst system errors.
			atomic.StoreInt32(&s.consecutiveErrors, 0)
		}
		return // Closed or filtered
	}
	atomic.StoreInt32(&s.consecutiveErrors, 0)
	defer conn.Close()

	atomic.AddUint64(&s.resultsCount, 1)

	// Port is open
	result := &ScanResult{
		Host:  host,
		Port:  port,
		State: PortStateOpen,
	}

	// Service Detection (Simple Banner Grabbing)
	// We set a deadline for reading
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))

	// Try to read initial banner (some services send immediately like SSH, FTP)
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	if n > 0 {
		result.Banner = string(buffer[:n])
	} else {
		// If no banner, try to send a generic probe (HTTP)
		// This is a very basic example. Real service detection is more complex.
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

		conn.SetReadDeadline(time.Now().Add(time.Second * 2))
		n, _ = conn.Read(buffer)
		if n > 0 {
			result.Banner = string(buffer[:n])
		}
	}

	// Clean banner
	result.Banner = cleanBanner(result.Banner)

	// Identify Service
	result.Fingerprint = IdentifyService(result.Banner, port)
	if result.Fingerprint.Name != "unknown" {
		result.Service = result.Fingerprint.Name
		result.Version = result.Fingerprint.Version
	}

	// Callback
	if s.options.OnResult != nil {
		s.options.OnResult(result)
	}
}

func cleanBanner(banner string) string {
	// Remove newlines and non-printable chars
	return strings.TrimSpace(banner)
}
