package portscan

import (
	"time"
)

// Options configuration for the port scanner
type Options struct {
	Targets                []string // List of IPs, CIDRs, or ranges
	Ports                  string   // Port range string (e.g., "80,443,1000-2000" or "top-100")
	RateLimit              int      // Packets per second (approx) or concurrency limit
	Timeout                time.Duration
	Retries                int
	ScanMode               ScanMode
	ServiceDB              string // Path to nmap-services or custom fingerprints
	OnResult               func(*ScanResult)
	Debug                  bool
	Proxy                  string
	SkipDiscovery          bool // Skip host discovery phase
	DiscoveryPorts         []int
	DiscoveryFallback      bool
	DiscoveryUDPEnabled    bool
	DiscoveryUDPPorts      []int
	DiscoveryFallbackPorts []int
}

// DefaultOptions returns a safe default configuration
func DefaultOptions() *Options {
	return &Options{
		Ports:                  "top-100",
		RateLimit:              500,
		Timeout:                1500 * time.Millisecond,
		Retries:                2,
		ScanMode:               ScanModeAuto,
		DiscoveryFallback:      true,
		DiscoveryUDPEnabled:    false,
		DiscoveryFallbackPorts: []int{21, 25, 502, 102, 123, 135, 445},
	}
}
