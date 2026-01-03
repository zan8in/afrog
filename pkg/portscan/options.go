package portscan

import (
	"time"
)

// Options configuration for the port scanner
type Options struct {
	Targets                []string // List of IPs, CIDRs, or ranges
	Ports                  string   // Port range string (e.g., "80,443,1000-2000" or "top")
	S4ChunkSize            int
	RateLimit              int // Packets per second (approx) or concurrency limit
	Timeout                time.Duration
	Retries                int
	ScanMode               ScanMode
	ServiceDB              string // Path to nmap-services or custom fingerprints
	OnResult               func(*ScanResult)
	Debug                  bool
	Quiet                  bool
	Proxy                  string
	SkipDiscovery          bool // Skip host discovery phase
	DiscoveryPorts         []int
	DiscoveryFallback      bool
	DiscoveryFallbackPorts []int
	DiscoveryMethod        string
	IcmpConcurrency        int
	PingConcurrency        int
	DiscoveryTop           int
	DiscoveryRetries       int
	LogDiscoveredHosts     bool
}

// DefaultOptions returns a safe default configuration
func DefaultOptions() *Options {
	return &Options{
		Ports:                  "full",
		S4ChunkSize:            1000,
		RateLimit:              500,
		Timeout:                1000 * time.Millisecond,
		Retries:                2,
		ScanMode:               ScanModeAuto,
		Quiet:                  false,
		DiscoveryFallback:      true,
		DiscoveryFallbackPorts: []int{21, 25, 502, 102, 123, 135, 445, 8000, 8080},
		DiscoveryMethod:        "auto",
		IcmpConcurrency:        1000,
		PingConcurrency:        50,
		DiscoveryTop:           10,
		DiscoveryRetries:       1,
		LogDiscoveredHosts:     true,
	}
}

func ApplyQuickStrategy(o *Options) {
	o.RateLimit = 500
	o.Timeout = 800 * time.Millisecond
	o.Retries = 2
}

func ApplyQuickestStrategy(o *Options) {
	o.RateLimit = 1500
	o.Timeout = 1500 * time.Millisecond
	o.Retries = 2
}
