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
	MaxHostConcurrency     int // Max concurrent probes per target (0 = unlimited)
	Timeout                time.Duration
	Retries                int
	AdaptiveTimeout        bool // Scale the connect timeout with measured RTT
	ScanMode               ScanMode
	ServiceProbes          bool   // Send active service probes (default: passive banner grabbing only)
	FingerprintDir         string // Optional directory with probes.yaml / services.yaml / ports.yaml that overrides the built-in set
	OnResult               func(*ScanResult)
	OnProgress             func(phase string, status string, finished int, total int, percent int)
	OnDiscoveredHost       func(host string)
	Debug                  bool
	LiveStats              bool
	StageLog               bool // Print phase boundary lines (HOST-DISC/PORT-SCAN started/completed); off by default
	Quiet                  bool
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
		MaxHostConcurrency:     50,
		Timeout:                1000 * time.Millisecond,
		Retries:                2,
		AdaptiveTimeout:        true,
		ScanMode:               ScanModeAuto,
		Quiet:                  false,
		DiscoveryFallback:      true,
		DiscoveryFallbackPorts: defaultDiscoveryFallbackPorts(),
		DiscoveryMethod:        "auto",
		IcmpConcurrency:        1000,
		PingConcurrency:        50,
		DiscoveryTop:           10,
		DiscoveryRetries:       1,
		LogDiscoveredHosts:     true,
	}
}
