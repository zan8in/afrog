package main

import (
	"context"
	"fmt"
	"time"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

func main() {
	// 1. Setup Options
	opts := portscan.DefaultOptions()
	opts.Targets = []string{"154.92.66.253/24"}
	opts.Ports = "full" // Test prioritized full scan
	opts.RateLimit = 500
	opts.Timeout = 1000 * time.Millisecond
	opts.Retries = 2
	opts.Debug = true
	opts.SkipDiscovery = false
	opts.DiscoveryUDPEnabled = true
	opts.DiscoveryUDPPorts = []int{53, 161}
	// opts.Proxy = "http://127.0.0.1:51024"

	// 2. Setup Callback
	opts.OnResult = func(result *portscan.ScanResult) {
		fmt.Printf("\r[+] Open: %s:%d (%s %s)\n", result.Host, result.Port, result.Service, result.Version)
		// if result.Banner != "" {
		// 	fmt.Printf("    Banner: %s\n", result.Banner)
		// }
	}

	// 3. Create Scanner
	scanner, err := portscan.NewScanner(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting Port Scan...")
	startTime := time.Now()

	// 4. Run Scan
	err = scanner.Scan(context.Background())
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
	}

	fmt.Printf("Scan completed in %v\n", time.Since(startTime))
}
