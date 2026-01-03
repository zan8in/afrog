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
	opts.Targets = []string{"imap.brutalnature.com", "47.102.209.132"}
	opts.DiscoveryMethod = "auto"
	opts.Ports = "full" // Test prioritized full scan
	opts.SkipDiscovery = false
	// opts.RateLimit = 300
	// opts.Timeout = 1000 * time.Millisecond
	// opts.Retries = 2
	opts.Debug = true
	// portscan.ApplyQuickestStrategy(opts)

	// 2. Setup Callback
	opts.OnResult = func(result *portscan.ScanResult) {
		fmt.Printf("%s:%d\n", result.Host, result.Port)
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
