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
	opts.Targets = []string{"scanme.nmap.org"}
	opts.Ports = "full" // Test prioritized full scan
	opts.RateLimit = 1000
	opts.Timeout = 800 * time.Millisecond
	opts.Retries = 2
	opts.Debug = true

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
