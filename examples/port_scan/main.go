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
	opts.Targets = []string{"221.194.144.85"}
	opts.Ports = "top-100" // Test prioritized full scan
	opts.RateLimit = 100
	opts.Timeout = 1800 * time.Millisecond
	opts.Retries = 2
	opts.Debug = true
	// opts.Proxy = "socks5://127.0.0.1:7890" // Example proxy
	opts.Proxy = "socks5://111.43.114.137:1080"

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
