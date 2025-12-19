package main

import (
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/zan8in/afrog/v3"
)

func main() {
	// Create SDK scan options
	options := afrog.NewSDKOptions()

	// Set scan target
	options.Targets = []string{
		"https://mmw.keshvacredit.com",
	}

	// Set POC path (required)
	pocPath, err := filepath.Abs("./pocs/afrog-pocs") // Adjust path as needed
	if err != nil {
		log.Fatalf("Failed to get POC path: %v", err)
	}
	options.PocFile = pocPath

	// Configuration for scanning
	options.Concurrency = 8
	options.RateLimit = 30
	options.Timeout = 12
	options.Search = "CVE-2025-55182" // Search for specific POC
	options.EnableStream = true

	fmt.Println("Creating SDK scanner for vulnerability scanning...")

	// Create scanner instance
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Start async scan
	err = scanner.RunAsync()
	if err != nil {
		log.Printf("Failed to start async scan: %v", err)
		return
	}

	// Process results in real-time
	startTime := time.Now()
	var totalVulns int

	for res := range scanner.ResultChan {
		if res == nil {
			break
		}

		totalVulns++
		fmt.Printf("\nVulnerability found:\n")
		fmt.Printf("   Target: %s\n", res.Target)
		fmt.Printf("   POC: %s\n", res.PocInfo.Info.Name)
		fmt.Printf("   Severity: %s\n", res.PocInfo.Info.Severity)
	}

	// Scan completed
	fmt.Printf("\nScan completed! Total vulnerabilities: %d\n", totalVulns)
	fmt.Printf("Duration: %v\n", time.Since(startTime))
}
