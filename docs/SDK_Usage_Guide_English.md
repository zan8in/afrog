# Afrog SDK Usage Guide

## Overview

The Afrog SDK provides a clean, efficient Go programming interface specifically designed for integrating vulnerability scanning capabilities. The SDK features the following core characteristics:

### 🚀 Core Features
- ✅ **Structured Returns** - Direct Go struct returns for easy program processing
- ✅ **Real-time Result Streaming** - Supports both synchronous callbacks and asynchronous streaming
- ✅ **OOB Detection Support** - Complete Out-of-Band detection configuration and management
- ✅ **Detailed Statistics** - Provides scan progress, performance, and result statistics
- ✅ **Concurrency Safe** - All APIs are thread-safe

## Installation

```bash
go get -u github.com/zan8in/afrog/v3
```

## Quick Start

### Basic Scan Example

The simplest usage pattern, suitable for quick integration:

```go
package main

import (
    "fmt"
    "log"
    "path/filepath"
    "github.com/zan8in/afrog/v3"
)

func main() {
    // Create scan options
    options := afrog.NewSDKOptions()
    
    // Set scan targets
    options.Targets = []string{"https://www.example.com"}
    
    // Set POC path (required)
    pocPath, _ := filepath.Abs("./pocs/afrog-pocs")
    options.PocFile = pocPath
    
    // Create scanner
    scanner, err := afrog.NewSDKScanner(options)
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()
    
    // Execute scan
    scanner.Run()
    
    // Get results
    results := scanner.GetResults()
    fmt.Printf("Found %d vulnerabilities\n", len(results))
}
```

## SDK Configuration Options

### SDKOptions Structure

```go
type SDKOptions struct {
    // ========== Target Configuration ==========
    Targets     []string // List of scan targets
    TargetsFile string   // Path to targets file
    
    // ========== POC Configuration ==========
    PocFile  string // POC file or directory path (required)
    Search   string // POC search keywords
    Severity string // Severity level filter
    
    // ========== Performance Configuration ==========
    RateLimit    int // Request rate limit (default: 150)
    Concurrency  int // Concurrency level (default: 25)
    Retries      int // Retry attempts (default: 1)
    Timeout      int // Timeout in seconds (default: 10)
    MaxHostError int // Max errors per host (default: 3)
    
    // ========== Network Configuration ==========
    Proxy string // HTTP/SOCKS5 proxy
    
    // ========== OOB Configuration ==========
    EnableOOB  bool   // Enable OOB detection
    OOB        string // OOB adapter type
    OOBKey     string // OOB API key
    OOBDomain  string // OOB domain
    OOBApiUrl  string // OOB API URL
    OOBHttpUrl string // OOB HTTP URL
    
    // ========== Output Configuration ==========
    EnableStream bool // Enable streaming output
}
```

### Configuration Options Explained

#### Target Configuration
- `Targets`: Directly specify list of scan targets
- `TargetsFile`: Read targets from file (one per line)

#### POC Configuration
- `PocFile`: **Required** POC file or directory path
- `Search`: Filter POCs by keywords, e.g., "tomcat,phpinfo"
- `Severity`: Filter by severity levels, e.g., "high,critical"

#### Performance Tuning
- `Concurrency`: Number of concurrent scan threads, adjust based on target count
- `RateLimit`: Requests per second limit to avoid triggering defenses
- `Timeout`: Individual request timeout
- `Retries`: Number of retry attempts for failed requests

## Core Feature Examples

### 1. Real-time Result Callbacks

Process vulnerabilities immediately upon discovery:

```go
scanner.OnResult = func(r *result.Result) {
    fmt.Printf("Vulnerability found: %s - %s [%s]\n", 
        r.Target, 
        r.PocInfo.Info.Name,
        r.PocInfo.Info.Severity)
    
    // Immediate processing logic
    if r.PocInfo.Info.Severity == "critical" {
        sendAlert(r)
    }
}

scanner.Run()
```

### 2. Progress Monitoring

Monitor scan progress in real-time:

```go
go func() {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        progress := scanner.GetProgress()
        stats := scanner.GetStats()
        fmt.Printf("Progress: %.2f%% (%d/%d) Vulnerabilities: %d\n", 
            progress, 
            stats.CompletedScans,
            stats.TotalScans,
            stats.FoundVulns)
    }
}()

scanner.Run()
```

### 3. Asynchronous Scanning with Streaming

Non-blocking scanning with real-time results:

```go
options.EnableStream = true
scanner, _ := afrog.NewSDKScanner(options)

// Start async scan
scanner.RunAsync()

// Read real-time results from channel
for result := range scanner.ResultChan {
    fmt.Printf("Live discovery: %s - %s\n", 
        result.Target, 
        result.PocInfo.Info.Name)
    
    // Process each result in real-time
    processResult(result)
}
```

### 4. OOB (Out-of-Band) Detection Configuration

#### CEYE.io Configuration (Recommended)
```go
options.EnableOOB = true
options.OOB = "ceyeio"
options.OOBKey = "your-ceye-api-token"
options.OOBDomain = "your-subdomain.ceye.io"
```

#### DNSLog.cn Configuration (Free)
```go
options.EnableOOB = true
options.OOB = "dnslogcn"
options.OOBDomain = "your.dnslog.cn"
```

#### Other OOB Services
```go
// Alphalog
options.OOB = "alphalog"
options.OOBDomain = "your.alphalog.cn"
options.OOBApiUrl = "https://api.alphalog.cn"

// XRay
options.OOB = "xray"
options.OOBDomain = "your.xray.domain"
options.OOBApiUrl = "http://xray-api:8777"
options.OOBKey = "your-xray-token"
```

#### OOB Status Check
```go
if oobEnabled, oobStatus := scanner.GetOOBStatus(); oobEnabled {
    fmt.Printf("✓ OOB Status: %s\n", oobStatus)
} else {
    fmt.Printf("✗ OOB Status: %s\n", oobStatus)
}
```

## API Method Reference

### SDKScanner Core Methods

| Method | Description | Return Value |
|--------|-------------|--------------|
| `NewSDKScanner(opts)` | Create scanner instance | `*SDKScanner, error` |
| `Run()` | Execute scan synchronously | `error` |
| `RunAsync()` | Execute scan asynchronously | `error` |
| `GetResults()` | Get all scan results | `[]*result.Result` |
| `GetStats()` | Get scan statistics | `ScanStats` |
| `GetProgress()` | Get scan progress (0-100) | `float64` |
| `GetVulnerabilityCount()` | Get vulnerability count | `int` |
| `HasVulnerabilities()` | Check if vulnerabilities exist | `bool` |
| `Stop()` | Stop scanning | - |
| `Close()` | Close scanner and release resources | - |

### Dynamic Configuration Methods

| Method | Description |
|--------|-------------|
| `SetProxy(proxy)` | Dynamically set proxy |
| `SetRateLimit(n)` | Dynamically set rate limit |
| `SetConcurrency(n)` | Dynamically set concurrency |

### OOB Related Methods

| Method | Description | Return Value |
|--------|-------------|--------------|
| `IsOOBEnabled()` | Check if OOB is enabled | `bool` |
| `GetOOBStatus()` | Get OOB status information | `bool, string` |

### ScanStats Structure

```go
type ScanStats struct {
    StartTime      time.Time  // Scan start time
    EndTime        time.Time  // Scan end time
    TotalTargets   int        // Total target count
    TotalPocs      int        // Total POC count
    TotalScans     int        // Total scan tasks
    CompletedScans int32      // Completed scan count
    FoundVulns     int32      // Found vulnerability count
}
```

## Advanced Usage Examples

### Batch Scanning with Result Analysis

```go
options := afrog.NewSDKOptions()
options.TargetsFile = "targets.txt"  // Read many targets from file
options.PocFile = "/path/to/pocs"
options.Severity = "high,critical"   // Only scan high-risk vulnerabilities
options.Concurrency = 50            // Increase concurrency

scanner, _ := afrog.NewSDKScanner(options)

// Handle different severity levels differently
scanner.OnResult = func(r *result.Result) {
    switch r.PocInfo.Info.Severity {
    case "critical":
        sendUrgentAlert(r)
    case "high":
        logHighRiskVuln(r)
    default:
        saveToDatabase(r)
    }
}

scanner.Run()
results := scanner.GetResults()
generateReport(results)
```

### Intelligent Scan Control

```go
scanner.OnResult = func(r *result.Result) {
    // Stop scanning when critical vulnerability found
    if r.PocInfo.Info.Severity == "critical" {
        fmt.Println("Critical vulnerability found, stopping scan")
        scanner.Stop()
    }
}

// Dynamically adjust scan parameters
go func() {
    time.Sleep(30 * time.Second)
    // Reduce rate after 30 seconds
    scanner.SetRateLimit(50)
}()
```

### Multi-target Parallel Scanning

```go
targets := [][]string{
    {"https://site1.com", "https://site2.com"},
    {"https://site3.com", "https://site4.com"},
}

var wg sync.WaitGroup
results := make(chan []*result.Result, len(targets))

for _, targetGroup := range targets {
    wg.Add(1)
    go func(targets []string) {
        defer wg.Done()
        
        options := afrog.NewSDKOptions()
        options.Targets = targets
        options.PocFile = pocPath
        
        scanner, _ := afrog.NewSDKScanner(options)
        defer scanner.Close()
        
        scanner.Run()
        results <- scanner.GetResults()
    }(targetGroup)
}

wg.Wait()
close(results)

// Aggregate all results
allResults := []*result.Result{}
for groupResults := range results {
    allResults = append(allResults, groupResults...)
}
```

## Performance Optimization Tips

### 1. Concurrency Optimization

```go
targetCount := len(options.Targets)

// Dynamically adjust concurrency based on target count
switch {
case targetCount <= 10:
    options.Concurrency = 5
case targetCount <= 100:
    options.Concurrency = 25
case targetCount <= 1000:
    options.Concurrency = 50
default:
    options.Concurrency = 100
}
```

### 2. Memory Optimization

```go
// For large-scale scans, use streaming to avoid memory accumulation
options.EnableStream = true

// Process results immediately, don't accumulate
scanner.OnResult = func(r *result.Result) {
    processImmediately(r)
    // Don't store in slices
}
```

### 3. Network Optimization

```go
// Configuration for unstable networks
options.Retries = 3
options.Timeout = 30
options.RateLimit = 50  // Reduce request frequency

// Use proxy pools
proxies := []string{"proxy1:8080", "proxy2:8080"}
scanner.SetProxy(proxies[rand.Intn(len(proxies))])
```

## Error Handling Best Practices

### Complete Error Handling

```go
scanner, err := afrog.NewSDKScanner(options)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "POC文件"):
        log.Fatal("POC configuration error:", err)
    case strings.Contains(err.Error(), "目标"):
        log.Fatal("Target configuration error:", err)
    default:
        log.Fatal("Initialization failed:", err)
    }
}

// Scan error handling
if err := scanner.Run(); err != nil {
    log.Printf("Scan exception: %v", err)
    
    // Even with errors, partial results can be obtained
    results := scanner.GetResults()
    if len(results) > 0 {
        fmt.Printf("Partial results obtained: %d vulnerabilities\n", len(results))
    }
}
```

### Timeout and Cancellation Handling

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

go func() {
    scanner.RunAsync()
}()

select {
case <-ctx.Done():
    scanner.Stop()
    fmt.Println("Scan timed out, stopped")
case <-scanner.ResultChan:
    // Normal completion
}
```

## Integration Examples

### Web Service Integration

```go
func scanHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("target")
    
    options := afrog.NewSDKOptions()
    options.Targets = []string{target}
    options.PocFile = os.Getenv("POC_PATH")
    
    scanner, err := afrog.NewSDKScanner(options)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer scanner.Close()
    
    scanner.Run()
    results := scanner.GetResults()
    
    // Return JSON results
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "vulnerabilities": len(results),
        "results": results,
    })
}
```

### CI/CD Integration

```go
func main() {
    options := afrog.NewSDKOptions()
    options.TargetsFile = "staging-urls.txt"
    options.PocFile = "/security/pocs"
    options.Severity = "high,critical"
    
    scanner, err := afrog.NewSDKScanner(options)
    if err != nil {
        os.Exit(1)
    }
    defer scanner.Close()
    
    scanner.Run()
    
    if scanner.HasVulnerabilities() {
        fmt.Println("❌ Security vulnerabilities found, blocking deployment")
        results := scanner.GetResults()
        for _, r := range results {
            fmt.Printf("- %s: %s\n", r.Target, r.PocInfo.Info.Name)
        }
        os.Exit(1)
    }
    
    fmt.Println("✅ Security check passed")
}
```

## Frequently Asked Questions

### Q: How to handle scanning of large numbers of targets?
A: Use streaming output and appropriate concurrency control:
```go
options.EnableStream = true
options.Concurrency = 50
scanner.OnResult = func(r *result.Result) {
    // Process immediately, don't accumulate
    processImmediately(r)
}
```

### Q: How to ensure OOB detection works properly?
A: Check OOB status before scanning:
```go
if enabled, status := scanner.GetOOBStatus(); !enabled {
    log.Printf("OOB Warning: %s", status)
}
```

### Q: How to optimize scan performance?
A: Adjust parameters based on network and target conditions:
```go
// Internal network scanning
options.Concurrency = 100
options.RateLimit = 500

// External network scanning
options.Concurrency = 25
options.RateLimit = 150
options.Timeout = 15
```

### Q: How to handle scan interruption?
A: Use context and signal handling:
```go
c := make(chan os.Signal, 1)
signal.Notify(c, os.Interrupt)

go func() {
    <-c
    scanner.Stop()
    fmt.Println("Scan stopped")
}()
```

## Important Notes

1. **POC Path Must Be Specified** - SDK won't automatically download or find POCs
2. **Completely Silent Operation** - No console output, suitable for program integration
3. **No File Generation** - Won't create any report files
4. **Resource Management** - Must call `Close()` to release resources
5. **Concurrency Safe** - All methods are thread-safe
6. **OOB Configuration** - Proper configuration required for out-of-band vulnerability detection

## License

MIT License

---

For more examples and detailed documentation, please refer to the example code in the `examples/` directory.
