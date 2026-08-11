// Port Scan Example / 端口扫描示例
//
// Uses the standalone portscan package directly, without the scanner SDK.
// For port pre-scanning as part of a vulnerability scan, see examples/sdk_portscan.
//
// 直接使用独立的 portscan 包，不经过扫描器 SDK。
// 如果需要在漏洞扫描前做端口预扫描，请参考 examples/sdk_portscan。
//
// Run / 运行:
//
//	go run ./examples/port_scan -targets 127.0.0.1
//	go run ./examples/port_scan -targets 127.0.0.1 -ports 22,80,443
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

func main() {
	targets := flag.String("targets", "127.0.0.1", "comma separated hosts / CIDRs to scan")
	ports := flag.String("ports", "top", "ports: top|full|all|80,443|1-1024")
	skipDiscovery := flag.Bool("Pn", true, "skip host discovery")
	flag.Parse()

	opts := portscan.DefaultOptions()
	opts.Targets = splitAndTrim(*targets)
	opts.Ports = *ports
	opts.DiscoveryMethod = "auto"
	opts.SkipDiscovery = *skipDiscovery

	if len(opts.Targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets provided / 未指定目标")
		os.Exit(1)
	}

	// OnResult is invoked concurrently from scan workers, so writes to shared
	// state (including stdout) need synchronising.
	// OnResult 由扫描工作协程并发调用，访问共享状态（包括 stdout）需要加锁。
	var mu sync.Mutex
	opts.OnResult = func(r *portscan.ScanResult) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Printf("%s:%d\n", r.Host, r.Port)
	}

	scanner, err := portscan.NewScanner(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create scanner / 创建扫描器失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("starting port scan... / 开始端口扫描...")
	start := time.Now()

	if err := scanner.Scan(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "scan failed / 扫描失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("completed in %v / 耗时 %v\n", time.Since(start), time.Since(start))
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
