// Vulnerability Scan Example / 漏洞扫描示例
//
// Demonstrates streaming results while the scan runs, and exiting non-zero when
// something is found — the shape a CI security gate usually needs.
//
// 演示扫描过程中实时消费结果，并在发现漏洞时以非零状态码退出，
// 这是 CI 安全门禁常见的用法。
//
// Run / 运行:
//
//	go run ./examples/vuln_scan -target https://example.com -search CVE-2024-1234
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	search := flag.String("search", "", "poc search keyword")
	severity := flag.String("severity", "", "severity filter, e.g. \"high,critical\"")
	failOnFind := flag.Bool("fail-on-find", false, "exit 1 when a vulnerability is found")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	options := []sdk.Option{
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(8),
		sdk.WithRateLimit(30),
		sdk.WithTimeout(12),
	}
	if *search != "" {
		options = append(options, sdk.WithSearch(*search))
	}
	if *severity != "" {
		options = append(options, sdk.WithSeverity(*severity))
	}

	scanner, err := sdk.New(ctx, options...)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// Subscribe before Start so that no finding is missed.
	// 在 Start 之前订阅，避免漏掉任何结果。
	results := scanner.ResultStream()

	if err := scanner.Start(ctx); err != nil {
		log.Fatalf("start scan / 启动扫描失败: %v", err)
	}

	start := time.Now()
	found := 0

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The stream closes when the scan finishes, so range terminates.
		// 扫描结束时流会关闭，range 自然退出。
		for r := range results {
			found++
			fmt.Printf("\n[%d] %s\n", found, r.FullTarget)
			fmt.Printf("    poc:      %s (%s)\n", r.PocName, r.PocID)
			fmt.Printf("    severity: %s\n", r.Severity)
		}
	}()

	if err := scanner.Wait(ctx); err != nil {
		log.Printf("scan finished with error / 扫描出错: %v", err)
	}
	wg.Wait()

	fmt.Printf("\nscan completed / 扫描完成: %d vulnerabilities in %v\n", found, time.Since(start))

	if *failOnFind && found > 0 {
		fmt.Println("vulnerabilities found, failing / 发现漏洞，返回失败状态")
		os.Exit(1)
	}
}
