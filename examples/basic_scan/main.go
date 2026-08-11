// Basic Scan Example / 基础扫描示例
//
// Demonstrates the smallest useful afrog SDK program: configure a target,
// point at a PoC directory, run the scan and read the results.
//
// 演示 afrog SDK 最小可用程序：配置目标、指定 PoC 目录、执行扫描并读取结果。
//
// Run / 运行:
//
//	go run ./examples/basic_scan
//	go run ./examples/basic_scan -target https://example.com -pocs /path/to/pocs
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	severity := flag.String("severity", "info", "severity filter, e.g. \"high,critical\"")
	flag.Parse()

	// Ctrl+C cancels the context, which stops the scan cleanly.
	// Ctrl+C 取消 context，扫描会干净地停止。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// WithPocPaths accepts a single file, a directory, or a glob pattern.
	// WithPocPaths 支持单个文件、目录，以及 glob 通配符。
	scanner, err := sdk.New(ctx,
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithSeverity(*severity),
		sdk.WithConcurrency(10),
		sdk.WithRateLimit(50),
		sdk.WithTimeout(10),
	)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// Inspect what was loaded before spending time on the network.
	// 在真正发起网络请求之前，先确认加载到了哪些 PoC。
	fmt.Printf("loaded %d pocs / 已加载 %d 个 PoC\n", scanner.PocCount(), scanner.PocCount())
	for _, d := range scanner.PocDiagnostics() {
		log.Printf("skipped poc / 跳过 PoC: %v", d)
	}

	fmt.Println("scanning... / 扫描中...")
	if err := scanner.Execute(ctx); err != nil {
		log.Printf("scan finished with error / 扫描出错: %v", err)
	}

	results := scanner.Results()
	stats := scanner.Stats()

	fmt.Printf("\n========== Results / 扫描结果 ==========\n")
	fmt.Printf("vulnerabilities / 漏洞数: %d\n", len(results))
	fmt.Printf("duration / 耗时: %v\n", stats.Duration())

	for i, v := range results {
		fmt.Printf("%d. [%s] %s\n", i+1, v.Severity, v.FullTarget)
		fmt.Printf("   poc: %s (%s)\n", v.PocName, v.PocID)
		if v.Description != "" {
			fmt.Printf("   description / 描述: %s\n", v.Description)
		}
	}
	if len(results) == 0 {
		fmt.Println("no vulnerabilities found / 未发现漏洞")
	}
}
