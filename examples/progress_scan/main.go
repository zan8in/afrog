package main

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// Progress Scan Example / 带进度条的扫描示例
//
// This example demonstrates how to monitor scan progress in real-time
// and display a progress bar during the scanning process.
//
// 此示例演示如何实时监控扫描进度，
// 并在扫描过程中显示进度条。

func main() {
	// Create SDK scan options / 创建 SDK 扫描选项
	options := afrog.NewSDKOptions()

	// Set multiple scan targets for better progress demonstration
	// 设置多个扫描目标以更好地演示进度
	options.Targets = []string{
		"https://www.example.com",
	}

	// Set POC path (required) / 设置 POC 路径（必需）
	pocPath, err := filepath.Abs("../pocs/afrog-pocs")
	if err != nil {
		log.Fatalf("Failed to get POC path / 获取 POC 路径失败: %v", err)
	}
	options.PocFile = pocPath

	// Configuration for better progress visibility / 配置以更好地显示进度
	options.Concurrency = 5        // Lower concurrency for visible progress / 较低并发以显示进度
	options.RateLimit = 20         // Lower rate limit / 较低速率限制
	options.Timeout = 15           // Longer timeout / 更长超时时间
	options.Search = "fingerprint" // Search fingerprint POCs / 搜索指纹识别 POC
	options.Severity = "info,low"  // Multiple severity levels / 多个严重级别

	fmt.Println("Creating SDK scanner... / 创建 SDK 扫描器...")

	// Create scanner instance / 创建扫描器实例
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		log.Fatalf("Failed to create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close() // Always close the scanner / 始终关闭扫描器

	// Real-time result callback / 实时结果回调
	var vulnCount int
	var mu sync.Mutex
	scanner.OnResult = func(r *result.Result) {
		mu.Lock()
		vulnCount++
		fmt.Printf("\n[Real-time Discovery / 实时发现] %s - %s [%s]\n",
			r.Target,
			r.PocInfo.Info.Name,
			r.PocInfo.Info.Severity)
		mu.Unlock()
	}

	// Start progress monitoring goroutine / 启动进度监控协程
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond) // Update every 0.5 seconds / 每0.5秒更新
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				progress := scanner.GetProgress()
				stats := scanner.GetStats()

				// Create progress bar / 创建进度条
				progressBar := createProgressBar(progress, 50)

				// Clear line and print progress / 清除行并打印进度
				fmt.Printf("\r[Progress / 进度] %s %.2f%% (%d/%d) Found / 发现: %d",
					progressBar,
					progress,
					stats.CompletedScans,
					stats.TotalScans,
					stats.FoundVulns)

			case <-done:
				return
			}
		}
	}()

	fmt.Println("Starting scan with progress monitoring... / 开始带进度监控的扫描...")

	// Execute scan (synchronous) / 执行扫描（同步）
	start := time.Now()
	err = scanner.Run()
	if err != nil {
		log.Printf("Scan error occurred / 扫描出现错误: %v", err)
	}

	// Stop progress monitoring / 停止进度监控
	done <- true
	time.Sleep(100 * time.Millisecond) // Wait for goroutine to finish / 等待协程结束

	// Get final results / 获取最终结果
	results := scanner.GetResults()
	stats := scanner.GetStats()
	duration := time.Since(start)

	// Print final results / 打印最终结果
	fmt.Printf("\n\n========== Scan Completed / 扫描完成 ==========\n")
	fmt.Printf("Total targets / 总目标数: %d\n", stats.TotalTargets)
	fmt.Printf("Total POCs / 总 POC 数: %d\n", stats.TotalPocs)
	fmt.Printf("Total scans / 总扫描数: %d\n", stats.TotalScans)
	fmt.Printf("Completed scans / 完成扫描数: %d\n", stats.CompletedScans)
	fmt.Printf("Vulnerabilities found / 发现漏洞: %d\n", len(results))
	fmt.Printf("Scan duration / 扫描耗时: %v\n", duration)
	fmt.Printf("Average speed / 平均速度: %.2f scans/sec\n",
		float64(stats.CompletedScans)/duration.Seconds())

	// Display vulnerability summary / 显示漏洞摘要
	if len(results) > 0 {
		fmt.Printf("\n========== Vulnerability Summary / 漏洞摘要 ==========\n")
		severityCount := make(map[string]int)

		for _, result := range results {
			severityCount[result.PocInfo.Info.Severity]++
		}

		for severity, count := range severityCount {
			fmt.Printf("  %s: %d\n", severity, count)
		}

		fmt.Printf("\n========== Vulnerability Details / 漏洞详情 ==========\n")
		for i, result := range results {
			fmt.Printf("%d. [%s] %s\n", i+1, result.PocInfo.Info.Severity, result.Target)
			fmt.Printf("   POC: %s\n", result.PocInfo.Info.Name)
			if result.PocInfo.Info.Description != "" {
				fmt.Printf("   Description / 描述: %s\n", result.PocInfo.Info.Description)
			}
			fmt.Println("   ---")
		}
	} else {
		fmt.Println("No vulnerabilities found / 未发现漏洞")
	}

	fmt.Println("Scan completed successfully! / 扫描成功完成!")
}

// createProgressBar creates a visual progress bar / 创建可视化进度条
func createProgressBar(progress float64, width int) string {
	if progress > 100 {
		progress = 100
	}
	if progress < 0 {
		progress = 0
	}

	filled := int(progress * float64(width) / 100)
	bar := "["

	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	bar += "]"
	return bar
}
