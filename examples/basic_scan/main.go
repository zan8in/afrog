package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/zan8in/afrog/v3"
)

// Basic Scan Example / 基础扫描示例
//
// This example demonstrates the most basic usage of the Afrog SDK.
// It performs a simple vulnerability scan on a target URL.
//
// 此示例演示了 Afrog SDK 的最基本用法。
// 它对目标 URL 执行简单的漏洞扫描。

func main() {
	// Create SDK scan options / 创建 SDK 扫描选项
	options := afrog.NewSDKOptions()

	// Set scan targets / 设置扫描目标
	options.Targets = []string{"https://www.example.com"}

	// Set POC path (required) / 设置 POC 路径（必需）
	pocPath, err := filepath.Abs("../pocs/afrog-pocs")
	if err != nil {
		log.Fatalf("Failed to get POC path / 获取 POC 路径失败: %v", err)
	}
	options.PocFile = pocPath

	// Basic configuration / 基础配置
	options.Concurrency = 10  // Concurrent threads / 并发线程数
	options.RateLimit = 50    // Request rate limit / 请求速率限制
	options.Timeout = 10      // Timeout in seconds / 超时时间（秒）
	options.Search = "info"   // Search for info-level POCs / 搜索信息级别的 POC
	options.Severity = "info" // Only scan info severity / 只扫描信息严重级别

	fmt.Println("Creating SDK scanner... / 创建 SDK 扫描器...")

	// Create scanner instance / 创建扫描器实例
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		log.Fatalf("Failed to create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close() // Always close the scanner / 始终关闭扫描器

	fmt.Println("Starting scan... / 开始扫描...")

	// Execute scan (synchronous) / 执行扫描（同步）
	err = scanner.Run()
	if err != nil {
		log.Printf("Scan error occurred / 扫描出现错误: %v", err)
	}

	// Get scan results / 获取扫描结果
	results := scanner.GetResults()
	stats := scanner.GetStats()

	// Print results / 打印结果
	fmt.Printf("\n========== Scan Results / 扫描结果 ==========\n")
	fmt.Printf("Vulnerabilities found / 发现漏洞: %d\n", len(results))
	fmt.Printf("Scan progress / 扫描进度: %.1f%%\n", scanner.GetProgress())
	fmt.Printf("Scan duration / 扫描耗时: %v\n", stats.EndTime.Sub(stats.StartTime))

	// Display vulnerability details / 显示漏洞详情
	if len(results) > 0 {
		fmt.Printf("\n========== Vulnerability Details / 漏洞详情 ==========\n")
		for i, result := range results {
			fmt.Printf("%d. Target / 目标: %s\n", i+1, result.Target)
			fmt.Printf("   POC Name / POC 名称: %s\n", result.PocInfo.Info.Name)
			fmt.Printf("   Severity / 严重程度: %s\n", result.PocInfo.Info.Severity)
			fmt.Printf("   Description / 描述: %s\n", result.PocInfo.Info.Description)
			fmt.Println("   ---")
		}
	} else {
		fmt.Println("No vulnerabilities found / 未发现漏洞")
	}

	fmt.Println("Scan completed! / 扫描完成!")
}
