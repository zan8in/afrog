package test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// TestBaiduScan 对www.baidu.com进行安全扫描测试
func TestBaiduScan(t *testing.T) {
	// 创建SDK扫描选项
	options := afrog.NewSDKOptions()

	// 设置扫描目标
	options.Targets = []string{"https://www.baidu.com"}

	// 设置POC路径 - 使用项目中的afrog-pocs目录
	pocPath, err := filepath.Abs("../pocs/afrog-pocs")
	if err != nil {
		t.Fatalf("获取POC路径失败: %v", err)
	}
	options.PocFile = pocPath

	// 优化扫描参数 - 对百度友好的配置
	options.Concurrency = 5  // 低并发数，避免对百度造成压力
	options.RateLimit = 30   // 限制请求速率
	options.Timeout = 10     // 超时时间
	options.Retries = 1      // 重试次数
	options.MaxHostError = 3 // 最大错误次数

	// 只扫描指纹识别类POC，避免对目标造成影响
	//options.Search = "fingerprint"
	//options.Severity = "info"

	t.Logf("开始扫描目标: %s", options.Targets[0])
	t.Logf("使用POC路径: %s", options.PocFile)

	// 创建SDK扫描器
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// 测试OOB功能状态
	if oobEnabled, oobMsg := scanner.GetOOBStatus(); oobEnabled {
		t.Logf("OOB状态: ✓ %s", oobMsg)
	} else {
		t.Logf("OOB状态: ✗ %s", oobMsg)
	}

	// 设置结果回调函数
	scanner.OnResult = func(r *result.Result) {
		t.Logf("✓ 发现指纹: %s - %s (严重程度: %s)",
			r.Target,
			r.PocInfo.Info.Name,
			r.PocInfo.Info.Severity)
	}

	// 记录开始时间
	startTime := time.Now()

	// 执行扫描（会自动输出POC数量和目标信息）
	err = scanner.Run()
	if err != nil {
		t.Logf("扫描过程中出现错误: %v", err)
		// 不直接失败，因为网络问题可能导致扫描失败
	}

	// 记录结束时间
	duration := time.Since(startTime)

	// 获取扫描结果和统计信息
	results := scanner.GetResults()
	stats := scanner.GetStats()

	// 输出扫描统计信息
	t.Logf("扫描完成!")
	t.Logf("扫描耗时: %v", duration)
	t.Logf("目标数量: %d", stats.TotalTargets)
	t.Logf("POC数量: %d", stats.TotalPocs)
	t.Logf("总扫描任务: %d", stats.TotalScans)
	t.Logf("完成扫描任务: %d", stats.CompletedScans)
	t.Logf("发现指纹数量: %d", len(results))
	t.Logf("扫描进度: %.1f%%", scanner.GetProgress())

	// 详细输出发现的指纹
	if len(results) > 0 {
		t.Log("发现的指纹详情:")
		for i, result := range results {
			t.Logf("  [%d] %s", i+1, result.PocInfo.Info.Name)
			t.Logf("      目标: %s", result.Target)
			t.Logf("      严重程度: %s", result.PocInfo.Info.Severity)
			if result.PocInfo.Info.Description != "" {
				t.Logf("      描述: %s", result.PocInfo.Info.Description)
			}
		}
	} else {
		t.Log("未发现指纹")
	}
}

// TestBaiduScanWithProgress 带进度显示的百度扫描测试
func TestBaiduScanWithProgress(t *testing.T) {
	// 创建SDK扫描选项
	options := afrog.NewSDKOptions()

	// 设置扫描目标
	options.Targets = []string{"https://www.baidu.com"}

	// 设置POC路径 - 只扫描disclosure类POC
	pocPath, err := filepath.Abs("../pocs/afrog-pocs")
	if err != nil {
		t.Fatalf("获取POC路径失败: %v", err)
	}
	options.PocFile = pocPath

	// 配置扫描参数
	options.Concurrency = 3 // 极低并发
	options.RateLimit = 20  // 极低速率
	options.Timeout = 8
	options.Retries = 1
	options.MaxHostError = 2
	//options.Search = "disclosure" // 只扫描信息泄露
	//options.Severity = "info,low"

	t.Logf("开始带进度显示的扫描...")

	// 创建SDK扫描器
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// 设置进度监控
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()

	// 启动进度监控协程
	go func() {
		for range progressTicker.C {
			progress := scanner.GetProgress()
			if progress > 0 {
				t.Logf("扫描进度: %.1f%%", progress)
			}
		}
	}()

	// 执行扫描
	err = scanner.Run()
	if err != nil {
		t.Logf("扫描过程中出现错误: %v", err)
	}

	// 获取结果和统计信息
	results := scanner.GetResults()
	stats := scanner.GetStats()

	t.Logf("带进度扫描完成:")
	t.Logf("  POC数量: %d", stats.TotalPocs)
	t.Logf("  发现结果: %d 个", len(results))
	t.Logf("  最终进度: %.1f%%", scanner.GetProgress())
	t.Logf("  扫描耗时: %v", stats.EndTime.Sub(stats.StartTime))
}

// TestBaiduScanBasic 基础扫描测试（最简配置）
func TestBaiduScanBasic(t *testing.T) {
	// 检查POC文件是否存在
	pocPath, err := filepath.Abs("../pocs/afrog-pocs/fingerprinting")
	if err != nil {
		t.Fatalf("获取POC路径失败: %v", err)
	}

	// 最简配置
	options := afrog.NewSDKOptions()
	options.Targets = []string{"https://www.baidu.com"}
	options.PocFile = pocPath

	// 极简配置 - 快速测试，对百度友好
	options.Concurrency = 1
	options.RateLimit = 10
	options.Timeout = 5
	options.MaxHostError = 1
	options.Retries = 1
	options.Search = "fingerprint"
	options.Severity = "info"

	t.Log("执行基础扫描测试...")
	t.Logf("POC路径: %s", options.PocFile)

	// 创建并运行SDK扫描器
	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// 简单的结果回调
	resultCount := 0
	scanner.OnResult = func(r *result.Result) {
		resultCount++
		t.Logf("✓ 发现: %s (目标: %s)", r.PocInfo.Info.Name, r.Target)
	}

	// 执行扫描
	if err := scanner.Run(); err != nil {
		t.Logf("扫描过程中出现错误: %v", err)
		// 不直接失败，因为网络问题可能导致扫描失败
	}

	// 输出结果
	results := scanner.GetResults()
	stats := scanner.GetStats()

	t.Logf("基础扫描完成")
	t.Logf("目标数量: %d", stats.TotalTargets)
	t.Logf("POC数量: %d", stats.TotalPocs)
	t.Logf("回调触发次数: %d", resultCount)
	t.Logf("结果数量: %d", len(results))
	t.Logf("扫描进度: %.1f%%", scanner.GetProgress())

	// 验证扫描器基本功能
	if stats.TotalTargets != 1 {
		t.Errorf("期望目标数量为1，实际为%d", stats.TotalTargets)
	}
}

// TestBaiduScanMultipleTargets 多目标扫描测试
func TestBaiduScanMultipleTargets(t *testing.T) {
	options := afrog.NewSDKOptions()

	// 设置多个百度相关目标
	options.Targets = []string{
		"https://www.baidu.com",
		"https://fanyi.baidu.com",
		"https://map.baidu.com",
	}

	pocPath, err := filepath.Abs("../pocs/afrog-pocs/fingerprinting")
	if err != nil {
		t.Fatalf("获取POC路径失败: %v", err)
	}
	options.PocFile = pocPath

	// 配置参数 - 对百度友好的多目标扫描
	options.Concurrency = 2 // 降低并发，避免对百度造成压力
	options.RateLimit = 25  // 降低速率
	options.Timeout = 10
	options.Retries = 1
	options.MaxHostError = 2
	options.Search = "hikvision"
	options.Severity = "High"

	t.Logf("开始多目标扫描，目标数量: %d", len(options.Targets))

	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// 统计每个目标的结果
	targetResults := make(map[string]int)
	scanner.OnResult = func(r *result.Result) {
		targetResults[r.Target]++
		t.Logf("目标 %s 发现指纹: %s", r.Target, r.PocInfo.Info.Name)
	}

	// 记录开始时间
	startTime := time.Now()

	// 执行扫描
	if err := scanner.Run(); err != nil {
		t.Logf("扫描过程中出现错误: %v", err)
	}

	// 输出统计结果
	results := scanner.GetResults()
	stats := scanner.GetStats()
	duration := time.Since(startTime)

	t.Logf("多目标扫描完成:")
	t.Logf("  扫描耗时: %v", duration)
	t.Logf("  总目标数: %d", stats.TotalTargets)
	t.Logf("  总POC数: %d", stats.TotalPocs)
	t.Logf("  总扫描任务: %d", stats.TotalScans)
	t.Logf("  发现指纹数: %d", len(results))
	t.Logf("  扫描进度: %.1f%%", scanner.GetProgress())

	// 按目标统计结果
	t.Log("各目标扫描结果:")
	for _, target := range options.Targets {
		count := targetResults[target]
		t.Logf("  %s: %d 个指纹", target, count)
	}
}

// TestOOBFunctionality 测试OOB功能
func TestOOBFunctionality(t *testing.T) {
	// 创建SDK扫描选项
	options := afrog.NewSDKOptions()
	options.Targets = []string{"https://www.baidu.com"}

	pocPath, err := filepath.Abs("../pocs/afrog-pocs")
	if err != nil {
		t.Fatalf("获取POC路径失败: %v", err)
	}
	options.PocFile = pocPath

	// 基础配置
	options.Concurrency = 1
	options.RateLimit = 10
	options.Timeout = 5

	t.Log("========== 测试OOB功能 ==========")

	// 测试1: 不启用OOB
	t.Log("测试1: 不启用OOB")
	options.EnableOOB = false
	scanner1, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}

	if scanner1.IsOOBEnabled() {
		t.Error("期望OOB未启用，但检测到已启用")
	} else {
		t.Log("✓ OOB正确显示为未启用")
	}

	enabled, msg := scanner1.GetOOBStatus()
	t.Logf("OOB状态: %t, 消息: %s", enabled, msg)
	scanner1.Close()

	// 测试2: 启用OOB但未配置
	t.Log("测试2: 启用OOB但未配置")
	options.EnableOOB = true
	options.OOB = "" // 未配置适配器
	scanner2, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}

	if scanner2.IsOOBEnabled() {
		t.Error("期望OOB未配置，但检测到已配置")
	} else {
		t.Log("✓ OOB正确显示为未配置")
	}

	enabled, msg = scanner2.GetOOBStatus()
	t.Logf("OOB状态: %t, 消息: %s", enabled, msg)
	scanner2.Close()

	// 测试3: 配置OOB（示例配置，可能连接失败）
	t.Log("测试3: 配置OOB（示例配置）")
	options.EnableOOB = true
	options.OOB = "alphalog"
	options.OOBKey = ""
	options.OOBDomain = "callback.red"
	options.OOBApiUrl = "http://callback.red/"

	scanner3, err := afrog.NewSDKScanner(options)
	if err != nil {
		t.Fatalf("创建扫描器失败: %v", err)
	}

	enabled, msg = scanner3.GetOOBStatus()
	t.Logf("OOB状态: %t, 消息: %s", enabled, msg)
	scanner3.Close()

	t.Log("========== OOB功能测试完成 ==========")
}
