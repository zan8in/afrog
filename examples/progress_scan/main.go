// Progress Scan Example / 带进度条的扫描示例
//
// Demonstrates monitoring scan progress in real time while the scan runs in
// the background.
//
// 演示在扫描后台运行的同时实时监控进度。
//
// Run / 运行:
//
//	go run ./examples/progress_scan
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Handlers are invoked concurrently from scan workers, so shared state
	// (here: stdout) needs a lock.
	// 回调由扫描工作协程并发触发，共享状态（这里是 stdout）需要加锁。
	var mu sync.Mutex

	scanner, err := sdk.New(ctx,
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(5),
		sdk.WithRateLimit(20),
		sdk.WithTimeout(15),
		sdk.WithResultHandler(func(r sdk.Result) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Printf("\n[found / 发现] %s - %s [%s]\n", r.Target, r.PocName, r.Severity)
		}),
	)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	start := time.Now()
	if err := scanner.Start(ctx); err != nil {
		log.Fatalf("start scan / 启动扫描失败: %v", err)
	}

	// The progress goroutine terminates on Done, so no sleep-based
	// synchronisation is needed.
	// 进度协程由 Done 通道终止，不需要用 sleep 做同步。
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st := scanner.Stats()
				percent := scanner.Progress()
				mu.Lock()
				fmt.Printf("\r[progress / 进度] %s %.2f%% (%d/%d) found / 发现: %d",
					progressBar(percent, 40), percent, st.CompletedScans, st.TotalScans, st.FoundVulns)
				mu.Unlock()
			case <-scanner.Done():
				return
			}
		}
	}()

	if err := scanner.Wait(ctx); err != nil {
		log.Printf("\nscan finished with error / 扫描出错: %v", err)
	}
	wg.Wait()

	results := scanner.Results()
	st := scanner.Stats()

	fmt.Printf("\n\n========== Scan Completed / 扫描完成 ==========\n")
	fmt.Printf("targets / 目标数:   %d\n", st.TotalTargets)
	fmt.Printf("pocs / PoC 数:      %d\n", st.TotalPocs)
	fmt.Printf("tasks / 任务数:     %d/%d\n", st.CompletedScans, st.TotalScans)
	fmt.Printf("vulnerabilities:    %d\n", len(results))
	fmt.Printf("duration / 耗时:    %v\n", time.Since(start))

	bySeverity := map[string]int{}
	for _, v := range results {
		bySeverity[v.Severity]++
	}
	for sev, n := range bySeverity {
		fmt.Printf("  %s: %d\n", sev, n)
	}
}

// progressBar renders a textual progress bar of the given width.
func progressBar(percent float64, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := int(percent * float64(width) / 100)
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}
