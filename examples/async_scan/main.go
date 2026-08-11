// Async Scan Example / 异步扫描示例
//
// Demonstrates asynchronous scanning with real-time result streaming.
//
// The scan runs in the background while the main goroutine consumes results as
// they are discovered. Completion is detected with Wait and Done rather than by
// draining the result stream, so each stream has exactly one consumer.
//
// 演示异步扫描与实时结果流。扫描在后台运行，主协程实时消费结果。
// 扫描结束通过 Wait / Done 判断，而不是靠空转结果通道，
// 因此每个通道只有一个消费者，不会出现结果被瓜分的问题。
//
// Run / 运行:
//
//	go run ./examples/async_scan
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

// stats aggregates findings across goroutines.
// stats 跨协程汇总统计。
type stats struct {
	mu       sync.Mutex
	total    int
	bySev    map[string]int
	byTarget map[string]int
}

func newStats() *stats {
	return &stats{bySev: map[string]int{}, byTarget: map[string]int{}}
}

func (s *stats) add(r sdk.Result) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.bySev[r.Severity]++
	s.byTarget[r.Target]++
	return s.total
}

func (s *stats) snapshot() (int, map[string]int, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sev := make(map[string]int, len(s.bySev))
	for k, v := range s.bySev {
		sev[k] = v
	}
	tgt := make(map[string]int, len(s.byTarget))
	for k, v := range s.byTarget {
		tgt[k] = v
	}
	return s.total, sev, tgt
}

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	agg := newStats()

	scanner, err := sdk.New(ctx,
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(8),
		sdk.WithRateLimit(30),
		sdk.WithTimeout(12),
	)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// Subscribe before starting so that no early result is missed. A stream
	// publishes nothing until it is subscribed to, so an unused one is free.
	// 在启动前订阅，避免漏掉早期结果。未被订阅的流不会产生任何开销。
	resultCh := scanner.ResultStream()

	if err := scanner.Start(ctx); err != nil {
		log.Fatalf("start scan / 启动扫描失败: %v", err)
	}

	var wg sync.WaitGroup

	// Consumer: the sole reader of the result stream.
	// 消费者：结果流的唯一读取方。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range resultCh {
			n := agg.add(r)
			fmt.Printf("\n[%d] %s  %s [%s]\n", n, r.Target, r.PocName, r.Severity)
		}
	}()

	// Progress reporter, terminated by Done.
	// 进度输出，由 Done 通道终止。
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st := scanner.Stats()
				fmt.Printf("\r[progress / 进度] %.1f%% | %d/%d | vulns %d",
					scanner.Progress(), st.CompletedScans, st.TotalScans, st.FoundVulns)
			case <-scanner.Done():
				return
			}
		}
	}()

	// Wait returns the real scan error instead of always nil.
	// Wait 返回真实的扫描错误，而不是恒为 nil。
	if err := scanner.Wait(ctx); err != nil {
		log.Printf("\nscan finished with error / 扫描出错: %v", err)
	}
	wg.Wait()

	total, bySev, byTarget := agg.snapshot()
	final := scanner.Stats()

	fmt.Printf("\n\n========== Async Scan Results / 异步扫描结果 ==========\n")
	fmt.Printf("vulnerabilities / 漏洞总数: %d\n", total)
	fmt.Printf("completed scans / 完成任务: %d\n", final.CompletedScans)
	fmt.Printf("duration / 耗时: %v\n", final.Duration())

	if len(bySev) > 0 {
		fmt.Println("\nby severity / 按严重程度:")
		for sev, n := range bySev {
			fmt.Printf("  %s: %d\n", sev, n)
		}
	}
	if len(byTarget) > 0 {
		fmt.Println("\nby target / 按目标:")
		for t, n := range byTarget {
			fmt.Printf("  %s: %d\n", t, n)
		}
	}
}
