// SDK Port Pre-Scan Example / SDK 端口预扫描示例
//
// Demonstrates running a port pre-scan before the PoC scan. Discovered open
// ports are appended to the target set as host:port, so subsequent PoCs run
// against the expanded target list.
//
// 演示在 PoC 扫描前先做端口预扫描。发现的开放端口会以 host:port 形式
// 追加进目标集合，后续 PoC 按扩展后的目标列表执行。
//
// Run / 运行:
//
//	go run ./examples/sdk_portscan -target 127.0.0.1
//	go run ./examples/sdk_portscan -target 127.0.0.1 -async
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "127.0.0.1", "target to scan")
	targetFile := flag.String("target-file", "", "file with one target per line")
	pocs := examplepath.PocsFlag()
	ports := flag.String("ports", "top", "ports: top|full|all|80,443|1-1024")
	async := flag.Bool("async", false, "run asynchronously and consume the port stream")
	search := flag.String("search", "", "poc search keyword")
	severity := flag.String("severity", "", "severity filter")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Guards stdout, which handlers write to from scan workers.
	// 保护 stdout：回调会从扫描工作协程并发写入。
	var mu sync.Mutex

	options := []sdk.Option{
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithPortScan(sdk.PortScanOptions{
			Ports:     *ports,
			TimeoutMs: 500,
		}),
	}
	if *targetFile != "" {
		options = append(options, sdk.WithTargetsFile(*targetFile))
	} else {
		options = append(options, sdk.WithTargets(*target))
	}
	if *search != "" {
		options = append(options, sdk.WithSearch(*search))
	}
	if *severity != "" {
		options = append(options, sdk.WithSeverity(*severity))
	}
	if !*async {
		options = append(options, sdk.WithPortHandler(func(p sdk.PortEvent) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Printf("[open] %s:%d\n", p.Host, p.Port)
		}))
	}

	scanner, err := sdk.New(ctx, options...)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	if *async {
		// Subscribe before Start. Once subscribed the stream must be consumed:
		// sends block when the buffer fills so that no open port is dropped.
		// 在 Start 之前订阅。订阅后必须消费：缓冲写满时发送会阻塞，
		// 以保证开放端口不被静默丢弃。
		ports := scanner.PortStream()

		if err := scanner.Start(ctx); err != nil {
			log.Fatalf("start scan / 启动扫描失败: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				fmt.Printf("[open] %s:%d\n", p.Host, p.Port)
			}
		}()

		if err := scanner.Wait(ctx); err != nil {
			log.Printf("scan finished with error / 扫描出错: %v", err)
		}
		wg.Wait()
	} else {
		if err := scanner.Execute(ctx); err != nil {
			log.Printf("scan finished with error / 扫描出错: %v", err)
		}
	}

	fmt.Println("\n========== Open Ports / 开放端口 ==========")
	open := scanner.OpenPorts()
	hosts := make([]string, 0, len(open))
	for h := range open {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, h := range hosts {
		ps := open[h]
		sort.Ints(ps)
		for _, p := range ps {
			fmt.Printf("%s:%d\n", h, p)
		}
	}

	if results := scanner.Results(); len(results) > 0 {
		fmt.Println("\n========== Vulnerabilities / 漏洞 ==========")
		for _, v := range results {
			fmt.Printf("[%s] %s - %s\n", v.Severity, v.FullTarget, v.PocName)
		}
	}
}
