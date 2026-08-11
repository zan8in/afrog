// OOB (Out-of-Band) Scan Example / OOB（带外）扫描示例
//
// Demonstrates configuring out-of-band detection and telling OOB findings
// apart from ordinary ones.
//
// 演示如何配置带外检测，以及如何区分 OOB 漏洞与普通漏洞。
//
// afrog v3 expresses OOB with the {{oob.DNS}} / {{oob.HTTP}} placeholders and
// the oobCheck() expression, for example:
//
//	rules:
//	  r0:
//	    request:
//	      method: GET
//	      path: /?dns=ping%20{{oob.DNS}}
//	    expression: oobCheck(oob.ProtocolDNS, 5)
//
// afrog v3 使用 {{oob.DNS}} / {{oob.HTTP}} 占位符配合 oobCheck() 表达式描述 OOB。
// v2 时代的 `set: oob/reverse` 与 oobWait() 写法均已废弃。
//
// Run / 运行:
//
//	go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
//	go run ./examples/oob_scan -oob ceyeio -oob-key TOKEN -oob-domain xxx.ceye.io
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	adapter := flag.String("oob", "dnslogcn", "oob adapter: ceyeio|dnslogcn|alphalog|xray|revsuit")
	key := flag.String("oob-key", "", "oob api key / token")
	domain := flag.String("oob-domain", "", "oob domain")
	apiURL := flag.String("oob-api-url", "", "oob api url")
	httpURL := flag.String("oob-http-url", "", "oob http url")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Handlers run on scan workers, so the counters must be atomic.
	// 回调运行在扫描工作协程上，计数器必须使用原子操作。
	var oobVulns, normalVulns atomic.Int64

	scanner, err := sdk.New(ctx,
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(10),
		sdk.WithTimeout(15),
		sdk.WithOOB(sdk.OOBOptions{
			Adapter: *adapter,
			Key:     *key,
			Domain:  *domain,
			ApiURL:  *apiURL,
			HttpURL: *httpURL,
		}),
		sdk.WithResultHandler(func(r sdk.Result) {
			if isOOBFinding(r) {
				oobVulns.Add(1)
				fmt.Printf("\n[OOB vulnerability / OOB 漏洞]\n")
			} else {
				normalVulns.Add(1)
				fmt.Printf("\n[standard vulnerability / 标准漏洞]\n")
			}
			fmt.Printf("  target / 目标: %s\n", r.FullTarget)
			fmt.Printf("  poc:           %s (%s)\n", r.PocName, r.Severity)
		}),
	)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	// OOBStatus performs a live connectivity probe against the OOB service.
	// OOBStatus 会对 OOB 服务发起一次真实的连通性探测。
	if enabled, status := scanner.OOBStatus(); enabled {
		fmt.Printf("OOB status / OOB 状态: %s\n", status)
	} else {
		fmt.Printf("OOB status / OOB 状态: %s\n", status)
		fmt.Println("OOB PoCs will not produce findings / OOB 类 PoC 将无法产出结果")
	}

	if err := scanner.Execute(ctx); err != nil {
		log.Printf("scan finished with error / 扫描出错: %v", err)
	}

	results := scanner.Results()
	fmt.Printf("\n========== OOB Scan Results / OOB 扫描结果 ==========\n")
	fmt.Printf("total / 总数:      %d\n", len(results))
	fmt.Printf("oob / OOB 漏洞:    %d\n", oobVulns.Load())
	fmt.Printf("standard / 普通:   %d\n", normalVulns.Load())

	bySeverity := map[string]int{}
	for _, v := range results {
		bySeverity[v.Severity]++
	}
	for sev, n := range bySeverity {
		fmt.Printf("  %s: %d\n", sev, n)
	}
}

// isOOBFinding reports whether a finding came from out-of-band detection.
//
// An OOB PoC embeds an {{oob.*}} placeholder in the request, so the evidence
// is visible in the raw request that the SDK returns.
//
// isOOBFinding 判断结果是否来自带外检测。OOB 类 PoC 会在请求中嵌入
// {{oob.*}} 占位符，因此可以直接在 SDK 返回的原始请求里看到痕迹。
func isOOBFinding(r sdk.Result) bool {
	for _, ex := range r.Exchanges {
		if strings.Contains(strings.ToLower(ex.Request), ".oob.") ||
			strings.Contains(strings.ToLower(ex.Request), "dnslog") ||
			strings.Contains(strings.ToLower(ex.Request), "ceye.io") {
			return true
		}
	}
	for k := range r.Extractors {
		if strings.HasPrefix(strings.ToLower(k), "oob") {
			return true
		}
	}
	return false
}
