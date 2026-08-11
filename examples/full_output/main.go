// Full Output Example / 完整数据输出示例
//
// Demonstrates how to obtain the complete request and response of every scan
// step, and how to serialise results to JSON.
//
// 演示如何获取每一步扫描的完整请求/响应报文，以及如何把结果序列化为 JSON。
//
// Run / 运行:
//
//	go run ./examples/full_output
//	go run ./examples/full_output -target https://example.com -json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/zan8in/afrog/v3/examples/internal/examplepath"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("target", "https://scanme.sh", "target to scan")
	pocs := examplepath.PocsFlag()
	asJSON := flag.Bool("json", false, "print results as JSON")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	scanner, err := sdk.New(ctx,
		sdk.WithTargets(*target),
		sdk.WithPocPaths(*pocs),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(10),
		sdk.WithTimeout(10),

		// Enabled by default; shown here to make the knob discoverable.
		// Turn it off on large scans to keep memory bounded.
		// 默认即为开启，这里显式写出以便发现该开关。
		// 大规模扫描时可关闭以控制内存占用。
		sdk.WithRequestResponse(true),

		// Failures used to be invisible; now they can be observed.
		// 执行失败以前完全不可见，现在可以被观察到。
		sdk.WithFailureHandler(func(f sdk.Failure) {
			log.Printf("poc %s failed on %s: %v", f.PocID, f.Target, f.Err)
		}),
	)
	if err != nil {
		log.Fatalf("create scanner / 创建扫描器失败: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil {
		log.Printf("scan finished with error / 扫描出错: %v", err)
	}

	results := scanner.Results()
	if len(results) == 0 {
		fmt.Println("no vulnerabilities found / 未发现漏洞")
		return
	}

	// sdk.Result is JSON serialisable: raw request/response are plain strings,
	// not protobuf []byte fields that would be base64 encoded.
	// sdk.Result 可直接序列化：原始请求/响应是普通字符串，
	// 而不是会被 base64 编码的 protobuf []byte 字段。
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			log.Fatalf("encode json: %v", err)
		}
		return
	}

	for i, v := range results {
		fmt.Printf("\n========== [%d] %s ==========\n", i+1, v.PocID)
		fmt.Printf("name / 名称:     %s\n", v.PocName)
		fmt.Printf("severity / 等级: %s\n", v.Severity)
		fmt.Printf("target / 目标:   %s\n", v.FullTarget)
		if v.CveID != "" {
			fmt.Printf("cve:             %s (cvss %.1f)\n", v.CveID, v.CvssScore)
		}
		for k, val := range v.Extractors {
			fmt.Printf("extractor:       %s = %s\n", k, val)
		}

		for j, ex := range v.Exchanges {
			fmt.Printf("\n--- step %d/%d (matched=%v) ---\n", j+1, len(v.Exchanges), ex.Matched)
			fmt.Printf("%s %s -> %d  (%d ms)\n", ex.Method, ex.URL, ex.StatusCode, ex.LatencyMs)

			fmt.Println("\n>>> REQUEST / 请求")
			fmt.Println(indent(ex.Request))

			fmt.Println("<<< RESPONSE / 响应")
			fmt.Println(indent(ex.Response))

			if ex.BodyTruncated {
				fmt.Println("!! response body was truncated at MaxRespBodySize")
				fmt.Println("!! 响应体在 MaxRespBodySize 上限处被截断，不是完整响应")
			}
			if ex.BruteTruncated {
				fmt.Printf("!! brute force stopped at %d requests / 爆破在 %d 个请求处截断\n",
					ex.BruteRequests, ex.BruteRequests)
			}
		}
	}
}

func indent(s string) string {
	if strings.TrimSpace(s) == "" {
		return "    (empty)"
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}
