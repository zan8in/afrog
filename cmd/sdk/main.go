// Command sdk is a minimal CI security gate built on the afrog SDK.
//
// It scans a target and exits non-zero when a vulnerability is found.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	target := flag.String("t", "https://scanme.sh", "target to scan")
	pocs := flag.String("pocs", "", "PoC file, directory or glob pattern (empty = built-in PoCs)")
	severity := flag.String("severity", "", "severity filter, e.g. \"high,critical\"")
	proxy := flag.String("proxy", "", "HTTP/SOCKS5 proxy")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	found, err := run(ctx, *target, *pocs, *severity, *proxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "afrog: %v\n", err)
		os.Exit(1)
	}
	if found {
		os.Exit(1)
	}
}

func run(ctx context.Context, target, pocs, severity, proxy string) (bool, error) {
	options := []sdk.Option{sdk.WithTargets(target)}
	if pocs != "" {
		options = append(options, sdk.WithPocPaths(pocs), sdk.WithPocPathsOnly())
	}
	if severity != "" {
		options = append(options, sdk.WithSeverity(severity))
	}
	if proxy != "" {
		options = append(options, sdk.WithProxy(proxy))
	}

	scanner, err := sdk.New(ctx, options...)
	if err != nil {
		return false, err
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil {
		return false, err
	}

	results := scanner.Results()
	if len(results) == 0 {
		fmt.Println("security check passed / 安全检查通过")
		return false, nil
	}

	fmt.Printf("found %d vulnerabilities / 发现 %d 个漏洞\n", len(results), len(results))
	for _, v := range results {
		fmt.Printf("- [%s] %s: %s\n", v.Severity, v.FullTarget, v.PocName)
	}
	return true, nil
}
