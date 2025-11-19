package main

import (
	"fmt"
	"os"

	"github.com/zan8in/afrog/v3"
)

func main() {
	options := afrog.NewSDKOptions()
	options.Targets = []string{"http://127.0.0.1:8848"}
	options.PocFile = "./pocs/afrog-pocs"
	options.Severity = "info"
	options.Search = "nacos"
	options.Proxy = "http://127.0.0.1:51024"

	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		os.Exit(1)
	}
	defer scanner.Close()

	scanner.Run()

	if scanner.HasVulnerabilities() {
		fmt.Println("❌ 发现安全漏洞，阻止部署")
		results := scanner.GetResults()
		for _, r := range results {
			fmt.Printf("- %s: %s\n", r.Target, r.PocInfo.Info.Name)
		}
		os.Exit(1)
	}

	fmt.Println("✅ 安全检查通过")
}
