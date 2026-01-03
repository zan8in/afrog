package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sort"

	"github.com/zan8in/afrog/v3"
)

func main() {
	var (
		target     string
		targetFile string
		pocsPath   string
		ports      string
		enablePS   bool
		search     string
		severity   string
	)

	flag.StringVar(&target, "t", "", "target")
	flag.StringVar(&targetFile, "T", "", "targets file")
	flag.StringVar(&pocsPath, "pocs", "", "pocs directory")
	flag.StringVar(&ports, "p", "top", "ports definition for pre-scan")
	flag.BoolVar(&enablePS, "ps", true, "enable pre-scan port scanning")
	flag.StringVar(&search, "s", "__no_such_poc__", "poc search keyword")
	flag.StringVar(&severity, "S", "", "poc severity filter")
	flag.Parse()

	if pocsPath == "" {
		abs, err := filepath.Abs("./pocs/afrog-pocs")
		if err != nil {
			log.Fatalf("pocs path: %v", err)
		}
		pocsPath = abs
	}

	opts := afrog.NewSDKOptions()
	opts.PocFile = pocsPath
	opts.Search = search
	opts.Severity = severity

	if targetFile != "" {
		opts.TargetsFile = targetFile
	} else if target != "" {
		opts.Targets = []string{target}
	} else {
		opts.Targets = []string{"127.0.0.1"}
	}

	opts.PortScan = enablePS
	opts.PSPorts = ports
	opts.PSSkipDiscovery = false
	opts.PSTimeout = 500

	sc, err := afrog.NewSDKScanner(opts)
	if err != nil {
		log.Fatalf("NewSDKScanner: %v", err)
	}
	defer sc.Close()

	sc.OnPort = func(host string, port int) {
		fmt.Printf("[open] %s:%d\n", host, port)
	}

	if err := sc.Run(); err != nil {
		log.Printf("Run: %v", err)
	}

	open := sc.GetOpenPorts()
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
}
