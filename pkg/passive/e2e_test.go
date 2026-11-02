package passive_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/sqli"
	"github.com/zan8in/afrog/v3/pkg/passive/proxy"
)

// TestEndToEndProxyToFinding 验证「代理 → 调度 → SQLi 检测 → Finding」整条管道。
//
// 这是分层设计是否真的解耦的唯一硬证据：三个包各自独立，只有在这里被串起来。
func TestEndToEndProxyToFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end pipeline is slow")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'") {
			fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n</ul>\n</body>\n</html>\n")
			return
		}
		fmt.Fprint(w, "<html>\n<body>\n<h1>List</h1>\n<ul>\n<li>ITEM-A</li>\n<li>ITEM-B</li>\n</ul>\n</body>\n</html>\n")
	}))
	defer target.Close()

	findings := make(chan passive.Finding, 4)

	engine := passive.NewEngine(passive.EngineOptions{
		Detectors: []passive.Detector{sqli.New(sqli.DefaultOptions())},
		Prober:    passive.NewHTTPProber(passive.DefaultProberOptions()),
		OnFinding: func(f passive.Finding) {
			select {
			case findings <- f:
			default:
			}
		},
		Workers:   1,
		QueueSize: 8,
	})
	engine.Start(context.Background())
	defer engine.Close()

	srv, err := proxy.New(proxy.Options{
		Addr:  "127.0.0.1:0",
		CADir: t.TempDir(),
		OnTransaction: func(tx *passive.CapturedTransaction) {
			engine.Submit(tx)
		},
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/list?id=1")
	if err != nil {
		t.Fatalf("get via proxy: %v", err)
	}
	defer resp.Body.Close()

	select {
	case f := <-findings:
		if f.VulnType != "sqli" {
			t.Fatalf("vuln type = %q, want sqli", f.VulnType)
		}
		if f.Confidence != passive.ConfidenceCertain {
			t.Fatalf("confidence = %s, want certain", f.Confidence)
		}
		if f.Location != "query:id" {
			t.Errorf("location = %q, want query:id", f.Location)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("no finding produced by the full pipeline; stats=%+v", engine.Stats())
	}
}
