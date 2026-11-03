package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

func TestLoadOrCreateCAPersists(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if string(first.Cert.Raw) != string(second.Cert.Raw) {
		t.Fatalf("CA must persist across restarts, got different certificates")
	}
	if len(first.CertPEM()) == 0 {
		t.Fatalf("CertPEM is empty")
	}
}

func newTestServer(t *testing.T, dir string, got chan<- *passive.CapturedTransaction) *Server {
	t.Helper()
	srv, err := New(Options{
		Addr:  "127.0.0.1:0",
		CADir: dir,
		OnTransaction: func(tx *passive.CapturedTransaction) {
			select {
			case got <- tx:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

func TestProxyCapturesPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>\n<body>ok</body>\n</html>")
	}))
	defer target.Close()

	got := make(chan *passive.CapturedTransaction, 1)
	srv := newTestServer(t, t.TempDir(), got)

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/api?id=1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	tx := waitTx(t, got)
	if tx.Request == nil || tx.Request.URL == nil {
		t.Fatalf("request not captured")
	}
	if tx.Request.URL.Path != "/api" || tx.Request.URL.RawQuery != "id=1" {
		t.Errorf("captured url = %s?%s", tx.Request.URL.Path, tx.Request.URL.RawQuery)
	}
	if tx.Response == nil || tx.Response.Status != 200 {
		t.Errorf("response not captured")
	}
	if len(tx.Response.Body) == 0 {
		t.Errorf("response body empty")
	}
}

func TestProxyMITMCapturesHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>\n<body>secure</body>\n</html>")
	}))
	defer target.Close()

	got := make(chan *passive.CapturedTransaction, 1)
	srv := newTestServer(t, t.TempDir(), got)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(srv.CACertPEM()) {
		t.Fatalf("append ca: failed")
	}

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	resp, err := client.Get(target.URL + "/secure?token=abc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	tx := waitTx(t, got)
	if tx.Request == nil || tx.Request.URL == nil {
		t.Fatalf("request not captured")
	}
	if tx.Request.URL.Scheme != "https" {
		t.Errorf("scheme = %q, want https", tx.Request.URL.Scheme)
	}
	if tx.Request.URL.Path != "/secure" {
		t.Errorf("path = %q, want /secure", tx.Request.URL.Path)
	}
	if tx.Response == nil || tx.Response.Status != 200 {
		t.Errorf("response not captured")
	}
}

func TestProxySkipsStaticAssets(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body{}")
	}))
	defer target.Close()

	got := make(chan *passive.CapturedTransaction, 4)
	srv := newTestServer(t, t.TempDir(), got)

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	select {
	case tx := <-got:
		t.Fatalf("static asset must be skipped, got %+v", tx.Request.URL)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestProxyReportsSkippedStatic 锁定：被放过的静态资源不能静默消失。
// 使用者看到「捕获数不涨」时，需要知道流量是被哪条规则挡住的。
func TestProxyReportsSkippedStatic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body{}")
	}))
	defer target.Close()

	traffic := make(chan passive.TrafficEvent, 4)
	srv, err := New(Options{
		Addr:  "127.0.0.1:0",
		CADir: t.TempDir(),
		OnTraffic: func(ev passive.TrafficEvent) {
			select {
			case traffic <- ev:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	select {
	case ev := <-traffic:
		if ev.Verdict != passive.VerdictSkippedStatic {
			t.Fatalf("verdict = %q, want %q", ev.Verdict, passive.VerdictSkippedStatic)
		}
		if ev.Reason == "" || ev.URL == "" {
			t.Fatalf("跳过的流量必须带上原因与 URL: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("静态资源被跳过时必须上报 TrafficEvent")
	}
}

// TestProxyDeniesUnsafeMethods 锁定：非幂等方法默认不重放。
// 检测会把同一请求重放数十次，PUT/PATCH/DELETE 在真实业务流量上有破坏数据的风险，
// 必须由使用者显式开启才做。
func TestProxyDeniesUnsafeMethods(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body{}")
	}))
	defer target.Close()

	traffic := make(chan passive.TrafficEvent, 4)
	srv, err := New(Options{
		Addr:  "127.0.0.1:0",
		CADir: t.TempDir(),
		OnTraffic: func(ev passive.TrafficEvent) {
			select {
			case traffic <- ev:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest(http.MethodDelete, target.URL+"/api/order?id=1", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer resp.Body.Close()

	select {
	case ev := <-traffic:
		if ev.Verdict != passive.VerdictSkippedMethod {
			t.Fatalf("verdict = %q, want %q", ev.Verdict, passive.VerdictSkippedMethod)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("非幂等方法被跳过时必须上报 TrafficEvent")
	}
}

// TestProxyRespectsScope 锁定：范围外的流量在代理层就被放过，不进调度层。
func TestProxyRespectsScope(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body{}")
	}))
	defer target.Close()

	traffic := make(chan passive.TrafficEvent, 4)
	srv, err := New(Options{
		Addr:  "127.0.0.1:0",
		CADir: t.TempDir(),
		Scope: passive.Scope{HostDeny: []string{"127.0.0.1"}},
		OnTraffic: func(ev passive.TrafficEvent) {
			select {
			case traffic <- ev:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/api/user?id=1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	select {
	case ev := <-traffic:
		if ev.Verdict != passive.VerdictSkippedScope {
			t.Fatalf("verdict = %q, want %q", ev.Verdict, passive.VerdictSkippedScope)
		}
		if ev.Reason == "" {
			t.Fatalf("范围外跳过必须说明原因: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("范围外流量被跳过时必须上报 TrafficEvent")
	}
}

// TestProxyReportsTLSHandshakeError 锁定：客户端不信任根证书时必须上报异常。
// 这是「HTTPS 一条都抓不到」最常见的原因，静默失败会让使用者无从下手。
func TestProxyReportsTLSHandshakeError(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	defer target.Close()

	errs := make(chan error, 4)
	traffic := make(chan passive.TrafficEvent, 8)
	srv, err := New(Options{
		Addr:  "127.0.0.1:0",
		CADir: t.TempDir(),
		OnTraffic: func(ev passive.TrafficEvent) {
			select {
			case traffic <- ev:
			default:
			}
		},
		OnError: func(scope string, e error) {
			if scope != "proxy" {
				return
			}
			select {
			case errs <- e:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	proxyURL, _ := url.Parse("http://" + srv.Addr())
	// 刻意使用系统根证书池：不接受代理签发的证书，握手必然失败。
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target.URL + "/secure?id=1")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("未信任根证书时请求不应成功")
	}

	select {
	case e := <-errs:
		if e == nil || !strings.Contains(e.Error(), "TLS 握手失败") {
			t.Fatalf("异常内容 = %v, 应说明是握手失败并提示信任证书", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("TLS 握手失败必须上报 OnError")
	}

	// CONNECT 只是隧道握手，不应被当作「方法跳过」的请求上报。
	close(traffic)
	for ev := range traffic {
		if ev.Verdict == passive.VerdictSkippedMethod {
			t.Fatalf("CONNECT 不应产生方法跳过记录: %+v", ev)
		}
	}
}

func waitTx(t *testing.T, got <-chan *passive.CapturedTransaction) *passive.CapturedTransaction {
	t.Helper()
	select {
	case tx := <-got:
		return tx
	case <-time.After(5 * time.Second):
		t.Fatalf("transaction not captured before timeout")
		return nil
	}
}
