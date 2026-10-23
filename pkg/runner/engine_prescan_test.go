package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/webscan"
)

func TestOpenPortsCollector_ConcurrentAdd(t *testing.T) {
	c := newOpenPortsCollector()

	const goroutines = 50
	const perG = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(worker int) {
			defer wg.Done()
			host := "h" + string(rune('a'+(worker%10)))
			for p := 0; p < perG; p++ {
				c.Add(host, p)
			}
		}(i)
	}
	wg.Wait()

	snap := c.Snapshot()
	total := 0
	for _, ports := range snap {
		total += len(ports)
	}
	if total != goroutines*perG {
		t.Fatalf("expected %d collected ports, got %d", goroutines*perG, total)
	}
}

func TestOpenPortsCollectorAddResult(t *testing.T) {
	c := newOpenPortsCollector()
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 8080, ServiceInfo: portscan.ServiceInfo{Service: "http", TLS: false}})
	// 同一端口的重复结果不应覆盖首次记录
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 8080, ServiceInfo: portscan.ServiceInfo{Service: "https", TLS: true}})

	snap := c.Snapshot()
	if got := len(snap["10.0.0.1"]); got != 2 {
		t.Fatalf("expected 2 entries for host, got %d", got)
	}
	got := c.Result("10.0.0.1", 8080)
	if got == nil {
		t.Fatal("expected fact for 10.0.0.1:8080, got nil")
	}
	if got.Service != "http" {
		t.Fatalf("first result should win, got service=%q", got.Service)
	}
	if c.Result("10.0.0.1", 22) != nil {
		t.Fatal("expected nil fact for unscanned port")
	}
}

func TestWebProbeScheme(t *testing.T) {
	tests := []struct {
		name       string
		fact       *portscan.ScanResult
		wantScheme string
		wantOK     bool
	}{
		{name: "no fact", fact: nil, wantScheme: "", wantOK: true},
		{
			name:       "https prior",
			fact:       &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "https", TLS: true}},
			wantScheme: "https", wantOK: true,
		},
		{
			name:       "http service",
			fact:       &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "http"}},
			wantScheme: "http", wantOK: true,
		},
		{
			name:       "web-ish service",
			fact:       &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "webmail", TLS: true}},
			wantScheme: "https", wantOK: true,
		},
		{
			name:   "mysql is skipped",
			fact:   &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "mysql"}},
			wantOK: false,
		},
		{
			name:   "ssh is skipped",
			fact:   &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "ssh"}},
			wantOK: false,
		},
		{
			name:       "tls service is never skipped",
			fact:       &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{Service: "kubernetes", TLS: true}},
			wantScheme: "https", wantOK: true,
		},
		{
			name:       "unknown service falls back to http",
			fact:       &portscan.ScanResult{ServiceInfo: portscan.ServiceInfo{}},
			wantScheme: "http", wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, ok := webProbeScheme(tt.fact)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want=%v", ok, tt.wantOK)
			}
			if scheme != tt.wantScheme {
				t.Fatalf("scheme=%q want=%q", scheme, tt.wantScheme)
			}
		})
	}
}

func TestWebProbeUsesPortFacts(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Server", "nginx")
		_, _ = w.Write([]byte("<html><head><title>hit</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	hostPort := net.JoinHostPort(host, portStr)

	hitCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}
	newRunner := func() *Runner {
		return &Runner{
			options: &config.Options{
				Timeout:         5,
				Retries:         0,
				MaxRespBodySize: 2,
				RateLimit:       10,
				Concurrency:     1,
				SDKMode:         true,
				Silent:          true,
			},
			ctx:          context.Background(),
			webURLByKey:  make(map[string]string),
			webMetaByKey: make(map[string]WebMeta),
		}
	}

	t.Run("web fact avoids protocol probe", func(t *testing.T) {
		facts := newOpenPortsCollector()
		facts.AddResult(&portscan.ScanResult{
			Host: host, Port: port,
			ServiceInfo: portscan.ServiceInfo{Service: "http"},
		})
		idx := targets.BuildTargetIndex([]string{hostPort})

		before := hitCount()
		out := newRunner().webProbe(context.Background(), idx, facts)
		if len(out) != 1 || out[0] != "http://"+hostPort {
			t.Fatalf("unexpected webprobe out: %#v", out)
		}
		// 协议已由指纹确定，只应发出一次请求（不再有协议试探）。
		if got := hitCount() - before; got != 1 {
			t.Fatalf("expected exactly 1 request, got %d", got)
		}
	})

	t.Run("non-web fact is skipped", func(t *testing.T) {
		facts := newOpenPortsCollector()
		facts.AddResult(&portscan.ScanResult{
			Host: host, Port: port,
			ServiceInfo: portscan.ServiceInfo{Service: "mysql"},
		})
		idx := targets.BuildTargetIndex([]string{hostPort})

		before := hitCount()
		out := newRunner().webProbe(context.Background(), idx, facts)
		if len(out) != 0 {
			t.Fatalf("expected non-web port to be skipped, got %#v", out)
		}
		if got := hitCount() - before; got != 0 {
			t.Fatalf("expected no request for non-web port, got %d", got)
		}
	})

	t.Run("non-web prior port is skipped without port facts", func(t *testing.T) {
		// 未开 -ps 时 facts 为 nil：此时应靠内置端口先验挡掉 3306 这类惯例非 Web 端口，
		// 而不是盲发一次 HTTP 请求（这正是 -w 默认开启后最容易被诟病的行为）。
		idx := targets.BuildTargetIndex([]string{"127.0.0.1:3306"})

		before := hitCount()
		out := newRunner().webProbe(context.Background(), idx, nil)
		if len(out) != 0 {
			t.Fatalf("expected non-web prior port to be skipped, got %#v", out)
		}
		if got := hitCount() - before; got != 0 {
			t.Fatalf("expected no request for non-web prior port, got %d", got)
		}
	})

	t.Run("tls non-web fact is skipped", func(t *testing.T) {
		// 465 的端口先验是 smtps 且 tls:true，webProbeScheme 会因 TLS 提前判成 https；
		// 但先验明确它不是 Web，应挡掉而不是发出 HTTPS 请求换回 malformed 噪音。
		facts := newOpenPortsCollector()
		facts.AddResult(&portscan.ScanResult{
			Host: host, Port: 465,
			ServiceInfo: portscan.ServiceInfo{Service: "smtps", TLS: true},
		})
		idx := targets.BuildTargetIndex([]string{net.JoinHostPort(host, "465")})

		before := hitCount()
		out := newRunner().webProbe(context.Background(), idx, facts)
		if len(out) != 0 {
			t.Fatalf("expected tls non-web port to be skipped, got %#v", out)
		}
		if got := hitCount() - before; got != 0 {
			t.Fatalf("expected no request for tls non-web port, got %d", got)
		}
	})
}

func TestWebProbeSkipByPrior(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		want     bool
	}{
		{name: "mysql", hostPort: "10.0.0.1:3306", want: true},
		{name: "ssh", hostPort: "10.0.0.1:22", want: true},
		{name: "redis", hostPort: "10.0.0.1:6379", want: true},
		{name: "http prior", hostPort: "10.0.0.1:8080", want: false},
		{name: "https prior", hostPort: "10.0.0.1:8443", want: false},
		// 先验只说明惯例，未登记的端口一律照试：Web 服务可能挂在任意端口上。
		{name: "port without prior", hostPort: "10.0.0.1:65500", want: false},
		{name: "invalid host port", hostPort: "noport", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := webProbeSkipByPrior(tt.hostPort); got != tt.want {
				t.Fatalf("webProbeSkipByPrior(%q) = %v, want %v", tt.hostPort, got, tt.want)
			}
		})
	}
}

func TestWebTechSummaryAndConfidenceLabel(t *testing.T) {
	techs := []WebTech{
		{Name: "PHP", Version: "8.1.2"},
		{Name: "ThinkPHP", Version: "6.0.13"},
		{Name: "  "},
	}
	if got := webTechSummary(techs); got != "PHP 8.1.2, ThinkPHP 6.0.13" {
		t.Fatalf("webTechSummary = %q", got)
	}
	if got := webTechSummary(nil); got != "" {
		t.Fatalf("empty webTechSummary = %q", got)
	}

	labels := map[string]string{
		"certain":  "verified",
		"CERTAIN":  "verified",
		"probable": "likely",
		"":         "",
		"unknown":  "",
	}
	for in, want := range labels {
		if got := webConfidenceLabel(in); got != want {
			t.Fatalf("webConfidenceLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeaderCoveredByTech(t *testing.T) {
	summary := "PHP 8.1.2, ThinkPHP 6.0.13, Apache httpd 2.4.6"
	tests := []struct {
		header string
		want   bool
	}{
		{header: "Apache/2.4.6 (CentOS)", want: true},
		{header: "PHP/8.1.2", want: true},
		{header: "nginx", want: false},
		{header: "", want: false},
	}
	for _, tt := range tests {
		if got := headerCoveredByTech(summary, tt.header); got != tt.want {
			t.Fatalf("headerCoveredByTech(%q, %q) = %v, want %v", summary, tt.header, got, tt.want)
		}
	}
	// 技术栈没有任何命中时，响应头必须原样补打。
	if headerCoveredByTech("", "nginx") {
		t.Fatal("empty tech summary must not cover any header")
	}
}

func TestApplyWebFingerprint(t *testing.T) {
	meta := WebMeta{Server: "nginx"}
	applyWebFingerprint(&meta, webscan.Result{
		Technologies: []webscan.Technology{{
			Name:       "Nginx",
			Version:    "1.25.3",
			Category:   "web-server",
			CPE:        "cpe:/a:igor_sysoev:nginx",
			Confidence: webscan.ConfidenceCertain,
		}},
		Confidence: webscan.ConfidenceCertain,
	})
	if len(meta.Technologies) != 1 {
		t.Fatalf("technologies = %#v, want 1 entry", meta.Technologies)
	}
	got := meta.Technologies[0]
	if got.Name != "Nginx" || got.Version != "1.25.3" || got.Confidence != "certain" {
		t.Fatalf("unexpected technology: %#v", got)
	}
	if meta.Fingerprint != "Nginx 1.25.3" {
		t.Fatalf("fingerprint = %q", meta.Fingerprint)
	}
	if meta.Confidence != "certain" {
		t.Fatalf("confidence = %q", meta.Confidence)
	}

	// 没有指纹命中时必须回落到 Server / X-Powered-By，保持老行为不丢。
	fallback := WebMeta{Server: "nginx", PoweredBy: "PHP/8.1.2"}
	applyWebFingerprint(&fallback, webscan.Result{})
	if fallback.Fingerprint != "nginx,PHP/8.1.2" {
		t.Fatalf("fallback fingerprint = %q", fallback.Fingerprint)
	}
	if fallback.Confidence != "" || len(fallback.Technologies) != 0 {
		t.Fatalf("unexpected fallback state: %#v", fallback)
	}
}

func TestWebAssetSummary(t *testing.T) {
	if got := webAssetSummary(nil); got != "" {
		t.Fatalf("empty summary = %q, want empty", got)
	}

	metas := []WebMeta{
		{Server: "nginx/1.25.3", WAF: "Cloudflare", TLS: &TLSInfo{Issuer: "Let's Encrypt"}},
		{Server: "nginx", WAF: "Cloudflare"},
		{Server: "Apache/2.4.6", TLS: &TLSInfo{Issuer: "DigiCert"}},
	}
	got := webAssetSummary(metas)
	// 同次数按名称升序：DigiCert 排在 Let's Encrypt 之前。
	for _, want := range []string{"assets=3", "https=2", "server: nginx(2), apache(1)", "waf: Cloudflare(2)", "tls: DigiCert(1), Let's Encrypt(1)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q missing %q", got, want)
		}
	}

	// 没有任何可归类信息时只留下资产数，不应出现空的分段。
	bare := webAssetSummary([]WebMeta{{URL: "http://x/"}})
	if bare != "assets=1" {
		t.Fatalf("bare summary = %q, want assets=1", bare)
	}
}

func TestApplyWebFingerprintWAF(t *testing.T) {
	// WAF/CDN 属于「站点前面挡了什么」，必须单独外露，且不能混进技术栈摘要，
	// 否则同一行里会出现两遍 Cloudflare。
	meta := WebMeta{Server: "cloudflare"}
	applyWebFingerprint(&meta, webscan.Result{
		Technologies: []webscan.Technology{
			{Name: "Cloudflare", Category: "cdn", Confidence: webscan.ConfidenceCertain, RuleID: "cloudflare"},
			{Name: "PHP", Version: "8.1.2", Category: "language", Confidence: webscan.ConfidenceCertain},
		},
		Confidence: webscan.ConfidenceCertain,
	})
	if meta.WAF != "Cloudflare" {
		t.Fatalf("waf = %q, want Cloudflare", meta.WAF)
	}
	if meta.Fingerprint != "PHP 8.1.2" {
		t.Fatalf("fingerprint = %q, want PHP only", meta.Fingerprint)
	}

	// 纯 WAF 命中时技术栈摘要为空，摘要回落到响应头，WAF 字段依然独立可见。
	onlyWAF := WebMeta{Server: "Sucuri/Cloudproxy"}
	applyWebFingerprint(&onlyWAF, webscan.Result{
		Technologies: []webscan.Technology{
			{Name: "Sucuri", Category: "waf", Confidence: webscan.ConfidenceCertain, RuleID: "sucuri"},
		},
		Confidence: webscan.ConfidenceCertain,
	})
	if onlyWAF.WAF != "Sucuri" {
		t.Fatalf("waf = %q, want Sucuri", onlyWAF.WAF)
	}
	if onlyWAF.Fingerprint != "Sucuri/Cloudproxy" {
		t.Fatalf("fingerprint = %q, want header fallback", onlyWAF.Fingerprint)
	}
}

func TestWebProbeDetectsWebFingerprint(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2">` +
			`<title>My Site</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	hostPort := net.JoinHostPort(host, portStr)

	r := &Runner{
		options: &config.Options{
			Timeout:         5,
			Retries:         0,
			MaxRespBodySize: 2,
			RateLimit:       10,
			Concurrency:     1,
			SDKMode:         true,
			Silent:          true,
		},
		ctx:          context.Background(),
		webURLByKey:  make(map[string]string),
		webMetaByKey: make(map[string]WebMeta),
	}

	idx := targets.BuildTargetIndex([]string{hostPort})
	out := r.webProbe(context.Background(), idx, nil)
	if len(out) != 1 {
		t.Fatalf("unexpected webprobe out: %#v", out)
	}

	key := fingerprint.KeyFromTarget(out[0])
	r.webMu.Lock()
	meta, ok := r.webMetaByKey[key]
	r.webMu.Unlock()
	if !ok {
		t.Fatalf("no web meta recorded for %q", key)
	}
	if meta.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", meta.Status)
	}
	if meta.Title != "My Site" {
		t.Fatalf("title = %q", meta.Title)
	}
	if meta.Confidence != "certain" {
		t.Fatalf("confidence = %q", meta.Confidence)
	}
	names := make(map[string]string, len(meta.Technologies))
	for _, tech := range meta.Technologies {
		names[tech.Name] = tech.Version
	}
	if names["Nginx"] != "1.25.3" {
		t.Fatalf("technologies = %#v, want Nginx 1.25.3", meta.Technologies)
	}
	if names["WordPress"] != "6.4.2" {
		t.Fatalf("technologies = %#v, want WordPress 6.4.2", meta.Technologies)
	}
	if meta.Fingerprint == "" {
		t.Fatal("fingerprint summary is empty")
	}
}

func TestFingerprintKeyFromTarget(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "example.com:443"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com", "example.com:80"},
		{"http://example.com:8080", "example.com:8080"},
		{"https://example.com:80", "example.com:80"},
		{"", ""},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := fingerprint.KeyFromTarget(tt.in); got != tt.want {
			t.Fatalf("fingerprint.KeyFromTarget(%q)=%q want=%q", tt.in, got, tt.want)
		}
	}
}

func TestRunnerKeyFromTargetWithPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "example.com:443"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com/admin", "example.com:80/admin"},
		{"http://example.com/admin/", "example.com:80/admin"},
		{"http://example.com//admin//", "example.com:80//admin"},
		{"http://example.com/?a=1", "example.com:80"},
		{"http://example.com/admin?a=1", "example.com:80/admin"},
		{"http://example.com:8080/admin", "example.com:8080/admin"},
		{"example.com:80", "example.com:80"},
		{"", ""},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := keyFromTargetWithPath(tt.in); got != tt.want {
			t.Fatalf("keyFromTargetWithPath(%q)=%q want=%q", tt.in, got, tt.want)
		}
	}
}

func TestWebProbeCapturesRedirectsAndTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = w.Write([]byte("<html><head><title>landed</title></head><body>ok</body></html>"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	r := &Runner{
		options: &config.Options{
			Timeout:         5,
			MaxRespBodySize: 2,
			RateLimit:       1000,
			Concurrency:     1,
			SDKMode:         true,
			Silent:          true,
			WebProbeTimeout: 5,
		},
		ctx:          context.Background(),
		webURLByKey:  make(map[string]string),
		webMetaByKey: make(map[string]WebMeta),
	}

	start := srv.URL + "/start"
	idx := targets.BuildTargetIndex([]string{start})
	out := r.webProbe(context.Background(), idx, nil)
	if len(out) != 1 {
		t.Fatalf("unexpected webprobe out: %#v", out)
	}

	r.webMu.Lock()
	meta, ok := r.webMetaByKey[fingerprint.KeyFromTarget(start)]
	r.webMu.Unlock()
	if !ok {
		t.Fatalf("no web meta recorded for %q", start)
	}
	if meta.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", meta.Status)
	}
	if meta.Title != "landed" {
		t.Fatalf("title = %q, want landed (final hop body)", meta.Title)
	}
	if len(meta.Redirects) != 1 || meta.Redirects[0] != srv.URL+"/final" {
		t.Fatalf("redirects = %#v, want [%s]", meta.Redirects, srv.URL+"/final")
	}
	// TLS 证书是同一次请求顺带取回的：https 目标必须有摘要，否则 A3 形同虚设。
	if meta.TLS == nil {
		t.Fatal("tls info is nil for an https target")
	}
	if meta.TLS.NotAfter == "" {
		t.Fatalf("tls info missing not_after: %#v", meta.TLS)
	}
	if meta.TLS.Subject == "" {
		t.Fatalf("tls info missing subject: %#v", meta.TLS)
	}
}

// 端到端串起断点续传的四个环节：探测 → 落盘 → 重载 → 复用。
//
// 单测各覆盖一段，串不起来就证明不了「中断后恢复不会误跳过依赖指纹的 PoC」：
// 第二轮必须一个包都不再发，同时指纹经 requires 门控仍然生效。
func TestWebProbeResumeReusesConclusionsEndToEnd(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	// 真实起一个可识别的站点，并统计被打了几次：恢复后这个计数必须纹丝不动。
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Server", "nginx/1.25.3")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2">` +
			`<title>My Site</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	// 带显式协议的目标：探测阶段不必试探协议，恢复时即可在候选过滤阶段整条剔除。
	// 裸 host:port 要先做一次协议试探才知道最终 URL，那种情形只能等拿到 URL 后再判。
	target := "http://" + net.JoinHostPort(host, portStr)
	key := fingerprint.KeyFromTarget(target)

	newRunner := func(sp *ScanProgress) *Runner {
		return &Runner{
			options: &config.Options{
				Timeout:         5,
				Retries:         0,
				MaxRespBodySize: 2,
				RateLimit:       10,
				Concurrency:     1,
				SDKMode:         true,
				Silent:          true,
				WebProbeTimeout: 5,
			},
			ctx:          context.Background(),
			ScanProgress: sp,
			webURLByKey:  make(map[string]string),
			webMetaByKey: make(map[string]WebMeta),
		}
	}

	// ---- 第一轮：真实探测并写回断点进度 ----
	sp1, err := NewScanProgress("")
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	r1 := newRunner(sp1)
	out1 := r1.webProbe(context.Background(), targets.BuildTargetIndex([]string{target}), nil)
	if len(out1) != 1 {
		t.Fatalf("first pass out = %#v, want 1 url", out1)
	}
	firstHits := atomic.LoadInt32(&hits)
	if firstHits == 0 {
		t.Fatal("first pass sent no request at all")
	}
	r1.webMu.Lock()
	meta1, ok := r1.webMetaByKey[key]
	r1.webMu.Unlock()
	if !ok {
		t.Fatalf("first pass recorded no meta for %q", key)
	}
	if names := webTechNames(meta1.Technologies); len(names) == 0 {
		t.Fatalf("first pass recognized no technology: %#v", meta1)
	}

	// ---- 落盘后按「新进程」语义重载：只认文件，不认内存 ----
	dir := t.TempDir()
	savePath := filepath.Join(dir, "resume.afg")
	if err := sp1.AtomicSave(savePath, 1, 1); err != nil {
		t.Fatalf("AtomicSave: %v", err)
	}
	sp2, err := NewScanProgress(savePath)
	if err != nil {
		t.Fatalf("NewScanProgress(resume): %v", err)
	}
	resumed := sp2.ResumedWebProbes()
	if len(resumed) != 1 {
		t.Fatalf("resumed web probes = %d, want 1 (%#v)", len(resumed), resumed)
	}
	if got := resumed[key]; got.URL != meta1.URL || got.Status != meta1.Status ||
		got.Title != meta1.Title || len(got.Technologies) != len(meta1.Technologies) {
		t.Fatalf("resumed meta lost information:\n got %+v\nwant %+v", got, meta1)
	}

	// ---- 第二轮：一个包都不发，但结论照样灌回引擎 ----
	r2 := newRunner(sp2)
	out2 := r2.webProbe(context.Background(), targets.BuildTargetIndex([]string{target}), nil)
	if len(out2) != 1 {
		t.Fatalf("resume pass out = %#v, want the resumed url", out2)
	}
	if got := atomic.LoadInt32(&hits); got != firstHits {
		t.Fatalf("resume re-probed the target: requests %d -> %d", firstHits, got)
	}

	// ---- 门控：恢复出来的指纹必须让 requires: [wordpress] 放行、让无关的仍然跳过 ----
	r2.webMu.Lock()
	snap := make(map[string]WebMeta, len(r2.webMetaByKey))
	for k, v := range r2.webMetaByKey {
		snap[k] = v
	}
	r2.webMu.Unlock()

	merged := webTechRequires([]string{target}, snap)
	if _, ok := merged[key]["wordpress"]; !ok {
		t.Fatalf("resumed fingerprint did not produce token wordpress: %#v", merged)
	}
	hit := poc.Poc{Info: poc.Info{Requires: []string{"wordpress"}}}
	if shouldSkipRequires(target, hit, keyFromTargetWithPath, merged, false) {
		t.Fatal("requires: [wordpress] was skipped even though the resumed fingerprint matches")
	}
	miss := poc.Poc{Info: poc.Info{Requires: []string{"thinkphp"}}}
	if !shouldSkipRequires(target, miss, keyFromTargetWithPath, merged, false) {
		t.Fatal("requires: [thinkphp] should still be skipped for a WordPress site")
	}

	// ---- 裸 host:port（用户没写协议、也没开 -ps）：同样不许重复发包 ----
	// 它的最终 URL 要先做一次协议试探才知道，但断点 key 只取决于端口，
	// 因此可以在候选过滤阶段提前剔除，一个包都不发。
	bareTarget := net.JoinHostPort(host, portStr)
	beforeBare := atomic.LoadInt32(&hits)

	sp3, err := NewScanProgress("")
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	r3 := newRunner(sp3)
	if out := r3.webProbe(context.Background(), targets.BuildTargetIndex([]string{bareTarget}), nil); len(out) != 1 {
		t.Fatalf("bare first pass out = %#v, want 1 url", out)
	}
	afterBareFirst := atomic.LoadInt32(&hits)
	if afterBareFirst == beforeBare {
		t.Fatal("bare first pass sent no request at all")
	}

	if err := sp3.AtomicSave(savePath, 1, 1); err != nil {
		t.Fatalf("AtomicSave: %v", err)
	}
	sp4, err := NewScanProgress(savePath)
	if err != nil {
		t.Fatalf("NewScanProgress(resume): %v", err)
	}
	if len(sp4.ResumedWebProbes()) != 1 {
		t.Fatalf("bare resumed web probes = %#v, want 1", sp4.ResumedWebProbes())
	}

	r4 := newRunner(sp4)
	if out := r4.webProbe(context.Background(), targets.BuildTargetIndex([]string{bareTarget}), nil); len(out) != 1 {
		t.Fatalf("bare resume out = %#v, want the resumed url", out)
	}
	if got := atomic.LoadInt32(&hits); got != afterBareFirst {
		t.Fatalf("bare resume re-probed the target: requests %d -> %d", afterBareFirst, got)
	}
}
