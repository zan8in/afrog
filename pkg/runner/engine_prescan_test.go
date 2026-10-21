package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
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
