package mcp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/policy"
)

func TestCountProbePorts(t *testing.T) {
	cases := []struct {
		spec string
		want int
	}{
		{"", 100},
		{"top100", 100},
		{"top1000", 1000},
		{"full", 65535},
		{"80", 1},
		{"80,443", 2},
		{"8000-8002", 3},
		{"80, 443 , 8000-8001", 4},
	}
	for _, tc := range cases {
		got, err := countProbePorts(tc.spec)
		if err != nil {
			t.Fatalf("countProbePorts(%q): %v", tc.spec, err)
		}
		if got != tc.want {
			t.Fatalf("countProbePorts(%q) = %d, want %d", tc.spec, got, tc.want)
		}
	}

	for _, bad := range []string{"abc", "0", "70000", "8000-7999", "topabc"} {
		if _, err := countProbePorts(bad); err == nil {
			t.Fatalf("countProbePorts(%q) should fail", bad)
		}
	}
}

func TestProbeHostExtraction(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5":                  "10.0.0.5",
		"10.0.0.5:8080":             "10.0.0.5",
		"http://a.example:8080/api": "a.example",
		"[::1]:8080":                "::1",
	}
	for in, want := range cases {
		got, err := probeHost(in)
		if err != nil {
			t.Fatalf("probeHost(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("probeHost(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := probeHost("  "); err == nil {
		t.Fatal("empty host should fail")
	}
}

// probe.port 用真实监听端口验证「开放端口会被报告」，并确认预算是按端口数扣的。
func TestProbePortToolFindsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	out, err := s.tools["probe.port"].Handler(context.Background(), mustJSON(t, map[string]any{
		"host":  "127.0.0.1",
		"ports": strconv.Itoa(port),
	}))
	if err != nil {
		t.Fatalf("probe.port: %v", err)
	}

	res := out.(map[string]any)
	if res["scanned"] != 1 {
		t.Fatalf("scanned = %v, want 1", res["scanned"])
	}
	open, ok := res["open"].([]map[string]any)
	if !ok || len(open) != 1 {
		t.Fatalf("open = %#v, want the listening port", res["open"])
	}
	if open[0]["port"] != port {
		t.Fatalf("open port = %v, want %d", open[0]["port"], port)
	}
	if got := s.gate.Budget().Remaining(); got != 19 {
		t.Fatalf("budget remaining = %d, want 19", got)
	}
}

// 全端口扫描不该从一次 MCP 调用里发起：超限要在扣预算之前拒绝。
func TestProbePortToolRejectsTooManyPorts(t *testing.T) {
	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20000\n  duration: 2m\n")

	_, err := s.tools["probe.port"].Handler(context.Background(), mustJSON(t, map[string]any{
		"host":  "127.0.0.1",
		"ports": "1-2000",
	}))
	if err == nil || !strings.Contains(err.Error(), "above the") {
		t.Fatalf("err = %v, want the port limit", err)
	}
	if got := s.gate.Budget().Remaining(); got != 20000 {
		t.Fatalf("budget touched by rejected call: %d", got)
	}
}

func TestProbeFingerprintToolMatchesTech(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		_, _ = w.Write([]byte(`<html><head><title>Console</title>` +
			`<meta name="generator" content="WordPress 6.4.2" /></head><body>ok</body></html>`))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	out, err := s.tools["probe.fingerprint"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": srv.URL,
	}))
	if err != nil {
		t.Fatalf("probe.fingerprint: %v", err)
	}

	res := out.(map[string]any)
	if res["status"] != 200 {
		t.Fatalf("status = %v, want 200", res["status"])
	}
	if res["title"] != "Console" {
		t.Fatalf("title = %v, want Console", res["title"])
	}
	if res["server"] != "nginx/1.25.3" || res["powered_by"] != "PHP/8.2.1" {
		t.Fatalf("headers not surfaced: %+v", res)
	}

	names := make(map[string]string, 4)
	for _, item := range res["technologies"].([]map[string]any) {
		names[item["name"].(string)] = item["version"].(string)
	}
	if names["Nginx"] != "1.25.3" {
		t.Fatalf("Nginx missing/wrong version: %+v", names)
	}
	if names["WordPress"] != "6.4.2" {
		t.Fatalf("WordPress missing/wrong version: %+v", names)
	}
	// suggested_search 由规则 id / 技术名等标识词拼成，且不带 category
	// （category 太宽，如 cms 会命中上百条 PoC）。
	suggested, _ := res["suggested_search"].(string)
	for _, want := range []string{"nginx", "wordpress"} {
		if !strings.Contains(suggested, want) {
			t.Fatalf("suggested_search = %q, want token %q", suggested, want)
		}
	}
	if strings.Contains(suggested, "web-server") {
		t.Fatalf("suggested_search must not carry category tokens: %q", suggested)
	}
	if got := s.gate.Budget().Remaining(); got != 19 {
		t.Fatalf("budget remaining = %d, want 19", got)
	}
}

// apache-httpd 这类规则的 id/name 在 PoC 语料里是死词（没人这么写），靠 search_tags
// 手写别名接回真实关键词（apache）。这里验证别名一路流到 suggested_search。
func TestProbeFingerprintSuggestedSearchCarriesSearchTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Unix)")
		_, _ = w.Write([]byte(`<html><head><title>It works!</title></head><body>ok</body></html>`))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	out, err := s.tools["probe.fingerprint"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": srv.URL,
	}))
	if err != nil {
		t.Fatalf("probe.fingerprint: %v", err)
	}
	suggested, _ := out.(map[string]any)["suggested_search"].(string)
	if !strings.Contains(suggested, "apache") {
		t.Fatalf("suggested_search = %q, want it to carry the search_tag apache", suggested)
	}
}

// 首页识别不出任何技术栈时，应自动补抓一次 /favicon.ico 再匹配（多一次请求、多一次预算）。
func TestProbeFingerprintAutoFetchesFaviconWhenNoTech(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte("\x00\x01\x02favicon-bytes"))
			return
		}
		// 首页给一个完全不携带指纹素材的响应：无 Server 头、无正文技术特征。
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	out, err := s.tools["probe.fingerprint"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": srv.URL,
	}))
	if err != nil {
		t.Fatalf("probe.fingerprint: %v", err)
	}
	res := out.(map[string]any)
	if techs, _ := res["technologies"].([]map[string]any); len(techs) != 0 {
		t.Fatalf("precondition failed: homepage should yield no tech, got %+v", techs)
	}
	if res["favicon_fetched"] != true {
		t.Fatalf("favicon_fetched = %v, want true", res["favicon_fetched"])
	}
	if res["favicon_hash"] == "" {
		t.Fatalf("favicon_hash empty after auto fetch: %+v", res)
	}
	// 首页 1 次 + 自动补抓 favicon 1 次 = 2。
	if got := s.gate.Budget().Remaining(); got != 18 {
		t.Fatalf("budget remaining = %d, want 18", got)
	}
}

// WAF 识别与跳转链是 probe.fingerprint 相对 probe.http 的增量价值。
func TestProbeFingerprintReportsWAFAndRedirects(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Iinfo", "9-12345-12346")
		_, _ = w.Write([]byte(`<html><body>guarded</body></html>`))
	}))
	t.Cleanup(final.Close)

	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(entry.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	out, err := s.tools["probe.fingerprint"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": entry.URL,
	}))
	if err != nil {
		t.Fatalf("probe.fingerprint: %v", err)
	}

	res := out.(map[string]any)
	if res["url"] != final.URL {
		t.Fatalf("final url = %v, want %s", res["url"], final.URL)
	}
	redirects, _ := res["redirects"].([]string)
	if len(redirects) != 1 || redirects[0] != final.URL {
		t.Fatalf("redirects = %v, want [%s]", redirects, final.URL)
	}
	waf, _ := res["waf"].([]string)
	if len(waf) == 0 {
		t.Fatalf("waf not detected: %+v", res)
	}
}

// 只读策略下 probe.* 必须被拒绝，且不扣预算。
func TestProbeToolsDeniedInReadOnly(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"probe.port", map[string]any{"host": "127.0.0.1", "ports": "80"}},
		{"probe.fingerprint", map[string]any{"url": "http://127.0.0.1:1"}},
	} {
		if _, err := s.tools[tc.tool].Handler(context.Background(), mustJSON(t, tc.args)); err == nil ||
			!strings.Contains(err.Error(), "policy denied") {
			t.Fatalf("%s err = %v, want policy denial", tc.tool, err)
		}
	}
	if got := s.gate.Budget().Remaining(); got != policy.DefaultRequests {
		t.Fatalf("budget after denial = %d, want %d", got, policy.DefaultRequests)
	}
}
