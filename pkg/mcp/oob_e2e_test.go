package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/ref"
)

// 反向 PoC 的端到端验收：全离线地走完「提议 → 执行 → 真的回连 → 落证据 → 观测回读」。
//
// 三个角色都在本进程里，没有一条网络请求出本机：
//  1. 假 alphalog 平台：实现适配器真正用到的两个接口（GET /get 握手、根路径轮询），
//     外加一个 /hit 供假靶标登记回连；
//  2. 假靶标：收到带 {{oob.HTTP}} 的请求后「被利用」，真的去访问那个反连地址 ——
//     也就是说它把回连登记到平台上，模拟一次真实的带外回连；
//  3. 工具面：走 verify.poc 的正式链路（SDK + 引擎 OOB 轮询 + finalize），
//     凭据只从 afrog-config.yaml 的 reverse 段取，与 CLI 的 -oob alphalog 完全同口径。
//
// 它锁的是整条语义：配了反连后端，反向 PoC 就必须真出证据，而不是静默返回「没命中」。

// fakeAlphalogPlatform 是一个足以骗过 alphalog 适配器的反连平台替身。
type fakeAlphalogPlatform struct {
	srv   *httptest.Server
	token string
	sub   string

	mu   sync.Mutex
	hits []string
}

func newFakeAlphalogPlatform(t *testing.T) *fakeAlphalogPlatform {
	t.Helper()
	p := &fakeAlphalogPlatform{token: "tok-e2e", sub: "oob.test"}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			// 适配器握手：拿 Key / Subdomain，凭它铸出 {rand}.{Subdomain} 形态的地址。
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Key": p.token, "Subdomain": p.sub,
			})
		case "/hit":
			// 假靶标登记一次「目标访问了反连地址」。
			p.record(r.URL.Query().Get("f"))
			w.WriteHeader(http.StatusOK)
		default:
			// 适配器轮询：POST 根路径，期待响应体里能搜到 filter。
			_, _ = io.WriteString(w, p.snapshot())
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeAlphalogPlatform) record(filter string) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return
	}
	p.mu.Lock()
	p.hits = append(p.hits, filter)
	p.mu.Unlock()
}

func (p *fakeAlphalogPlatform) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.hits, "\n")
}

// newOOBCallbackTarget 起一个「会被利用」的假靶标：它把请求里带的反连地址真的访问一遍。
func newOOBCallbackTarget(t *testing.T, platform *fakeAlphalogPlatform) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := strings.TrimSpace(r.URL.Query().Get("http")); v != "" {
			// PoC 注入的是 curl 命令形态：curl http://{filter}。
			raw := strings.TrimSpace(strings.TrimPrefix(v, "curl"))
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				platform.record(u.Host)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeOOBE2EPoc 落一份与 pocs/oob-http.yaml 同形态的反向 PoC。
func writeOOBE2EPoc(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp-oob-e2e.yaml")
	body := `id: mcp-oob-e2e
info:
  name: mcp oob e2e
  author: afrog-test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /?http=curl%20{{oob.HTTP}}
    expression: oobCheck(oob.ProtocolHTTP, 3)
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write oob poc: %v", err)
	}
	return path
}

// newOOBE2EServer 装配工具面：HOME 指向临时目录，afrog-config.yaml 里同时写 curated 开关
// 与 reverse.alphalog 凭据——SDK 侧就是靠这份凭据去连假平台的。
func newOOBE2EServer(t *testing.T, policyYAML, apiURL string) (*Server, *oobSource) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	confDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	conf := "curated:\n  enabled: \"off\"\nreverse:\n  alphalog:\n    domain: oob.test\n    api_url: " + apiURL + "\n"
	if err := os.WriteFile(filepath.Join(confDir, "afrog-config.yaml"), []byte(conf), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	src, err := NewOOBSource("alphalog", config.Reverse{
		Alphalog: config.Alphalog{Domain: "oob.test", ApiUrl: apiURL},
	})
	if err != nil {
		t.Fatalf("new oob source: %v", err)
	}
	if src == nil {
		t.Fatal("NewOOBSource returned nil for a fully configured alphalog")
	}
	concrete, ok := src.(*oobSource)
	if !ok {
		t.Fatalf("oob source = %T, want *oobSource", src)
	}
	t.Cleanup(concrete.Close)

	return New(Options{Policy: p, OOB: src}), concrete
}

// 端到端：反向 PoC 必须凭真实回连拿到证据，并把这次回连写进观测流。
func TestOOBEndToEndAcceptance(t *testing.T) {
	platform := newFakeAlphalogPlatform(t)
	target := newOOBCallbackTarget(t, platform)

	s, _ := newOOBE2EServer(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n", platform.srv.URL)

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	endpoint, err := ref.NormalizeEndpoint(target.URL)
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}

	out, err := s.tools["verify.poc"].Handler(context.Background(),
		mustJSON(t, map[string]any{"poc_path": writeOOBE2EPoc(t), "target": endpoint, "timeout_sec": 30}))
	if err != nil {
		t.Fatalf("verify.poc: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result = %#v, want a map", out)
	}
	if res["found"] != true {
		t.Fatalf("found = %v, want true: the target called back, so the reverse PoC must confirm", res["found"])
	}

	items, _ := res["results"].([]map[string]any)
	if len(items) != 1 {
		t.Fatalf("results = %#v, want exactly one confirmed result", res["results"])
	}
	ev, _ := items[0]["evidence"].(*evidence.Evidence)
	if ev == nil {
		t.Fatalf("evidence missing: %#v", items[0]["evidence"])
	}

	// 回连是一个独立事实：即使下游不把它当漏洞，它也必须出现在观测流里。
	sqlite.FlushObservations()
	page := queryOOBObservations(t, s)
	if len(page.Items) != 1 {
		t.Fatalf("observations = %d (%+v), want exactly one oob_hit", len(page.Items), page.Items)
	}
	item := page.Items[0]
	if item.Kind != observation.KindOOBHit || item.Source != observation.SourceOOB {
		t.Fatalf("unexpected observation: %+v", item)
	}
	if item.Subject != observation.EndpointSubject(endpoint) {
		t.Fatalf("subject = %q, want the normalized target %q", item.Subject, observation.EndpointSubject(endpoint))
	}
}
