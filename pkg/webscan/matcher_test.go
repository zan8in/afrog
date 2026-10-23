package webscan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoadBuiltinDB(t *testing.T) {
	db, err := LoadDB("")
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}
	if len(db.Rules) == 0 {
		t.Fatal("builtin rules are empty")
	}
	for _, r := range db.Rules {
		if r.ID == "" || r.Name == "" {
			t.Fatalf("rule missing id/name: %+v", r)
		}
	}
}

func TestMatchServerHeader(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{
		StatusCode: 200,
		Headers:    map[string]string{"server": "nginx/1.25.3", "content-type": "text/html"},
		Body:       []byte("<html><head><title>Hello</title></head><body>ok</body></html>"),
	})
	var got *Technology
	for i := range res.Technologies {
		if res.Technologies[i].Name == "Nginx" {
			got = &res.Technologies[i]
		}
	}
	if got == nil {
		t.Fatalf("expected Nginx, got %+v", res.Technologies)
	}
	if got.Version != "1.25.3" {
		t.Fatalf("version = %q, want 1.25.3", got.Version)
	}
	if got.Confidence != ConfidenceCertain {
		t.Fatalf("confidence = %v, want certain", got.Confidence)
	}
}

func TestMatchBodyAndTitle(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	body := `<html><head><meta name="generator" content="WordPress 6.4.2" />` +
		`<title>Jenkins</title></head><body><script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script></body></html>`
	res := m.Match(Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)})

	names := make(map[string]Technology, len(res.Technologies))
	for _, tech := range res.Technologies {
		names[tech.Name] = tech
	}
	wp, ok := names["WordPress"]
	if !ok || wp.Version != "6.4.2" {
		t.Fatalf("WordPress = %+v (ok=%v), want version 6.4.2", wp, ok)
	}
	if _, ok := names["jQuery"]; !ok {
		t.Fatalf("expected jQuery hit, got %+v", res.Technologies)
	}
	// 结果必须按可信度从高到低排序。
	for i := 1; i < len(res.Technologies); i++ {
		if res.Technologies[i-1].Confidence < res.Technologies[i].Confidence {
			t.Fatalf("technologies not sorted by confidence: %+v", res.Technologies)
		}
	}
}

func TestMatchSoftmatchIsProbable(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{
		Headers: map[string]string{"set-cookie": "rememberMe=deleteMe; Path=/"},
	})
	if len(res.Technologies) != 1 {
		t.Fatalf("expected 1 technology, got %+v", res.Technologies)
	}
	if got := res.Technologies[0]; got.Name != "Apache Shiro" || got.Confidence != ConfidenceProbable {
		t.Fatalf("got %+v, want Apache Shiro/probable", got)
	}
}

func TestMatchDeduplicatesSameNameVersion(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	// Cloudflare 同时命中 server 头与 cf-ray 头，但只应产出一条。
	res := m.Match(Response{
		Headers: map[string]string{"server": "cloudflare", "cf-ray": "7f8a-ABC"},
	})
	count := 0
	for _, tech := range res.Technologies {
		if tech.Name == "Cloudflare" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 Cloudflare hit, got %d (%+v)", count, res.Technologies)
	}
}

func TestFaviconHash(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	first := faviconHash(data)
	if _, err := strconv.ParseInt(first, 10, 64); err != nil {
		t.Fatalf("favicon hash %q is not a decimal integer: %v", first, err)
	}
	if second := faviconHash(data); second != first {
		t.Fatalf("favicon hash not deterministic: %q vs %q", first, second)
	}
	if faviconHash([]byte{0x01}) == first {
		t.Fatal("favicon hash ignores input")
	}

	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{Favicon: data})
	if res.FaviconHash != first {
		t.Fatalf("Result.FaviconHash = %q, want %q", res.FaviconHash, first)
	}
}

// favicon 素材要能真正参与匹配：传入 favicon 字节即命中，不传则整条规则不生效。
func TestMatchFaviconRule(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	db := &DB{Rules: []*Rule{{
		ID:       "custom",
		Name:     "Custom",
		Category: "app",
		Match:    []MatchRule{{Source: SourceFavicon, Pattern: "^" + faviconHash(data) + "$"}},
	}}}
	if err := db.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := NewMatcher(db)

	res := m.Match(Response{Favicon: data})
	if len(res.Technologies) != 1 {
		t.Fatalf("expected 1 technology, got %+v", res.Technologies)
	}
	if got := res.Technologies[0]; got.Name != "Custom" || got.Confidence != ConfidenceCertain {
		t.Fatalf("got %+v, want Custom/certain", got)
	}
	if res.FaviconHash != faviconHash(data) {
		t.Fatalf("FaviconHash = %q, want %q", res.FaviconHash, faviconHash(data))
	}
	if got := m.Match(Response{Favicon: []byte{0x01, 0x02}}); len(got.Technologies) != 0 {
		t.Fatalf("unexpected match for other favicon: %+v", got.Technologies)
	}
	if got := m.Match(Response{}); len(got.Technologies) != 0 {
		t.Fatalf("favicon rule matched without favicon: %+v", got.Technologies)
	}
}

// 内置规则集带了 favicon 规则，但抓取与否必须由 -w-favicon 决定：内置规则不能自动开启
// 抓取，只有外置规则集里写了 favicon 规则才自动开启。
func TestFaviconRulesDoNotAutoEnableBuiltinFetch(t *testing.T) {
	db, err := LoadDB("")
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}
	if !hasFaviconRules(db.Rules) {
		t.Fatal("builtin rules should carry favicon rules")
	}
	if NewMatcher(db).HasFavicon() {
		t.Fatal("builtin favicon rules must not auto-enable favicon fetching")
	}

	dir := t.TempDir()
	external := `- id: my-panel
  name: My Panel
  match:
    - source: favicon
      pattern: '^123$'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(external), 0o644); err != nil {
		t.Fatalf("write external rules: %v", err)
	}
	m, err := LoadMatcher(dir)
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	if !m.HasFavicon() {
		t.Fatal("external favicon rules should auto-enable favicon fetching")
	}
}

func TestExternalDirOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	custom := `- id: nginx
  name: CustomNginx
  category: web-server
  match:
    - source: header
      header: server
      pattern: '(?i)\bnginx\b'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(custom), 0o644); err != nil {
		t.Fatalf("write external rules: %v", err)
	}

	m, err := LoadMatcher(dir)
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{Headers: map[string]string{"server": "nginx/1.25.3"}})
	if len(res.Technologies) != 1 {
		t.Fatalf("expected 1 technology, got %+v", res.Technologies)
	}
	if got := res.Technologies[0].Name; got != "CustomNginx" {
		t.Fatalf("external rule did not override builtin: got %q", got)
	}
}

func TestLoadDBRejectsInvalidRule(t *testing.T) {
	dir := t.TempDir()
	bad := `- id: broken
  name: Broken
  match:
    - pattern: 'foo'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write external rules: %v", err)
	}
	if _, err := LoadDB(dir); err == nil {
		t.Fatal("expected error for match without source")
	}
}

func TestSummarize(t *testing.T) {
	techs := []Technology{{Name: "Nginx", Version: "1.25.3"}, {Name: "WordPress", Version: "6.4"}, {Name: ""}}
	if got := Summarize(techs); got != "Nginx 1.25.3, WordPress 6.4" {
		t.Fatalf("Summarize = %q", got)
	}
	if got := Summarize(nil); got != "" {
		t.Fatalf("Summarize(nil) = %q, want empty", got)
	}
}

// WAF/CDN 前置层规则只认各家专属的响应头或 Cookie 名，命中后 category 必须是 waf/cdn。
func TestMatchWAFAndCDNHeaders(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	tests := []struct {
		name     string
		headers  map[string]string
		wantName string
		wantCat  string
	}{
		{name: "cloudfront", headers: map[string]string{"x-amz-cf-id": "abc123"}, wantName: "AWS CloudFront", wantCat: "cdn"},
		{name: "cloudflare", headers: map[string]string{"cf-ray": "7f0e-abc"}, wantName: "Cloudflare", wantCat: "cdn"},
		{name: "imperva", headers: map[string]string{"x-iinfo": "9-12345-12346"}, wantName: "Imperva Incapsula", wantCat: "waf"},
		{name: "aliyun", headers: map[string]string{"set-cookie": "acw_tc=0b1c2d; path=/"}, wantName: "Alibaba Cloud WAF", wantCat: "waf"},
		{name: "baota", headers: map[string]string{"server": "btwaf/1.0"}, wantName: "BT Panel WAF", wantCat: "waf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := m.Match(Response{StatusCode: 200, Headers: tt.headers})
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].Name == tt.wantName {
					got = &res.Technologies[i]
				}
			}
			if got == nil {
				t.Fatalf("expected %s, got %+v", tt.wantName, res.Technologies)
			}
			if got.Category != tt.wantCat {
				t.Fatalf("%s category = %q, want %q", tt.wantName, got.Category, tt.wantCat)
			}
		})
	}

	// 普通站点响应不应误报前置层。
	plain := m.Match(Response{
		StatusCode: 200,
		Headers:    map[string]string{"server": "nginx/1.25.3", "content-type": "text/html"},
		Body:       []byte("<html><head><title>Hello</title></head><body>ok</body></html>"),
	})
	for _, tech := range plain.Technologies {
		if tech.Category == "waf" || tech.Category == "cdn" {
			t.Fatalf("unexpected front-layer match on plain response: %+v", tech)
		}
	}
}

// requires 门控的词表必须覆盖「id / 名 / 连字符名 / 分类」，且小写去重。
func TestTechnologyMatchTokens(t *testing.T) {
	tests := []struct {
		tech Technology
		want []string
	}{
		{Technology{RuleID: "apache-shiro", Name: "Apache Shiro", Category: "framework"},
			[]string{"apache-shiro", "apache shiro", "framework"}},
		{Technology{RuleID: "nextjs", Name: "Next.js", Category: "framework"},
			[]string{"nextjs", "next.js", "framework"}},
		{Technology{RuleID: "iis", Name: "Microsoft IIS", Category: "web-server"},
			[]string{"iis", "microsoft iis", "microsoft-iis", "web-server"}},
		// 无 id、无分类时只剩名称词，且空串被丢弃。
		{Technology{Name: "Nginx"}, []string{"nginx"}},
		{Technology{}, nil},
	}
	for _, tc := range tests {
		got := tc.tech.MatchTokens()
		if len(got) != len(tc.want) {
			t.Fatalf("%+v: MatchTokens = %v, want %v", tc.tech, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("%+v: MatchTokens = %v, want %v", tc.tech, got, tc.want)
			}
		}
	}
}

// 内置规则集里的技术栈都应能产出 requires 词，避免出现「识别得出却门控不上」。
func TestBuiltinRulesProduceMatchTokens(t *testing.T) {
	db, err := LoadDB("")
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}
	for _, r := range db.Rules {
		tokens := MatchTokens(r.ID, r.Name, r.Category)
		if len(tokens) == 0 {
			t.Fatalf("rule %s produces no requires token", r.ID)
		}
		if tokens[0] != strings.ToLower(r.ID) {
			t.Fatalf("rule %s first token = %q, want its id", r.ID, tokens[0])
		}
	}
}
