package webscan

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// 内置规则集带了 favicon 规则，但 HasFavicon 只反映「外置规则集是否有 favicon 规则」：
// 内置规则不参与自动开启判定（是否抓取由 -w-favicon 控制，默认开启），只有外置规则集里
// 写了 favicon 规则才算「用户意图」，即便显式关掉 -w-favicon 也要强制抓。
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

// 国内常见云 WAF / 主机防护：强判据（专属头 / Cookie 名）记为 certain，
// 弱判据（泛化关键词）记为 probable，避免把普通站点误报成 WAF。
func TestMatchCommonWAF(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	tests := []struct {
		name     string
		headers  map[string]string
		body     string
		wantName string
		wantCat  string
		wantConf Confidence
	}{
		// 用户现场：Server: CW 的前置节点（社区观测，只能作 probable）。
		{name: "huawei-server-cw", headers: map[string]string{"server": "CW"},
			wantName: "Huawei Cloud WAF", wantCat: "waf", wantConf: ConfidenceProbable},
		{name: "huawei-cookie", headers: map[string]string{"set-cookie": "HWWAFSESID=abc123; Path=/"},
			wantName: "Huawei Cloud WAF", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "huawei-server-name", headers: map[string]string{"server": "HuaweiCloudWAF"},
			wantName: "Huawei Cloud WAF", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "huawei-body", body: `<html><a href="https://console.hwclouds.com/">x</a></html>`,
			wantName: "Huawei Cloud WAF", wantCat: "waf", wantConf: ConfidenceProbable},

		{name: "safedog", headers: map[string]string{"set-cookie": "safedog-flow-item=abc;"},
			wantName: "SafeDog", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "yunsuo", headers: map[string]string{"set-cookie": "yunsuo_session=abc;"},
			wantName: "Yunsuo", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "anquanbao", headers: map[string]string{"x-powered-by-anquanbao": "1"},
			wantName: "Anquanbao", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "chuangyu", body: `<script src="https://help.365cyd.com/cyd-error-help.html"></script>`,
			wantName: "Chuangyu Shield", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "eisoo", headers: map[string]string{"server": "EisooWAF-AZURE"},
			wantName: "Eisoo Cloud Firewall", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "bluedon", headers: map[string]string{"server": "BDWAF"},
			wantName: "Bluedon WAF", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "tencent", body: `<script>location.href="https://waf.tencent-cloud.com/403"</script>`,
			wantName: "Tencent Cloud WAF", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "safeline", body: `<title>SafeLine</title><div id="safeline">x</div>`,
			wantName: "SafeLine", wantCat: "waf", wantConf: ConfidenceProbable},
		{name: "nsfocus", headers: map[string]string{"server": "NSFocus"},
			wantName: "NSFOCUS WAF", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "radware", headers: map[string]string{"x-sl-compstate": "1"},
			wantName: "Radware AppWall", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "wallarm", headers: map[string]string{"server": "nginx-wallarm"},
			wantName: "Wallarm", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "fortiweb", headers: map[string]string{"set-cookie": "FORTIWAFSID=abc;"},
			wantName: "FortiWeb", wantCat: "waf", wantConf: ConfidenceCertain},
		{name: "chinacache", headers: map[string]string{"powered-by-chinacache": "1"},
			wantName: "ChinaCache", wantCat: "cdn", wantConf: ConfidenceCertain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := m.Match(Response{StatusCode: 200, Headers: tt.headers, Body: []byte(tt.body)})
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
			if got.Confidence != tt.wantConf {
				t.Fatalf("%s confidence = %v, want %v", tt.wantName, got.Confidence, tt.wantConf)
			}
		})
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

// Confluence 页面同样带 AJS 的 ajs-version-number，不能被误判为 Jira。
func TestJiraDoesNotMatchConfluence(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{
		Headers: map[string]string{"x-confluence-request-time": "1234567890"},
		Body: []byte(`<html><head><meta name="ajs-version-number" content="9.0.0">` +
			`<title>Confluence</title></head></html>`),
	})
	var jira, confluence bool
	for _, tech := range res.Technologies {
		switch tech.Name {
		case "Atlassian Jira":
			jira = true
		case "Atlassian Confluence":
			confluence = true
		}
	}
	if jira {
		t.Fatalf("Confluence response was reported as Jira: %+v", res.Technologies)
	}
	if !confluence {
		t.Fatalf("Confluence was not detected: %+v", res.Technologies)
	}
}

// 标题前缀相似的产品不能被 Vault 规则误中。
func TestVaultDoesNotMatchVaultwarden(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{Body: []byte("<html><title>Vaultwarden</title></html>")})
	for _, tech := range res.Technologies {
		if tech.RuleID == "vault" {
			t.Fatalf("Vaultwarden was reported as Vault: %+v", tech)
		}
	}
}

// 新增的专属头 / Cookie / 生成器指纹必须能命中，且版本可提取。
func TestExclusiveFingerprints(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name        string
		resp        Response
		wantRule    string
		wantVersion string
	}{
		{"sharepoint", Response{Headers: map[string]string{"microsoftsharepointteamservices": "16.0.0.1234"}}, "sharepoint", "16.0.0.1234"},
		{"artifactory-id", Response{Headers: map[string]string{"x-artifactory-id": "abc"}}, "artifactory", ""},
		{"artifactory-server", Response{Headers: map[string]string{"server": "Artifactory/7.77.5"}}, "artifactory", "7.77.5"},
		{"f5-big-ip", Response{Headers: map[string]string{"set-cookie": "BIGipServerpool=12345.6789; Path=/"}}, "f5-big-ip", ""},
		{"netscaler", Response{Headers: map[string]string{"set-cookie": "NSC_AAAC=xyz; Path=/"}}, "citrix-netscaler", ""},
		{"squid", Response{Headers: map[string]string{"x-squid-error": "ERR_CACHE_MISS"}}, "squid", ""},
		{"gerrit", Response{Body: []byte("<html><title>Gerrit Code Review</title></html>")}, "gerrit", ""},
		{"kubernetes-dashboard", Response{Body: []byte("<html><title>Kubernetes Dashboard</title></html>")}, "kubernetes-dashboard", ""},
		{"jsf", Response{Body: []byte(`<input type="hidden" name="javax.faces.ViewState" value="x">`)}, "jsf", ""},
		{"zabbix-web", Response{Headers: map[string]string{"set-cookie": "zbx_session=abc; Path=/"}}, "zabbix-web", ""},
		{"jekyll", Response{Body: []byte(`<meta name="generator" content="Jekyll v4.2.2">`)}, "jekyll", "4.2.2"},
		{"hugo", Response{Body: []byte(`<meta name="generator" content="Hugo 0.123.0">`)}, "hugo", "0.123.0"},
		{"hexo", Response{Body: []byte(`<meta name="generator" content="Hexo 7.2.0">`)}, "hexo", "7.2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Version != tc.wantVersion {
				t.Errorf("version = %q, want %q", got.Version, tc.wantVersion)
			}
		})
	}
}

// 前端库的版本识别：文件名、?v= 查询串、内联脚本横幅注释三种来源都要能取到版本，
// 且带构建后缀（vue.global.prod.js）的产物仍应被识别（只是拿不到版本）。
func TestFrontendLibraryVersions(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name        string
		body        string
		wantRule    string
		wantVersion string
	}{
		{"jquery-filename", `<script src="/js/jquery-3.6.0.min.js"></script>`, "jquery", "3.6.0"},
		{"jquery-query", `<script src="/assets/jquery.min.js?v=3.6.0"></script>`, "jquery", "3.6.0"},
		{"jquery-query-extra", `<script src="/assets/jquery.min.js?foo=1&v=3.6.0"></script>`, "jquery", "3.6.0"},
		{"jquery-banner", `<script>/*! jQuery v3.7.1 | (c) OpenJS Foundation */</script>`, "jquery", "3.7.1"},
		{"jquery-no-version", `<script src="/assets/jquery.min.js"></script>`, "jquery", ""},
		{"vue-query", `<script src="/js/vue.min.js?v=3.4.21"></script>`, "vue", "3.4.21"},
		{"vue-banner", `<script>/*! Vue.js v3.4.21 */</script>`, "vue", "3.4.21"},
		{"vue-build-suffix", `<script src="/assets/vue.global.prod.js"></script>`, "vue", ""},
		{"react-query", `<script src="/static/react.production.min.js?v=18.2.0"></script>`, "react", "18.2.0"},
		// 版本独占一个路径段（CDN 的 name/version/ 形态），不是文件名前缀。
		{"react-path-segment", `<script src="https://gw.alipayobjects.com/os/lib/??react/16.13.1/umd/react.production.min.js"></script>`, "react", "16.13.1"},
		{"jquery-path-segment", `<script src="/cdn/jquery/3.6.0/jquery.min.js"></script>`, "jquery", "3.6.0"},
		{"vue-path-segment", `<script src="/cdn/vue/3.4.21/vue.global.prod.js"></script>`, "vue", "3.4.21"},
		{"lodash-query", `<script src="/assets/lodash.min.js?v=4.17.21"></script>`, "lodash", "4.17.21"},
		{"moment-query", `<script src="/assets/moment.min.js?v=2.30.1"></script>`, "moment-js", "2.30.1"},
		{"moment-path-segment", `<script src="/os/lib/??moment/2.24.0/min/moment.min.js"></script>`, "moment-js", "2.24.0"},
		{"angular-attr", `<div ng-version="17.1.0"></div>`, "angular", "17.1.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(Response{Body: []byte(tc.body)})
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Version != tc.wantVersion {
				t.Errorf("%s version = %q, want %q", tc.wantRule, got.Version, tc.wantVersion)
			}
		})
	}
}

// 社区库缺失、由精选集补齐的页面元信息判据：Open Graph（og:* 的 meta）与
// PWA（<link rel="manifest">）。判据就在首页 HTML 里，但属页面约定标记而非厂商身份，
// 一律记 probable；没有这些标记的普通页面不得误报。
func TestPageMetadataFingerprints(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name, body, wantRule string
	}{
		{"open-graph-title", `<meta property="og:title" content="语雀">`, "open-graph"},
		{"open-graph-image", `<meta property="og:image" content="https://x/y.png">`, "open-graph"},
		{"pwa-manifest", `<link rel="manifest" href="/manifest.json" />`, "pwa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(Response{Body: []byte("<html><head>" + tc.body + "</head></html>")})
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Confidence != ConfidenceProbable {
				t.Errorf("%s confidence = %s, want probable", tc.wantRule, got.Confidence)
			}
		})
	}

	res := m.Match(Response{Body: []byte("<html><head><title>plain</title></head></html>")})
	for _, tech := range res.Technologies {
		if tech.RuleID == "open-graph" || tech.RuleID == "pwa" {
			t.Fatalf("plain page reported %s: %+v", tech.RuleID, tech)
		}
	}
}

// 回收被 id 碰撞丢弃的社区判据：这些判据（如 Cloudflare 的 cf-cache-status、Vercel 的
// x-vercel-cache、Netlify 的 server 头）精选集里没有，此前随整条社区规则一并被丢弃。
// 现在应追加到精选规则上，只凭社区判据也能命中，且按社区数据的可信度记为 probable。
func TestCommunityCriteriaReclaimedOnIDCollision(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name     string
		resp     Response
		wantRule string
	}{
		{"cloudflare-cf-cache-status", Response{Headers: map[string]string{"cf-cache-status": "HIT"}}, "cloudflare"},
		{"vercel-x-vercel-cache", Response{Headers: map[string]string{"x-vercel-cache": "HIT"}}, "vercel"},
		{"netlify-server", Response{Headers: map[string]string{"server": "Netlify"}}, "netlify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected from community-only criteria: %+v", tc.wantRule, res.Technologies)
			}
			if got.Confidence != ConfidenceProbable {
				t.Errorf("%s confidence = %s, want probable (社区判据)", tc.wantRule, got.Confidence)
			}
		})
	}
}

// 社区库未覆盖的前端库（Preact / Knockout / Element UI / Element Plus / Layui /
// Vant / WeUI / Bulma / Lit）：新增的精选规则要能从文件名、资源路径或专属语法
// 识别出来，并尽量取到版本。
func TestGapFilledFrontendLibraries(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name, body, wantRule, wantVersion string
	}{
		{"preact-file", `<script src="/js/preact-10.19.2.min.js"></script>`, "preact", "10.19.2"},
		{"preact-banner", `<script>/*! Preact v10.19.2 */</script>`, "preact", "10.19.2"},
		{"knockout-file", `<script src="/js/knockout-3.5.1.js"></script>`, "knockout", "3.5.1"},
		{"knockout-banner", `<script>/*! Knockout JavaScript library v3.5.1 */</script>`, "knockout", "3.5.1"},
		{"knockout-binding", `<script>ko.applyBindings({});</script>`, "knockout", ""},
		{"element-ui-version", `<link href="/element-ui@2.15.14/lib/theme-chalk/index.css">`, "element-ui", "2.15.14"},
		{"element-ui-path", `<link href="/element-ui/lib/theme-chalk/index.css">`, "element-ui", ""},
		{"element-plus-version", `<link href="/element-plus@2.5.6/dist/index.css">`, "element-plus", "2.5.6"},
		{"element-plus-var", `<style>:root{--el-color-primary:#409eff}</style>`, "element-plus", ""},
		{"layui-file", `<script src="/static/layui-2.9.16.js"></script>`, "layui", "2.9.16"},
		{"layui-use", `<script>layui.use(['form'], function(){});</script>`, "layui", ""},
		{"vant-version", `<script src="/js/vant-2.12.0.min.js"></script>`, "vant", "2.12.0"},
		{"vant-path", `<link href="/vant/lib/index.css">`, "vant", ""},
		{"vant-class", `<button class="van-button">ok</button>`, "vant", ""},
		{"weui-version", `<link href="/css/weui-2.6.5.min.css">`, "weui", "2.6.5"},
		{"weui-class", `<div class="weui-cells">ok</div>`, "weui", ""},
		{"bulma-version", `<link href="/css/bulma-0.9.4.min.css">`, "bulma", "0.9.4"},
		{"bulma-banner", `<style>/*! bulma.io v0.9.4 | MIT License | github.com/jgthms/bulma */</style>`, "bulma", ""},
		{"lit-element-file", `<script src="/js/lit-element-3.3.0.js"></script>`, "lit", "3.3.0"},
		{"lit-html-file", `<script src="/js/lit-html@2.8.0.js"></script>`, "lit", "2.8.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(Response{Body: []byte(tc.body)})
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Version != tc.wantVersion {
				t.Errorf("%s version = %q, want %q", tc.wantRule, got.Version, tc.wantVersion)
			}
		})
	}
}

// TestFrameworkContentMarkers 覆盖「内容型判据」：SPA 首页为空间、脚本名被哈希化时，
// 只剩页面内联脚本与打包产物内容里还留着框架痕迹。此类判据一律记为 probable。
func TestFrameworkContentMarkers(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name, body, wantRule string
	}{
		{"nextjs-pages-data", `<script id="__NEXT_DATA__" type="application/json">{}</script>`, "nextjs"},
		{"nextjs-app-payload", `<script>self.__next_f.push([1,"x"])</script>`, "nextjs"},
		{"nuxt-data", `<script>window.__NUXT__={}</script>`, "nuxtjs"},
		{"nuxt-assets", `<link href="/_nuxt/entry.a1b2.js">`, "nuxtjs"},
		{"vite-dev-client", `<script type="module" src="/@vite/client"></script>`, "vite"},
		{"vite-build-runtime", `<script>const x=__vite__mapDeps([])</script>`, "vite"},
		{"sveltekit-global", `<script>__sveltekit_1a2b3c.start()</script>`, "sveltekit"},
		{"sveltekit-attr", `<a data-sveltekit-preload-data="hover" href="/x">x</a>`, "sveltekit"},
		{"angular-view-encapsulation", `<style>[_ngcontent-abc-c12]{color:red}</style>`, "angular"},
		{"angular-ssr", `<app-root ng-server-context="ssr"></app-root>`, "angular"},
		{"angular-ivy-runtime", `<script>ɵɵdefineComponent({})</script>`, "angular"},
		{"react-error-prefix", `<script>throw Error("Minified React error #130")</script>`, "react"},
		{"swiper-version", `<script src="/js/swiper@8.4.5.min.js"></script>`, "swiper"},
		{"swiper-bundle", `<link href="/js/swiper-bundle.min.css" rel="stylesheet">`, "swiper"},
		{"swiper-init", `<script>new Swiper('.hero', {})</script>`, "swiper"},
		{"swiper-dom", `<div class="swiper-wrapper"></div>`, "swiper"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(Response{Body: []byte(tc.body)})
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Confidence != ConfidenceProbable {
				t.Errorf("%s confidence = %s, want probable", tc.wantRule, got.Confidence)
			}
		})
	}
}

// TestFrameworkContentMarkersInAssets 确认内容型判据在「只喂正文」的资源匹配路径同样生效
// （MatchAssets 只把资源内容当正文，不喂响应头、URL）。
func TestFrameworkContentMarkersInAssets(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	assets := []Asset{
		{URL: "https://cdn.example/assets/index-a1b2c3.js", Body: []byte(`var x=__vite__mapDeps([]);ɵɵdefineComponent({})`)},
	}
	res := m.MatchAssets(assets)
	names := make(map[string]bool, len(res.Technologies))
	for _, tech := range res.Technologies {
		names[tech.Name] = true
		if tech.Confidence != ConfidenceProbable {
			t.Errorf("%s confidence = %s, want probable", tech.Name, tech.Confidence)
		}
		if !strings.HasPrefix(tech.Evidence, "asset ") {
			t.Errorf("%s evidence = %q, want asset prefix", tech.Name, tech.Evidence)
		}
	}
	for _, want := range []string{"Vite", "Angular"} {
		if !names[want] {
			t.Errorf("%s not detected from asset content: %+v", want, res.Technologies)
		}
	}
}

// 收紧后的弱判据必须落在 probable，避免以 certain 结论输出。
func TestTightenedRulesUseProbable(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name     string
		resp     Response
		wantRule string
	}{
		{"prestashop", Response{Body: []byte("<p>prestashop</p>")}, "prestashop"},
		{"django", Response{Headers: map[string]string{"set-cookie": "csrftoken=abc; Path=/"}}, "django"},
		{"opencart", Response{Body: []byte("<a href=\"index.php?route=product\">x</a>")}, "opencart"},
		{"magento", Response{Body: []byte("<script>Mage.Cookies.init()</script>")}, "magento"},
		{"empirecms", Response{Body: []byte("<link href=\"/e/data/\">")}, "empirecms"},
		{"phpbb", Response{Body: []byte("<p>phpBB</p>")}, "phpbb"},
		{"vbulletin", Response{Body: []byte("<p>vBulletin</p>")}, "vbulletin"},
		{"phpcms", Response{Body: []byte("<p>PHPCMS</p>")}, "phpcms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Confidence != ConfidenceProbable {
				t.Errorf("%s confidence = %s, want probable", tc.wantRule, got.Confidence)
			}
		})
	}
}

// TestMatchCommunitySources 覆盖随社区库引入的各类素材来源。
//
// 这些都是「服务端可见」的判据：不需要执行页面 JS 也能拿到，正是本次扩容的依据。
func TestMatchCommunitySources(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}

	t.Run("scriptSrc", func(t *testing.T) {
		body := `<html><head><script src="/static/mathjax.js"></script></head></html>`
		if !hasTech(m.Match(Response{Body: []byte(body)}), "MathJax") {
			t.Fatal("MathJax not detected from script src")
		}
	})

	t.Run("modulepreload", func(t *testing.T) {
		// SPA 打包器用 modulepreload 载入入口脚本，没有 <script src>。
		body := `<html><head><link rel="modulepreload" href="/assets/moment.min.js"></head></html>`
		if !hasTech(m.Match(Response{Body: []byte(body)}), "Moment.js") {
			t.Fatal("Moment.js not detected from modulepreload")
		}
	})

	t.Run("css", func(t *testing.T) {
		if !hasTech(m.Match(Response{Body: []byte(`.a{--tw-rotate:1deg}`)}), "Tailwind CSS") {
			t.Fatal("Tailwind CSS not detected from css variable")
		}
	})

	t.Run("html", func(t *testing.T) {
		body := `<html><body><button class="ant-btn">x</button></body></html>`
		if !hasTech(m.Match(Response{Body: []byte(body)}), "Ant Design") {
			t.Fatal("Ant Design not detected from class name")
		}
	})

	t.Run("meta", func(t *testing.T) {
		body := `<html><head><meta name="application-name" content="Tailwind CSS"></head></html>`
		if !hasTech(m.Match(Response{Body: []byte(body)}), "Tailwind CSS") {
			t.Fatal("Tailwind CSS not detected from meta")
		}
	})

	t.Run("cookies", func(t *testing.T) {
		// 上游把「只要存在这个 Cookie」写成空 pattern，这里按名字精确命中。
		if !hasTech(m.Match(Response{Cookies: []string{"AWSALB=abc123; Path=/"}}), "Amazon ALB") {
			t.Fatal("Amazon ALB not detected from cookie name")
		}
	})

	t.Run("url", func(t *testing.T) {
		if !hasTech(m.Match(Response{RequestURL: "https://staff.tumblr.com/"}), "Tumblr") {
			t.Fatal("Tumblr not detected from request url")
		}
	})
}

// TestPrefilterKeepsCaseInsensitiveMatch 守住预筛的大小写语义。
//
// 预筛按字节比较，若把 (?i) 规则的字面量当大小写敏感来查，正文写大写时
// 就会静默漏报——这类错在功能测试里极难暴露，必须单独钉住。
func TestPrefilterKeepsCaseInsensitiveMatch(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	res := m.Match(Response{Headers: map[string]string{"server": "NGINX/1.25.3"}})
	var got *Technology
	for i := range res.Technologies {
		if res.Technologies[i].Name == "Nginx" {
			got = &res.Technologies[i]
		}
	}
	if got == nil {
		t.Fatalf("Nginx not detected from uppercase server header: %+v", res.Technologies)
	}
}

// TestPrefilterSkipsWhenLiteralAbsent 确认预筛确实在拦：一条不可能命中的模式
// 不该把正文交给正则。用「字面量不在正文里」的取材反向验证形态。
func TestLiteralHints(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
		ci      bool
	}{
		// 顶层分支各自抽字面量，任一出现即放行。
		{`(?i)\bhwclouds\.com\b|\bhws_security@`, []string{"hwclouds.com", "hws_security@"}, true},
		// 元字符在前、长字面量在后。
		{`<[^>]*class="ant-(?:btn|col)`, []string{`class="ant-`}, false},
		{`\.monaco-editor`, []string{".monaco-editor"}, false},
		// 分组的重复次数不影响它后面的字面量：bar 仍然必然出现。
		{`(?:foo)?bar`, []string{"bar"}, false},
		// 太短的字面量无从加快匹配，直接放弃。
		{`\d+`, nil, false},
	}
	for _, tc := range cases {
		got, ci := literalHints(tc.pattern)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") || ci != tc.ci {
			t.Errorf("literalHints(%q) = %q ci=%v, want %q ci=%v", tc.pattern, got, ci, tc.want, tc.ci)
		}
	}
}

// TestTechnologyEvidence 钉住「为什么命中」的证据串：素材位置 + 触发片段。
//
// Evidence 是新增的可复核字段（D11），probable 弱判据尤其依赖它——没有证据串，
// 使用者只能相信一个黑白结论。位置命名与片段都是对外契约，改动应在此暴露。
func TestTechnologyEvidence(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}

	tests := []struct {
		name       string
		resp       Response
		wantTech   string
		wantPrefix string
		wantIn     string // 期望出现在证据里的匹配片段；空表示只断言位置前缀
	}{
		{
			name:       "header-with-key",
			resp:       Response{Headers: map[string]string{"server": "nginx/1.25.3"}},
			wantTech:   "Nginx",
			wantPrefix: "header server: ",
			wantIn:     "nginx/1.25.3",
		},
		{
			name:       "set-cookie-header",
			resp:       Response{Headers: map[string]string{"set-cookie": "rememberMe=deleteMe; Path=/"}},
			wantTech:   "Apache Shiro",
			wantPrefix: "header set-cookie: ",
			wantIn:     "rememberMe=",
		},
		{
			name:       "body",
			resp:       Response{Body: []byte(`<meta name="generator" content="WordPress 6.4.2">`)},
			wantTech:   "WordPress",
			wantPrefix: "body: ",
			wantIn:     "WordPress 6.4.2",
		},
		{
			name:       "keyed-meta-source",
			resp:       Response{Body: []byte(`<meta name="application-name" content="Tailwind CSS">`)},
			wantTech:   "Tailwind CSS",
			wantPrefix: "meta application-name: ",
			wantIn:     "Tailwind CSS",
		},
		{
			// 存在性判据（无正则）没有片段，证据只到素材位置为止。
			name:       "cookie-existence",
			resp:       Response{Cookies: []string{"AWSALB=abc123; Path=/"}},
			wantTech:   "Amazon ALB",
			wantPrefix: "cookie AWSALB",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].Name == tc.wantTech {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not matched: %+v", tc.wantTech, res.Technologies)
			}
			if !strings.HasPrefix(got.Evidence, tc.wantPrefix) {
				t.Fatalf("evidence = %q, want prefix %q", got.Evidence, tc.wantPrefix)
			}
			if tc.wantIn != "" && !strings.Contains(got.Evidence, tc.wantIn) {
				t.Errorf("evidence = %q, want it to contain %q", got.Evidence, tc.wantIn)
			}
		})
	}
}

// TestFetchAssets 覆盖资源抓取的 HTTP 路径：同源脚本抓回内容、非 2xx 资源跳过、
// max=0 直接不抓。这是「抓取」与「匹配」之间唯一的一段网络代码，必须单独钉住。
func TestFetchAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/js/app.js":
			_, _ = w.Write([]byte("/*! vue.runtime.esm-bundler */"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := NewProber(ProbeOptions{})
	body := []byte(`<html><head>` +
		`<script src="/js/app.js"></script>` +
		`<script src="/js/missing.js"></script>` +
		`</head></html>`)

	assets := p.FetchAssets(context.Background(), srv.URL+"/", body, 5)
	if len(assets) != 1 {
		t.Fatalf("assets = %+v, want only the 2xx one", assets)
	}
	if !strings.Contains(string(assets[0].Body), "vue.runtime") {
		t.Fatalf("asset body = %q", assets[0].Body)
	}

	if got := p.FetchAssets(context.Background(), srv.URL+"/", body, 0); got != nil {
		t.Fatalf("max=0 should not fetch: %+v", got)
	}
}

// TestCoverageGapFingerprints 覆盖本轮为「社区库缺失」补齐的指纹规则。
//
// 判据全部来自服务端可见素材（响应头 / 正文 / 标题 / Cookie / meta），不依赖执行 JS。
// 断言两件事：能命中，且可信度与判据强度一致（专属头/路径/Cookie 记 certain，
// 泛化关键词或共享件记 probable）。
func TestCoverageGapFingerprints(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name     string
		resp     Response
		wantRule string
		wantVer  string
		wantConf Confidence
	}{
		{"webmin-title", Response{Body: []byte("<html><head><title>Webmin 2.105</title></head></html>")}, "webmin", "", ConfidenceCertain},
		{"webmin-miniserv", Response{Headers: map[string]string{"server": "MiniServ/1.984"}}, "webmin", "", ConfidenceProbable},
		{"rundeck", Response{Body: []byte("<html><head><title>Rundeck</title></head></html>")}, "rundeck", "", ConfidenceCertain},
		{"jumpserver", Response{Body: []byte(`<div id="jumpserver-app">x</div>`)}, "jumpserver", "", ConfidenceCertain},
		{"netbox", Response{Body: []byte("<html><head><title>NetBox</title></head></html>")}, "netbox", "", ConfidenceCertain},
		{"jaeger", Response{Body: []byte("<html><head><title>Jaeger UI</title></head></html>")}, "jaeger", "", ConfidenceCertain},
		{"victoriametrics", Response{Body: []byte(`<title>VictoriaMetrics</title>`)}, "victoriametrics", "", ConfidenceCertain},
		{"apache-spark", Response{Body: []byte("<html><head><title>Spark Master at spark://h:7077</title></head></html>")}, "apache-spark", "", ConfidenceCertain},
		{"apache-flink", Response{Body: []byte("<html><head><title>Apache Flink Dashboard</title></head></html>")}, "apache-flink", "", ConfidenceCertain},
		{"hadoop", Response{Body: []byte("<html><head><title>NameNode</title></head></html>")}, "hadoop", "", ConfidenceProbable},
		{"airflow", Response{Body: []byte("<html><head><title>Airflow</title></head></html>")}, "airflow", "", ConfidenceCertain},
		{"metabase", Response{Body: []byte("<html><head><title>Metabase</title></head></html>")}, "metabase", "", ConfidenceCertain},
		{"nifi", Response{Body: []byte("<html><head><title>Apache NiFi</title></head></html>")}, "nifi", "", ConfidenceCertain},
		{"apache-solr", Response{Body: []byte("<html><head><title>Solr Admin</title></head></html>")}, "apache-solr", "", ConfidenceCertain},
		{"clickhouse-header", Response{Headers: map[string]string{"x-clickhouse-query-id": "a1b2"}}, "clickhouse", "", ConfidenceProbable},
		{"clickhouse-exception", Response{Body: []byte("Code: 62. DB::Exception: Syntax error")}, "clickhouse", "", ConfidenceProbable},
		{"mikrotik", Response{Body: []byte("<html><head><title>RouterOS</title></head></html>")}, "mikrotik-routeros", "", ConfidenceCertain},
		{"sonicwall", Response{Body: []byte("<html><head><title>SonicWall</title></head></html>")}, "sonicwall", "", ConfidenceCertain},
		{"fortigate", Response{Body: []byte("<html><head><title>FortiGate</title></head></html>")}, "fortinet-fortigate", "", ConfidenceCertain},
		{"globalprotect", Response{Body: []byte(`<div id="globalprotect">GlobalProtect Portal</div>`)}, "paloalto-globalprotect", "", ConfidenceCertain},
		{"cisco-asa", Response{Body: []byte(`<a href="/+CSCOE+/logon.html">login</a>`)}, "cisco-asa", "", ConfidenceProbable},
		{"docker-registry", Response{Headers: map[string]string{"docker-distribution-api-version": "registry/2.0"}}, "docker-registry", "", ConfidenceCertain},
		{"k8s-apiserver-header", Response{Headers: map[string]string{"x-kubernetes-pf-flowschema-uid": "abc"}}, "kubernetes-apiserver", "", ConfidenceProbable},
		{"k8s-apiserver-status", Response{Body: []byte(`{"kind":"Status","apiVersion":"v1","status":"Failure"}`)}, "kubernetes-apiserver", "", ConfidenceProbable},
		{"haproxy-server", Response{Headers: map[string]string{"server": "HAProxy"}}, "haproxy", "", ConfidenceProbable},
		{"haproxy-cookie", Response{Cookies: []string{"SERVERID=node1; Path=/"}}, "haproxy", "", ConfidenceProbable},
		{"remix", Response{Body: []byte(`<script>window.__remixContext={}</script>`)}, "remix", "", ConfidenceCertain},
		{"vitepress", Response{Body: []byte(`<meta name="generator" content="VitePress v1.5.0">`)}, "vitepress", "1.5.0", ConfidenceCertain},
		{"jupyter", Response{Body: []byte("<html><head><title>JupyterLab</title></head></html>")}, "jupyter", "", ConfidenceCertain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Version != tc.wantVer {
				t.Errorf("%s version = %q, want %q", tc.wantRule, got.Version, tc.wantVer)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("%s confidence = %s, want %s", tc.wantRule, got.Confidence, tc.wantConf)
			}
		})
	}

	// 普通站点（nginx 静态页）不得被这批规则误报。
	plain := m.Match(Response{
		StatusCode: 200,
		Headers:    map[string]string{"server": "nginx/1.25.3", "content-type": "text/html"},
		Body:       []byte("<html><head><title>Hello</title></head><body>ok</body></html>"),
	})
	guarded := map[string]bool{
		"webmin": true, "rundeck": true, "jumpserver": true, "netbox": true, "jaeger": true,
		"victoriametrics": true, "apache-spark": true, "apache-flink": true, "hadoop": true,
		"airflow": true, "metabase": true, "nifi": true, "apache-solr": true, "clickhouse": true,
		"mikrotik-routeros": true, "sonicwall": true, "fortinet-fortigate": true,
		"paloalto-globalprotect": true, "cisco-asa": true, "docker-registry": true,
		"kubernetes-apiserver": true, "haproxy": true, "remix": true, "vitepress": true, "jupyter": true,
	}
	for _, tech := range plain.Technologies {
		if guarded[tech.RuleID] {
			t.Fatalf("plain response reported %s (%s): %+v", tech.Name, tech.RuleID, tech)
		}
	}
}

func hasTech(res Result, name string) bool {
	for _, tech := range res.Technologies {
		if tech.Name == name {
			return true
		}
	}
	return false
}

// TestDomesticAppFingerprints 覆盖本轮补齐的国内应用 / OA / ERP 指纹规则。
//
// 判据全部取自仓库内自带 PoC 的真实字面量（见规则注释里的 Poc 文件名），不依赖执行 JS。
// 断言两件事：能命中，且可信度与判据强度一致——厂商专属的标题/DOM id/关键词记 certain，
// 仅凭路径片段的记 probable。
func TestDomesticAppFingerprints(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		name     string
		resp     Response
		wantRule string
		wantConf Confidence
	}{
		{"yonyou-iuap", Response{Body: []byte(`<script>var pageTitle = '欢迎登录';</script>`)}, "yonyou-iuap", ConfidenceCertain},
		{"yonyou-mobsm", Response{Body: []byte(`<script>a="/mobsm/login/home",b="/mobsm/html/index.jsp";</script>`)}, "yonyou-mobsm", ConfidenceCertain},
		{"yonyou-u8crm", Response{Body: []byte("<html><head><title>用友U8CRM</title></head></html>")}, "yonyou-u8crm", ConfidenceCertain},
		{"yonyou-grp-u8", Response{Body: []byte(`<script src="/R9iPortal/js/x.js"></script>`)}, "yonyou-grp-u8", ConfidenceProbable},
		{"yonyou-nc", Response{Body: []byte(`<form action="/servlet/~ic/nc.bs.framework.x">`)}, "yonyou-nc", ConfidenceProbable},
		{"kingdee-k3cloud", Response{Body: []byte("<html><head><title>金蝶云星空</title></head></html>")}, "kingdee-k3cloud", ConfidenceCertain},
		{"kingdee-eas", Response{Body: []byte(`<a href="/easportal/autoLogin.jsp">登录</a>`)}, "kingdee-eas", ConfidenceProbable},
		{"landray-oa", Response{Body: []byte(`<input id="lui_login_input_username" type="text">`)}, "landray-oa", ConfidenceCertain},
		{"sangfor-logcenter", Response{Body: []byte(`<script>var c={isHighPerformance : !!SFIsHighPerformance,};</script>`)}, "sangfor-logcenter", ConfidenceCertain},
		{"sangfor-ngaf", Response{Body: []byte("<html><head><title>SANGFOR | NGAF</title></head></html>")}, "sangfor-ngaf", ConfidenceCertain},
		{"seeyon-server", Response{Headers: map[string]string{"server": "SY8044"}}, "seeyon", ConfidenceCertain},
		{"seeyon-product", Response{Body: []byte(`<script>var seeyonProductId="A8";</script>`)}, "seeyon", ConfidenceProbable},
		{"seeyon-yyoa", Response{Body: []byte(`<script src="/yyoa/seeyonoa/common/x.js"></script>`)}, "seeyon", ConfidenceProbable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.resp)
			var got *Technology
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.wantRule {
					got = &res.Technologies[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s not detected: %+v", tc.wantRule, res.Technologies)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("%s confidence = %s, want %s", tc.wantRule, got.Confidence, tc.wantConf)
			}
		})
	}

	// 普通站点（nginx 静态页）不得被这批规则误报。
	plain := m.Match(Response{
		StatusCode: 200,
		Headers:    map[string]string{"server": "nginx/1.25.3", "content-type": "text/html"},
		Body:       []byte("<html><head><title>Hello</title></head><body>ok</body></html>"),
	})
	guarded := map[string]bool{
		"yonyou-iuap": true, "yonyou-mobsm": true, "yonyou-u8crm": true, "yonyou-grp-u8": true,
		"yonyou-nc": true, "kingdee-k3cloud": true, "kingdee-eas": true, "landray-oa": true,
		"sangfor-logcenter": true, "sangfor-ngaf": true,
	}
	for _, tech := range plain.Technologies {
		if guarded[tech.RuleID] {
			t.Fatalf("plain response reported %s (%s): %+v", tech.Name, tech.RuleID, tech)
		}
	}
}

// TestFingerprintHubGapRules 覆盖从 FingerprintHub v4 取差集补齐的指纹规则（见 rules.yaml 末尾
// 「公开指纹库差集补充」段）。逐条验证「命中 + 可信度」。
//
// favicon 判据依赖真实图标字节，无法在单测里构造出指定 mmh3，故 landray-ekp /
// shardingsphere-elasticjob-ui / jsherp 只纳入误报守卫，不在命中用例里断言。
func TestFingerprintHubGapRules(t *testing.T) {
	m, err := LoadMatcher("")
	if err != nil {
		t.Fatalf("LoadMatcher: %v", err)
	}
	cases := []struct {
		rule     string
		resp     Response
		wantConf Confidence
	}{
		// ---- 国产 OA / ERP / 政企应用 ----
		{"weaver-ecology", Response{Body: []byte(`<script src="/theme/ecology8/jquery/js/zdialog_wev8.js"></script>`)}, ConfidenceCertain},
		{"weaver-e-mobile", Response{Body: []byte(`<meta name="generator" content="weaver e-mobile">`)}, ConfidenceCertain},
		{"landray-eis", Response{Body: []byte(`<script src="/scripts/jquery.landray.common.js"></script>`)}, ConfidenceCertain},
		{"jinher-oa", Response{Body: []byte(`<iframe src="/c6/jhsoft.web.login"></iframe>`)}, ConfidenceCertain},
		{"seeyon-m3", Response{Body: []byte(`<title>M3 Server v2.0</title>`)}, ConfidenceCertain},
		{"yonyou-u8", Response{Body: []byte(`<body id="login_main_bg">`)}, ConfidenceProbable},
		{"yonyou-u8cloud", Response{Body: []byte(`<h1>开启U8 cloud云端之旅</h1>`)}, ConfidenceCertain},
		{"yonyou-ksoa", Response{Body: []byte(`<a onmouseout="this.className='btn btnoff'">x</a>`)}, ConfidenceProbable},
		{"yonyou-ism", Response{Body: []byte(`<script>var h=sHeight*window.screen.deviceYDpi;</script>`)}, ConfidenceCertain},
		{"yonyou-shop", Response{Body: []byte(`<script>$.post("/shopfront/shoppingcar/gotoshoppingcartajax.action")</script>`)}, ConfidenceCertain},
		{"yonbip", Response{Body: []byte(`<div>数字化工作台</div>`)}, ConfidenceProbable},
		{"kingdee", Response{Body: []byte(`<script>var x=kingdee.entryRole;</script>`)}, ConfidenceCertain},
		{"hongfan-ioffice", Response{Body: []byte(`<title>ioffice.net</title>`)}, ConfidenceCertain},
		{"rockoa-oa", Response{Body: []byte(`<div>信呼开发团队</div>`)}, ConfidenceCertain},
		{"dzzoffice", Response{Body: []byte(`<script src="/dzz/scripts/dzz_min.js"></script>`)}, ConfidenceCertain},
		{"qiyuesuo", Response{Body: []byte(`<div class="qyswebapp"></div>`)}, ConfidenceCertain},
		{"weihong-oa", Response{Body: []byte(`<form action="/wh/serverlogin.jsp">`)}, ConfidenceProbable},
		// ---- 中间件 / 应用服务器 ----
		{"apache-activemq", Response{Body: []byte(`<title>Apache ActiveMQ</title>`)}, ConfidenceCertain},
		{"apache-dubbo", Response{Headers: map[string]string{"www-authenticate": `Basic realm="dubbo"`}}, ConfidenceCertain},
		{"apache-skywalking", Response{Body: []byte(`Sorry but SkyWalking doesn't work`)}, ConfidenceCertain},
		{"eureka-server", Response{Body: []byte(`<link href="eureka/css/wro.css">`)}, ConfidenceCertain},
		{"rocketmq-console", Response{Body: []byte(`<title>rocketmq-console-ng</title>`)}, ConfidenceCertain},
		{"kafka-ui", Response{Body: []byte(`<title>UI for Apache Kafka</title>`)}, ConfidenceCertain},
		{"kafka-center", Response{Body: []byte(`<title>Kafka Center</title>`)}, ConfidenceCertain},
		{"kafka-manager", Response{Body: []byte(`<img src="vassets/images/2af62f58ee2baf495c9b3a9a1c30ce03-favicon.png">`)}, ConfidenceProbable},
		{"apache-axis2", Response{Body: []byte(`<link href="axis2-web/css/axis-style.css">`)}, ConfidenceCertain},
		{"apache-oozie", Response{Body: []byte(`<a href="/oozie">Oozie Console</a>`)}, ConfidenceCertain},
		{"apache-archiva", Response{Body: []byte(`<link href="/archiva.css">`)}, ConfidenceCertain},
		{"apache-mesos", Response{Body: []byte(`<img src="/static/img/mesos_logo.png">`)}, ConfidenceCertain},
		{"apache-kylin", Response{Body: []byte(`<meta http-equiv="refresh" content="1;url=kylin">`)}, ConfidenceCertain},
		{"apache-ambari", Response{Body: []byte(`<title>Ambari</title>`)}, ConfidenceProbable},
		{"apache-cocoon", Response{Headers: map[string]string{"x-cocoon-version": "2.1"}}, ConfidenceCertain},
		{"apache-guacamole", Response{Body: []byte(`<title>Guacamole - Clientless Remote Desktop</title>`)}, ConfidenceCertain},
		{"openfire", Response{Body: []byte(`<title>Openfire Admin Console</title>`)}, ConfidenceCertain},
		{"wildfly", Response{Body: []byte(`<h3>Welcome to WildFly Project</h3>`)}, ConfidenceProbable},
		// ---- 网络 / 安全设备 ----
		{"ruijie-rgos", Response{Headers: map[string]string{"server": "RGOS HTTP-Server"}}, ConfidenceCertain},
		{"ruijie-eweb", Response{Body: []byte(`<span class="resource" mark="login.copyright">锐捷网络</span>`)}, ConfidenceCertain},
		{"ruijie-sslvpn", Response{Body: []byte(`<script>document.cookie="rjsslvpn_encookie=yes;"</script>`)}, ConfidenceCertain},
		{"huawei-ssl-vpn", Response{Body: []byte(`<script>SVN_GETLOGINCONTEXTVALUE();</script>`)}, ConfidenceCertain},
		{"huawei-fusioncompute", Response{Body: []byte(`<a href="/omsportal/">登录</a>`)}, ConfidenceCertain},
		{"huawei-esight", Response{Body: []byte(`<div class="esight_login_copy_right_font"></div>`)}, ConfidenceCertain},
		{"h3c-imc", Response{Body: []byte(`<form action="/imc/login.jsf">`)}, ConfidenceCertain},
		{"h3c-secpath-audit", Response{Body: []byte(`<title>登录-H3C SecPath 运维审计系统</title>`)}, ConfidenceCertain},
		{"sangfor-ssl-vpn", Response{Body: []byte(`<script>location.href="/por/login_psw.csp";</script>`)}, ConfidenceCertain},
		{"qi-an-xin-vpn", Response{Body: []byte(`<div>qianxinvpn</div>`)}, ConfidenceCertain},
		{"qax-secfox", Response{Body: []byte(`<object id=mtokenplugin></object>`)}, ConfidenceCertain},
		{"nsfocus-vpn", Response{Body: []byte(`<img src="/logo_login_nsfocus.png">`)}, ConfidenceCertain},
		{"leadsec-ssl-vpn", Response{Body: []byte(`<a href="/ssl/down/usbkey.exe">下载</a>`)}, ConfidenceCertain},
		{"topsec-vpn", Response{Headers: map[string]string{"server": "topwebserver"}}, ConfidenceCertain},
		{"wangshen-vpn", Response{Body: []byte(`<script src="admin/js/virtual_keyboard.js"></script>`)}, ConfidenceProbable},
		{"cisco-ssl-vpn", Response{Cookies: []string{"webvpncontext=abc; Path=/"}}, ConfidenceCertain},
		{"fortinet-sslvpn", Response{Body: []byte(`<iframe src="/sslvpn/portal.html">`)}, ConfidenceCertain},
		{"fortitoken", Response{Body: []byte(`<div>FortiToken</div>`)}, ConfidenceProbable},
		{"sophos-web-appliance", Response{Body: []byte(`background:url(resources/images/en/login_swa.jpg)`)}, ConfidenceCertain},
		{"freenas", Response{Body: []byte(`<img src="/images/ui/freenas-logo.png">`)}, ConfidenceCertain},
		{"mikrotik-httpproxy", Response{Headers: map[string]string{"server": "Mikrotik HttpProxy"}}, ConfidenceCertain},
		{"profense-firewall", Response{Headers: map[string]string{"server": "profense"}}, ConfidenceCertain},
		{"anheng-mingyu-waf", Response{Body: []byte(`<div>明御web应用防火墙</div>`)}, ConfidenceCertain},
		{"hikvision-isecure-center", Response{Body: []byte(`<img src="/portal/conf/icon/logo.png">`)}, ConfidenceCertain},
		{"dahua-smart-park", Response{Body: []byte(`<span>dss助手</span>`)}, ConfidenceCertain},
		// ---- CMS / 建站 / 报表 ----
		{"pbootcms", Response{Cookies: []string{"pbootsystem=abc; Path=/"}}, ConfidenceCertain},
		{"jeesite", Response{Cookies: []string{"jeesite.session.id=abc; Path=/"}}, ConfidenceCertain},
		{"jeecms", Response{Body: []byte(`<script src="/r/cms/www/js/x.js"></script>`)}, ConfidenceCertain},
		{"duomicms", Response{Body: []byte(`<a href="/duomicms_member/login.php">`)}, ConfidenceCertain},
		{"aspcms", Response{Body: []byte(`<script src="/inc/aspcms_advjs.asp"></script>`)}, ConfidenceCertain},
		{"cmseasy", Response{Body: []byte(`<meta name="generator" content="CmsEasy">`)}, ConfidenceCertain},
		{"espcms", Response{Body: []byte(`<link href="/templates/default/style/tempates_div.css">`)}, ConfidenceCertain},
		{"siteserver", Response{Body: []byte(`<div>Powered by SiteServer CMS</div>`)}, ConfidenceCertain},
		{"jspxcms", Response{Body: []byte(`<div>- Powered by Jspxcms</div>`)}, ConfidenceCertain},
		{"cms4j", Response{Body: []byte(`<a href="/cms4jadmin/login.jsp">`)}, ConfidenceCertain},
		{"08cms", Response{Body: []byte(`<script>typeof(_08cms)</script>`)}, ConfidenceCertain},
		{"feifeicms", Response{Body: []byte(`<a data-target="#navbar-feifeicms">`)}, ConfidenceCertain},
		{"74cms", Response{Body: []byte(`<meta name="keywords" content="74cms.com">`)}, ConfidenceCertain},
		{"twcms", Response{Body: []byte(`<link href="/twcms/theme/default/css/global.css">`)}, ConfidenceCertain},
		{"wuzhicms", Response{Body: []byte(`<meta name="generator" content="wuzhicms">`)}, ConfidenceCertain},
		{"chanzhicms", Response{Body: []byte(`<script src="/js/chanzhi.js"></script>`)}, ConfidenceCertain},
		{"hdwiki", Response{Body: []byte(`<meta name="generator" content="HDWiki">`)}, ConfidenceCertain},
		{"tpshop", Response{Body: []byte(`<script>var tpshop_config={};</script>`)}, ConfidenceCertain},
		{"shopnc", Response{Body: []byte(`<div>Copyright 2007-2014 ShopNC Inc</div>`)}, ConfidenceCertain},
		{"niushop", Response{Body: []byte(`<div>niushop</div>`)}, ConfidenceProbable},
		{"taocms", Response{Body: []byte(`<script src="/taocms/code/calendar.js"></script>`)}, ConfidenceCertain},
		{"qibosoft", Response{Body: []byte(`<div>Powered by Qibosoft V1.0</div>`)}, ConfidenceCertain},
		{"jizhicms", Response{Body: []byte(`<div>极致CMS建站系统</div>`)}, ConfidenceCertain},
		{"xunruicms", Response{Body: []byte(`<img alt="xunruicms" src="x">`)}, ConfidenceCertain},
		{"zzzcms", Response{Body: []byte(`<a href='http://zzzcms.com'>ZZZCMS</a>`)}, ConfidenceCertain},
		{"smartbi", Response{Body: []byte(`<script>gcfUtil = jsLoader.resolve('smartbi.gcf.gcfUtil');</script>`)}, ConfidenceCertain},
		{"finereport", Response{Body: []byte(`<a href="/finereport/decision?op=fr_dialog">`)}, ConfidenceCertain},
		{"aj-report", Response{Body: []byte(`<title>AJ-Report</title>`)}, ConfidenceCertain},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			res := m.Match(tc.resp)
			for i := range res.Technologies {
				if res.Technologies[i].RuleID == tc.rule {
					if res.Technologies[i].Confidence != tc.wantConf {
						t.Errorf("%s confidence = %s, want %s", tc.rule, res.Technologies[i].Confidence, tc.wantConf)
					}
					return
				}
			}
			t.Fatalf("%s not detected: %+v", tc.rule, res.Technologies)
		})
	}

	// 普通站点（nginx 静态页）不得被这批规则误报。
	plain := m.Match(Response{
		StatusCode: 200,
		Headers:    map[string]string{"server": "nginx/1.25.3", "content-type": "text/html"},
		Body:       []byte("<html><head><title>Hello</title></head><body>ok</body></html>"),
	})
	guarded := map[string]bool{
		"weaver-ecology": true, "weaver-e-mobile": true, "landray-eis": true, "landray-ekp": true,
		"jinher-oa": true, "seeyon-m3": true, "yonyou-u8": true, "yonyou-u8cloud": true,
		"yonyou-ksoa": true, "yonyou-ism": true, "yonyou-shop": true, "yonbip": true,
		"kingdee": true, "hongfan-ioffice": true, "rockoa-oa": true, "dzzoffice": true,
		"qiyuesuo": true, "weihong-oa": true,
		"apache-activemq": true, "apache-dubbo": true, "apache-skywalking": true, "eureka-server": true,
		"rocketmq-console": true, "kafka-ui": true, "kafka-center": true, "kafka-manager": true,
		"apache-axis2": true, "apache-oozie": true, "apache-archiva": true, "apache-mesos": true,
		"apache-kylin": true, "apache-ambari": true, "apache-cocoon": true, "apache-guacamole": true,
		"openfire": true, "shardingsphere-elasticjob-ui": true, "wildfly": true,
		"ruijie-rgos": true, "ruijie-eweb": true, "ruijie-sslvpn": true, "huawei-ssl-vpn": true,
		"huawei-fusioncompute": true, "huawei-esight": true, "h3c-imc": true, "h3c-secpath-audit": true,
		"sangfor-ssl-vpn": true, "qi-an-xin-vpn": true, "qax-secfox": true, "nsfocus-vpn": true,
		"leadsec-ssl-vpn": true, "topsec-vpn": true, "wangshen-vpn": true, "cisco-ssl-vpn": true,
		"fortinet-sslvpn": true, "fortitoken": true, "sophos-web-appliance": true, "freenas": true,
		"mikrotik-httpproxy": true, "profense-firewall": true, "anheng-mingyu-waf": true,
		"hikvision-isecure-center": true, "dahua-smart-park": true,
		"pbootcms": true, "jeesite": true, "jeecms": true, "duomicms": true, "aspcms": true,
		"cmseasy": true, "espcms": true, "siteserver": true, "jspxcms": true, "cms4j": true,
		"08cms": true, "feifeicms": true, "74cms": true, "twcms": true, "wuzhicms": true,
		"chanzhicms": true, "hdwiki": true, "tpshop": true, "shopnc": true, "niushop": true,
		"taocms": true, "qibosoft": true, "jizhicms": true, "xunruicms": true, "zzzcms": true,
		"smartbi": true, "finereport": true, "aj-report": true, "jsherp": true,
	}
	for _, tech := range plain.Technologies {
		if guarded[tech.RuleID] {
			t.Fatalf("plain response reported %s (%s): %+v", tech.Name, tech.RuleID, tech)
		}
	}
}

// TestAssetRefs 钉住静态资源地址抽取：只收同站、按类型过滤、去重并按 max 截断。
//
// 同站过滤是安全属性——抓第三方 CDN 会给目标之外的站点发请求；rel/as 过滤是成本属性——
// preload 覆盖字体/图片，全抓会把请求花在无关二进制上。
func TestAssetRefs(t *testing.T) {
	body := []byte(`<html><head>
<script src="/js/app.a1b2.js"></script>
<script src="https://static.example.com/js/vendor.js"></script>
<script src="https://cdn.other.com/lib.js"></script>
<script src="/js/app.a1b2.js"></script>
<link rel="modulepreload" href="/assets/index-x.js">
<link rel="stylesheet" href="/css/site.css">
<link rel="preload" as="image" href="/img/hero.png">
<link rel="preload" as="script" href="/js/lazy.js">
</head></html>`)

	got := AssetRefs("https://www.example.com/", body, 10)
	want := []string{
		"https://www.example.com/js/app.a1b2.js",
		"https://static.example.com/js/vendor.js",
		"https://www.example.com/assets/index-x.js",
		"https://www.example.com/css/site.css",
		"https://www.example.com/js/lazy.js",
	}
	if len(got) != len(want) {
		t.Fatalf("AssetRefs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AssetRefs[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if capped := AssetRefs("https://www.example.com/", body, 2); len(capped) != 2 {
		t.Fatalf("max not honored: %v", capped)
	}
	if none := AssetRefs("https://www.example.com/", body, 0); none != nil {
		t.Fatalf("max=0 should disable: %v", none)
	}
}

// TestSameSite 钉住「同站」判定：同 host 或同注册域算同站，跨注册域不算；
// 用 PSL 而非「取末两段」，故 .co.uk 这类多段后缀不会被误判。
func TestSameSite(t *testing.T) {
	cases := []struct {
		base, abs string
		want      bool
	}{
		{"www.example.com", "www.example.com", true},
		{"www.example.com", "static.example.com", true},
		{"www.example.com", "example.com", true},
		{"www.example.com", "cdn.other.com", false},
		{"a.example.co.uk", "b.example.co.uk", true},
		{"a.example.co.uk", "b.example.co.jp", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"www.example.com", "", false},
	}
	for _, c := range cases {
		if got := sameSite(c.base, c.abs); got != c.want {
			t.Fatalf("sameSite(%q, %q) = %v, want %v", c.base, c.abs, got, c.want)
		}
	}
}

// TestMatchAssets 钉住两件与「资源内容 ≠ 站点身份」直接相关的纪律：
// 命中可信度一律压到 probable（因而不会进入 gating 的 CertainTokens 产生否定跳过），
// 且证据里必须带上「来自哪个资源」。
func TestMatchAssets(t *testing.T) {
	db := &DB{Rules: []*Rule{{
		ID:       "vue",
		Name:     "Vue.js",
		Category: "js-framework",
		Match:    []MatchRule{{Source: SourceBody, Pattern: `vue\.runtime`, Confidence: "certain"}},
	}}}
	if err := db.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := NewMatcher(db)

	res := m.MatchAssets([]Asset{{
		URL:  "https://h.example/assets/index-a1b2.js",
		Body: []byte("var x=1;/*vue.runtime.esm-bundler*/"),
	}})
	if len(res.Technologies) != 1 {
		t.Fatalf("technologies = %+v", res.Technologies)
	}
	tech := res.Technologies[0]
	if tech.Name != "Vue.js" {
		t.Fatalf("name = %q, want Vue.js", tech.Name)
	}
	if tech.Confidence != ConfidenceProbable {
		t.Fatalf("confidence = %v, want probable (asset content must not be certain)", tech.Confidence)
	}
	if !strings.Contains(tech.Evidence, "/assets/index-a1b2.js") {
		t.Fatalf("evidence should point at the asset: %q", tech.Evidence)
	}
}

// TestResultMergeDedupKeepsHigherConfidence：首页素材认出的 certain 结论，不该被
// 资源内容匹配出的 probable 同名结论覆盖；新结论则追加进来。
func TestResultMergeDedupKeepsHigherConfidence(t *testing.T) {
	r := Result{
		Technologies: []Technology{{Name: "Vue.js", Confidence: ConfidenceCertain, RuleID: "vue"}},
		Confidence:   ConfidenceCertain,
	}
	r.Merge(Result{
		Technologies: []Technology{
			{Name: "Vue.js", Confidence: ConfidenceProbable, RuleID: "vue", Evidence: "asset /a.js: body: vue"},
			{Name: "Webpack", Confidence: ConfidenceProbable, RuleID: "webpack"},
		},
		Confidence: ConfidenceProbable,
	})
	if len(r.Technologies) != 2 {
		t.Fatalf("technologies = %+v, want 2", r.Technologies)
	}
	for _, tech := range r.Technologies {
		if tech.Name == "Vue.js" && tech.Confidence != ConfidenceCertain {
			t.Fatalf("Vue.js confidence = %v, want certain (dedup must keep the stronger one)", tech.Confidence)
		}
	}
	if r.Confidence != ConfidenceCertain {
		t.Fatalf("overall confidence = %v, want certain", r.Confidence)
	}
}
