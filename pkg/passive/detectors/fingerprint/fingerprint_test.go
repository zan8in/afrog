package fingerprint

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

func newTx(t *testing.T, rawURL string, body []byte, headers http.Header) *passive.CapturedTransaction {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if headers == nil {
		headers = make(http.Header)
	}
	return &passive.CapturedTransaction{
		ID:       "t1",
		Request:  &passive.CapturedRequest{Method: "GET", URL: u, Headers: make(http.Header)},
		Response: &passive.CapturedResponse{Status: 200, Headers: headers, Body: body, Duration: 6 * time.Millisecond},
	}
}

// 响应头里的 Server 应被识别为技术栈，产物为 info 级、tech 分类提取物。
func TestFingerprintDetectsNginx(t *testing.T) {
	e := New()
	headers := http.Header{"Server": {"nginx/1.25.3"}}
	got := e.Extract(newTx(t, "https://a.example.com/", []byte("<html><title>hi</title></html>"), headers))

	var nginx *passive.Extraction
	for i := range got {
		if strings.HasPrefix(got[i].Value, "Nginx") {
			nginx = &got[i]
		}
	}
	if nginx == nil {
		t.Fatalf("expected Nginx, got %#v", got)
	}
	if nginx.Detector != DetectorName {
		t.Fatalf("detector = %q, want %q", nginx.Detector, DetectorName)
	}
	if nginx.Category != techCategory {
		t.Fatalf("category = %q, want %q", nginx.Category, techCategory)
	}
	if nginx.Severity != "info" {
		t.Fatalf("severity = %q, want info", nginx.Severity)
	}
	if nginx.Value != "Nginx 1.25.3" {
		t.Fatalf("value = %q, want %q", nginx.Value, "Nginx 1.25.3")
	}
	if nginx.Target != "https://a.example.com" {
		t.Fatalf("target = %q, want origin", nginx.Target)
	}
}

// 无响应的事务不感兴趣：指纹完全依赖响应。
func TestFingerprintInterestNeedsResponse(t *testing.T) {
	e := New()
	u, _ := url.Parse("https://a.example.com/")
	if e.Interest(&passive.CapturedTransaction{Request: &passive.CapturedRequest{URL: u}}) {
		t.Fatal("transaction without response must not be of interest")
	}
	if !e.Interest(newTx(t, "https://a.example.com/", []byte("x"), nil)) {
		t.Fatal("transaction with response should be of interest")
	}
}

// 文本类静态资源（.js 等）不做指纹：避免在门控池里对大体积 JS 反复跑正则。
func TestFingerprintSkipsStaticResource(t *testing.T) {
	e := New()
	txStatic := newTx(t, "https://a.example.com/app.js", []byte("var jQuery=1"), nil)
	txStatic.Static = true
	if e.Interest(txStatic) {
		t.Fatal("static text resource must not be of interest")
	}
}

// 样式表要放行：Tailwind/UnoCSS/Monaco 的判据几乎只出现在 CSS 里。
func TestFingerprintAcceptsStylesheet(t *testing.T) {
	e := New()
	css := newTx(t, "https://a.example.com/app.css", []byte(".a{--tw-rotate:1deg}"), http.Header{"Content-Type": {"text/css"}})
	css.Static = true
	if !e.Interest(css) {
		t.Fatal("stylesheet should be of interest")
	}
	got := e.Extract(css)
	var tailwind bool
	for _, ex := range got {
		if strings.HasPrefix(ex.Value, "Tailwind CSS") {
			tailwind = true
		}
	}
	if !tailwind {
		t.Fatalf("Tailwind CSS not extracted from stylesheet: %#v", got)
	}
}

// 同一 origin 的样式表只在头几个上做匹配：几十个 chunk 都跑一遍没有收益。
func TestFingerprintLimitsStylesheetsPerOrigin(t *testing.T) {
	e := New()
	accepted := 0
	for i := 0; i < maxStaticSamplesPerOrigin+5; i++ {
		tx := newTx(t, "https://a.example.com/app.css", []byte(".a{}"), http.Header{"Content-Type": {"text/css"}})
		tx.Static = true
		if e.Interest(tx) {
			accepted++
		}
	}
	if accepted != maxStaticSamplesPerOrigin {
		t.Fatalf("accepted %d stylesheets, want %d", accepted, maxStaticSamplesPerOrigin)
	}
	// 换一个 origin 不受影响。
	other := newTx(t, "https://b.example.com/app.css", []byte(".a{}"), http.Header{"Content-Type": {"text/css"}})
	other.Static = true
	if !e.Interest(other) {
		t.Fatal("another origin should get its own budget")
	}
}

// favicon 请求只交给 favicon 规则：其二进制正文本不该再参与正文指纹匹配。
func TestFingerprintFaviconPathSkipsBody(t *testing.T) {
	e := New()
	body := []byte(`<meta name="generator" content="WordPress 6.4.2" />`)
	got := e.Extract(newTx(t, "https://a.example.com/favicon.ico", body, nil))
	for _, ex := range got {
		if strings.Contains(ex.Value, "WordPress") {
			t.Fatalf("favicon body must not be matched against body rules: %#v", got)
		}
	}
}
