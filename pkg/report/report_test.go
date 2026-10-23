package report

import (
	"strings"
	"testing"
)

// 技术栈指纹、Server、X-Powered-By 在报告里必须并列可见：
// 早先它们被并成一个字段，命中框架后中间件与语言版本就从报告里消失了。
func TestWebProbeEntriesHtmlKeepsFingerprintAndHeaders(t *testing.T) {
	entries := []WebProbeEntry{{
		Number:      "1",
		URL:         "http://example.com",
		Title:       "My Site",
		Fingerprint: "PHP 8.1.2, ThinkPHP 6.0.13",
		Confidence:  "certain",
		Server:      "Apache/2.4.6 (CentOS)",
		PoweredBy:   "PHP/8.1.2",
	}}

	def := (&Report{Template: DefaultTemplate}).webProbeEntriesHtml(entries)
	for _, want := range []string{
		"webprobe-fingerprint",
		"PHP 8.1.2, ThinkPHP 6.0.13 · certain",
		"Apache/2.4.6 (CentOS)",
		"PHP/8.1.2",
		"My Site",
	} {
		if !strings.Contains(def, want) {
			t.Fatalf("default template missing %q in:\n%s", want, def)
		}
	}

	minimal := (&Report{Template: MinimalTemplate}).webProbeEntriesHtml(entries)
	for _, want := range []string{
		"[My Site]",
		"[PHP 8.1.2, ThinkPHP 6.0.13 · certain]",
		"[Apache/2.4.6 (CentOS),PHP/8.1.2]",
	} {
		if !strings.Contains(minimal, want) {
			t.Fatalf("minimal template missing %q in:\n%s", want, minimal)
		}
	}
}

func TestWebProbeEntriesHtmlWithoutFingerprint(t *testing.T) {
	entries := []WebProbeEntry{{
		Number: "1",
		URL:    "http://example.com",
		Server: "nginx",
	}}

	def := (&Report{Template: DefaultTemplate}).webProbeEntriesHtml(entries)
	if strings.Contains(def, "webprobe-fingerprint") {
		t.Fatalf("未命中指纹时不应出现指纹徽标:\n%s", def)
	}
	if !strings.Contains(def, "nginx") {
		t.Fatalf("Server 头仍应展示:\n%s", def)
	}
}

// 报告需要先给全貌：整批资产的分布（技术栈/中间件/前置层/证书签发）要能一眼看到。
func TestWebProbeEntriesHtmlAggregatesAssets(t *testing.T) {
	entries := []WebProbeEntry{
		{
			Number:       "1",
			URL:          "https://a.example.com",
			Technologies: []string{"PHP", "ThinkPHP"},
			Server:       "nginx/1.25.3",
			WAF:          "Cloudflare",
			TLS:          &WebProbeTLS{Issuer: "Let's Encrypt", Subject: "a.example.com"},
		},
		{
			Number:       "2",
			URL:          "http://b.example.com",
			Technologies: []string{"PHP"},
			Server:       "nginx",
			WAF:          "Cloudflare",
		},
		{
			Number: "3",
			URL:    "http://c.example.com",
			Server: "Apache/2.4.6",
		},
	}

	def := (&Report{Template: DefaultTemplate}).webProbeEntriesHtml(entries)
	for _, want := range []string{
		`class="webprobe-summary"`,
		"3 个",
		"https ×1",
		"PHP ×2",
		"ThinkPHP ×1",
		"nginx ×2",
		"apache ×1",
		"Cloudflare ×2",
		"Let's Encrypt ×1",
	} {
		if !strings.Contains(def, want) {
			t.Fatalf("报告汇总缺少 %q:\n%s", want, def)
		}
	}

	minimal := (&Report{Template: MinimalTemplate}).webProbeEntriesHtml(entries)
	for _, want := range []string{"summary assets=3", "https=1", "tech: PHP(2)", "waf: Cloudflare(2)"} {
		if !strings.Contains(minimal, want) {
			t.Fatalf("minimal 汇总缺少 %q:\n%s", want, minimal)
		}
	}
}
