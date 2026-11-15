package observation

import (
	"strings"
	"testing"
)

func TestNewIsContentAddressed(t *testing.T) {
	payload := HTTPTransaction{
		Method: "GET", URL: "http://a.example/x", Status: 200, Matched: true,
		LatencyMs: 12, RequestExcerpt: "GET /x", ResponseExcerpt: "HTTP/1.1 200 OK",
	}
	first, err := New("p1", SourceHTTP, KindHTTPTransaction, "http://a.example", payload)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !strings.HasPrefix(first.ID, "obs_") {
		t.Fatalf("id = %q, want obs_ prefix", first.ID)
	}

	// 延迟与片段抖动不应产生新事实。
	payload.LatencyMs = 9876
	payload.RequestExcerpt = "GET /x HTTP/1.1"
	payload.ResponseExcerpt = "changed"
	second, err := New("p1", SourceHTTP, KindHTTPTransaction, "http://a.example", payload)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if second.ID != first.ID || second.Digest != first.Digest {
		t.Fatalf("id/digest drifted: %s/%s vs %s/%s", first.ID, first.Digest, second.ID, second.Digest)
	}

	// 真正的差异必须换 id。
	payload.Matched = false
	third, err := New("p1", SourceHTTP, KindHTTPTransaction, "http://a.example", payload)
	if err != nil {
		t.Fatalf("new third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatal("matched change must produce a new observation id")
	}
}

// 指纹集合的遍历顺序不该改变 id：同一份技术栈重扫必须归并为一条观测。
func TestNewIsOrderInsensitiveForTech(t *testing.T) {
	techs := []Technology{{Name: "Nginx", Version: "1.25"}, {Name: "PHP", Version: "8.2"}}
	first, err := New("", SourceWebscan, KindTech, "http://a.example", Tech{
		URL: "http://a.example", Technologies: techs, WAF: []string{"Cloudflare", "SafeDog"},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	second, err := New("", SourceWebscan, KindTech, "http://a.example", Tech{
		URL:          "http://a.example",
		Technologies: []Technology{techs[1], techs[0]},
		WAF:          []string{"SafeDog", "Cloudflare"},
	})
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("id depends on ordering: %s vs %s", first.ID, second.ID)
	}
}

// 被动观测的身份只由「方法 + URL + 状态码」决定：响应大小、Content-Type、来源 IP
// 都会随流量抖动，把它们算进 id 会让同一次往返反复新增行。
func TestNewHTTPPassiveIdentity(t *testing.T) {
	base := HTTPPassive{Method: "GET", URL: "http://a.example/item?id=1", Status: 200}
	first, err := New("p1", SourcePassive, KindHTTPPassive, "http://a.example/item", base)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	noisy := base
	noisy.ResponseBytes = 4096
	noisy.RequestBytes = 128
	noisy.ContentType = "text/html; charset=utf-8"
	noisy.ClientIP = "10.0.0.2"
	second, err := New("p1", SourcePassive, KindHTTPPassive, "http://a.example/item", noisy)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("抖动字段不应改变 id: %s vs %s", first.ID, second.ID)
	}

	// 真正的差异必须换 id。
	changed := base
	changed.Status = 500
	third, err := New("p1", SourcePassive, KindHTTPPassive, "http://a.example/item", changed)
	if err != nil {
		t.Fatalf("new third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatal("状态码变化必须产生新的观测 id")
	}
	changed = base
	changed.Method = "POST"
	fourth, err := New("p1", SourcePassive, KindHTTPPassive, "http://a.example/item", changed)
	if err != nil {
		t.Fatalf("new fourth: %v", err)
	}
	if fourth.ID == first.ID {
		t.Fatal("方法变化必须产生新的观测 id")
	}
}

// 证书摘要的身份不依赖 SAN 顺序；但续期换了到期时间必须算新事实。
func TestNewTLSCertIdentity(t *testing.T) {
	base := TLSCert{
		URL: "https://a.example", Subject: "CN=a.example", Issuer: "CN=R3",
		NotAfter: "2027-01-01T00:00:00Z", DNSNames: []string{"a.example", "www.a.example"},
	}
	first, err := New("", SourceWebscan, KindTLS, "https://a.example", base)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	reordered := base
	reordered.DNSNames = []string{"www.a.example", "a.example"}
	second, err := New("", SourceWebscan, KindTLS, "https://a.example", reordered)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("SAN 顺序不应改变 id: %s vs %s", first.ID, second.ID)
	}

	renewed := base
	renewed.NotAfter = "2028-01-01T00:00:00Z"
	third, err := New("", SourceWebscan, KindTLS, "https://a.example", renewed)
	if err != nil {
		t.Fatalf("new third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatal("到期时间变化必须产生新的观测 id")
	}
}

// 回连摘要里的时间与来源 IP 每次都不同，不能算进身份；换 PoC 才算新事实。
func TestNewOOBHitIdentity(t *testing.T) {
	base := OOBHit{
		FilterType: "dns", Filter: "abc.oob.example", Token: "t1",
		Target: "https://a.example", PocID: "CVE-2024-1", Evidence: "1.2.3.4 at 10:00",
	}
	first, err := New("", SourceOOB, KindOOBHit, "https://a.example", base)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	again := base
	again.Evidence = "5.6.7.8 at 11:00"
	second, err := New("", SourceOOB, KindOOBHit, "https://a.example", again)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("回连摘要抖动不应改变 id: %s vs %s", first.ID, second.ID)
	}

	otherPoc := base
	otherPoc.PocID = "CVE-2024-2"
	third, err := New("", SourceOOB, KindOOBHit, "https://a.example", otherPoc)
	if err != nil {
		t.Fatalf("new third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatal("换 PoC 必须产生新的观测 id")
	}
}

// 解析结果的地址顺序取决于解析器与 DNS 轮询，不能改变 id；换主机名才是新事实。
func TestNewDNSIdentity(t *testing.T) {
	base := DNS{Host: "a.example", Addresses: []string{"1.2.3.4", "5.6.7.8"}}
	first, err := New("", SourceWebscan, KindDNS, "a.example", base)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	reordered := base
	reordered.Addresses = []string{"5.6.7.8", "1.2.3.4"}
	second, err := New("", SourceWebscan, KindDNS, "a.example", reordered)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("地址顺序不应改变 id: %s vs %s", first.ID, second.ID)
	}

	other := base
	other.Host = "b.example"
	third, err := New("", SourceWebscan, KindDNS, "b.example", other)
	if err != nil {
		t.Fatalf("new third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatal("换主机名必须产生新的观测 id")
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	if _, err := New("", SourceHTTP, KindTech, "  ", Tech{}); err == nil {
		t.Fatal("empty subject must be rejected")
	}
	if _, err := New("", SourceHTTP, "unknown", "http://a.example", struct{ X int }{1}); err == nil {
		t.Fatal("unknown payload type must be rejected")
	}
}

func TestNewCompressesOversizedPayload(t *testing.T) {
	payload := HTTPTransaction{
		Method: "GET", URL: "http://a.example/x",
		RequestExcerpt:  strings.Repeat("a", payloadLimit),
		ResponseExcerpt: strings.Repeat("b", payloadLimit),
	}
	obs, err := New("", SourceHTTP, KindHTTPTransaction, "http://a.example", payload)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if len(obs.Payload) > payloadLimit {
		t.Fatalf("payload = %d bytes, want <= %d", len(obs.Payload), payloadLimit)
	}
	body := string(obs.Payload)
	if !strings.Contains(body, `"truncated":true`) {
		t.Fatalf("oversized payload must be marked truncated: %s", body[:120])
	}
}

func TestExcerptCutsOnRuneBoundary(t *testing.T) {
	if got := Excerpt("hello", 10); got != "hello" {
		t.Fatalf("short text must be untouched, got %q", got)
	}

	// 「观测」每个汉字 3 字节；limit=4 只能落在第一个字之后。
	got := Excerpt("观测流", 4)
	if !strings.HasSuffix(got, "…[truncated]") {
		t.Fatalf("missing truncation marker: %q", got)
	}
	if !strings.HasPrefix(got, "观") || strings.HasPrefix(got, "观测流") {
		t.Fatalf("cut not on rune boundary: %q", got)
	}
}

func TestSubjectHelpers(t *testing.T) {
	if got := HostPortSubject("::1", 443); got != "[::1]:443" {
		t.Fatalf("ipv6 subject = %q", got)
	}
	if got := HostPortSubject(" ", 80); got != "" {
		t.Fatalf("blank host subject = %q", got)
	}
	if got := EndpointSubject("HTTP://Example.COM/a"); got == "" || strings.Contains(got, "Example") {
		t.Fatalf("endpoint subject not normalized: %q", got)
	}
	if got := EndpointSubject("not a url"); got != "not a url" {
		t.Fatalf("non-url subject should pass through, got %q", got)
	}
}
