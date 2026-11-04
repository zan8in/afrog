package recon

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

func tx(t *testing.T, rawURL string, body []byte) *passive.CapturedTransaction {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return &passive.CapturedTransaction{
		ID:       "t1",
		Request:  &passive.CapturedRequest{Method: "GET", URL: u, Headers: make(http.Header)},
		Response: &passive.CapturedResponse{Status: 200, Headers: make(http.Header), Body: body, Duration: 8 * time.Millisecond},
	}
}

func rulesOf(exts []passive.Extraction) map[string][]string {
	out := make(map[string][]string)
	for _, e := range exts {
		out[e.Rule] = append(out[e.Rule], e.Value)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// 五种云厂商的主机式引用都应被识别为云存储桶，URI 形式单列。
func TestReconCloudBuckets(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`{
  "a": "mybucket.s3.amazonaws.com",
  "b": "mybucket.s3.us-east-1.amazonaws.com",
  "c": "myapp.oss-cn-hangzhou.aliyuncs.com",
  "d": "myapp-1250000000.cos.ap-guangzhou.myqcloud.com",
  "e": "myaccount.blob.core.windows.net",
  "f": "https://storage.googleapis.com/mybucket/logo.png",
  "g": "s3://backup-bucket",
  "h": "gs://data-lake"
}`)
	got := rulesOf(e.Extract(tx(t, "https://app.example.com/config.json", body)))

	buckets := got["cloud-bucket"]
	if len(buckets) != 6 {
		t.Fatalf("cloud-bucket = %#v, want 6", buckets)
	}
	for _, want := range []string{
		"mybucket.s3.amazonaws.com",
		"mybucket.s3.us-east-1.amazonaws.com",
		"myapp.oss-cn-hangzhou.aliyuncs.com",
		"myapp-1250000000.cos.ap-guangzhou.myqcloud.com",
		"myaccount.blob.core.windows.net",
		"storage.googleapis.com/mybucket",
	} {
		if !contains(buckets, want) {
			t.Fatalf("cloud-bucket missing %q: %#v", want, buckets)
		}
	}

	uris := got["cloud-bucket-uri"]
	if len(uris) != 2 || !contains(uris, "s3://backup-bucket") || !contains(uris, "gs://data-lake") {
		t.Fatalf("cloud-bucket-uri = %#v", uris)
	}
}

// 邮箱只保留真实地址：域名噪声（w3.org / example.com）与「长得像域名的文件名」都要剔除。
func TestReconEmailFiltersNoise(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`reach alice@corp.com, ignore ns@w3.org, x@example.com, sprite@2x.png`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body)))

	emails := got["email"]
	if len(emails) != 1 || emails[0] != "alice@corp.com" {
		t.Fatalf("email = %#v, want [alice@corp.com]", emails)
	}
}

// 接口路径要能提出真实路径，又不把 `/apiaries` 这类更长单词的前缀误当接口。
func TestReconAPIPathBoundary(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`fetch("/api/v1/users"); var a="/apiaries"; const g="/graphql";`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body)))

	paths := got["api-path"]
	if !contains(paths, "/api/v1/users") || !contains(paths, "/graphql") {
		t.Fatalf("api-path = %#v, want /api/v1/users and /graphql", paths)
	}
	if contains(paths, "/api") {
		t.Fatalf("`/apiaries` prefix must be rejected: %#v", paths)
	}
}

// 二进制响应体不参与提取（由引擎的文本性判定拦截）。
func TestReconSkipsBinaryBody(t *testing.T) {
	e := New(DefaultOptions())
	body := append([]byte("alice@corp.com"), 0x00, 0x01, 0x02)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/asset", body)))
	if len(got) != 0 {
		t.Fatalf("binary body should be skipped, got %#v", got)
	}
}

// 同一事务内同一个值只报一条。
func TestReconDedupWithinTransaction(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`{"a":"alice@corp.com","b":"alice@corp.com"}`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body)))
	if len(got["email"]) != 1 {
		t.Fatalf("email should be deduped, got %#v", got["email"])
	}
}
