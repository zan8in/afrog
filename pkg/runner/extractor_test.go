package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

func newExtractorChecker() *Checker {
	return &Checker{
		VariableMap: map[string]any{
			"response": &proto.Response{
				Status:    200,
				Body:      []byte(`{"code":0,"data":{"version":"1.2.3","tags":["a","b"]}}`),
				Raw:       []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\n\r\nbody"),
				RawHeader: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\nContent-Type: application/json\r\n"),
				Headers:   map[string]string{"Server": "nginx/1.2", "Content-Type": "application/json"},
			},
			"response_text": "hello world 42 and 43",
		},
		Result:    &result.Result{},
		CustomLib: NewCustomLib(),
	}
}

func TestTypedExtractorRegex(t *testing.T) {
	cases := []struct {
		name  string
		ex    poc.Extractors
		want  any
		isStr bool
	}{
		{
			name:  "named group",
			ex:    poc.Extractors{Name: "ver", Type: "regex", Part: "body", Regex: `"version":"(?P<v>[0-9.]+)"`, Group: "v"},
			want:  "1.2.3",
			isStr: true,
		},
		{
			name:  "whole match",
			ex:    poc.Extractors{Name: "ver", Type: "regex", Part: "body", Regex: `[0-9]+\.[0-9]+\.[0-9]+`},
			want:  "1.2.3",
			isStr: true,
		},
		{
			name:  "numeric group",
			ex:    poc.Extractors{Name: "ver", Type: "regex", Part: "body", Regex: `"version":"([0-9.]+)"`, Group: "1"},
			want:  "1.2.3",
			isStr: true,
		},
		{
			name: "all matches",
			ex:   poc.Extractors{Name: "nums", Type: "regex", Part: "text", Regex: `\d+`, All: true},
			want: []string{"42", "43"},
		},
		{
			name:  "no match yields empty",
			ex:    poc.Extractors{Name: "missing", Type: "regex", Part: "body", Regex: `"nope":"(?P<v>x)"`, Group: "v"},
			want:  "",
			isStr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newExtractorChecker()
			c.UpdateVariableMapExtractor([]poc.Extractors{tc.ex})
			got := c.VariableMap[tc.ex.Name]
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %T(%#v), want %T(%#v)", got, got, tc.want, tc.want)
			}
		})
	}
}

func TestTypedExtractorJSON(t *testing.T) {
	c := newExtractorChecker()
	c.UpdateVariableMapExtractor([]poc.Extractors{
		{Name: "dver", Type: "json", Path: "$.data.version"},
		{Name: "tag0", Type: "json", Path: "data.tags[0]"},
		{Name: "code", Type: "json", Path: "code"},
	})

	if got := c.VariableMap["dver"]; got != "1.2.3" {
		t.Fatalf("dver = %#v, want 1.2.3", got)
	}
	if got := c.VariableMap["tag0"]; got != "a" {
		t.Fatalf("tag0 = %#v, want a", got)
	}
	if fmt.Sprint(c.VariableMap["code"]) != "0" {
		t.Fatalf("code = %#v, want 0", c.VariableMap["code"])
	}
}

func TestTypedExtractorKval(t *testing.T) {
	c := newExtractorChecker()
	c.UpdateVariableMapExtractor([]poc.Extractors{
		{Name: "server", Type: "kval", Part: "header", Key: "server"}, // 大小写不敏感
		{Name: "server2", Type: "kval", Part: "raw", Key: "Server"},   // 从原始报文行解析
		{Name: "ctype", Type: "kval", Key: "Content-Type"},            // part 缺省为 header
	})

	if got := c.VariableMap["server"]; got != "nginx/1.2" {
		t.Fatalf("server = %#v", got)
	}
	if got := c.VariableMap["server2"]; got != "nginx/1.2" {
		t.Fatalf("server2 = %#v", got)
	}
	if got := c.VariableMap["ctype"]; got != "application/json" {
		t.Fatalf("ctype = %#v", got)
	}
}

func TestTypedExtractorLiteralAndCEL(t *testing.T) {
	c := newExtractorChecker()
	c.VariableMap["user"] = "root"
	c.UpdateVariableMapExtractor([]poc.Extractors{
		{Name: "cred", Type: "literal", Value: "{{user}}/pwd"},
		{Name: "status", Type: "cel", Value: "response.status"},
	})

	if got := c.VariableMap["cred"]; got != "root/pwd" {
		t.Fatalf("cred = %#v", got)
	}
	if fmt.Sprint(c.VariableMap["status"]) != "200" {
		t.Fatalf("status = %#v", c.VariableMap["status"])
	}
}

func TestTypedExtractorReportsToResult(t *testing.T) {
	c := newExtractorChecker()
	c.UpdateVariableMapExtractor([]poc.Extractors{
		{Name: "ver", Type: "regex", Part: "body", Regex: `"version":"(?P<v>[0-9.]+)"`, Group: "v"},
	})
	if len(c.Result.Extractor) != 1 {
		t.Fatalf("expected 1 extractor result, got %d", len(c.Result.Extractor))
	}
	if c.Result.Extractor[0].Key != "ver" || c.Result.Extractor[0].Value != "1.2.3" {
		t.Fatalf("unexpected extractor result: %#v", c.Result.Extractor[0])
	}
}

func TestLegacyExtractorStillWorks(t *testing.T) {
	c := newExtractorChecker()

	// 旧 regex 两步式
	c.UpdateVariableMapExtractor([]poc.Extractors{{
		Type: "regex",
		Extractor: yaml.MapSlice{
			{Key: "ext1", Value: `"\"version\":\"(?P<v>[0-9.]+)\"".bsubmatch(response.body)`},
			{Key: "legacyVer", Value: `ext1["v"]`},
		},
	}})
	if got := c.VariableMap["legacyVer"]; got != "1.2.3" {
		t.Fatalf("legacyVer = %#v, want 1.2.3", got)
	}

	// 旧 word 字面量模板
	c.VariableMap["u"] = "admin"
	c.UpdateVariableMapExtractor([]poc.Extractors{{
		Type:      "word",
		Extractor: yaml.MapSlice{{Key: "pass", Value: "{{u}}-secret"}},
	}})
	if got := c.VariableMap["pass"]; got != "admin-secret" {
		t.Fatalf("pass = %#v, want admin-secret", got)
	}
}

// output 与 extractors 共用核心：output 不写 Result.Extractor，且非字符串值不再 panic。
func TestOutputSharesCoreWithoutReporting(t *testing.T) {
	c := newExtractorChecker()
	c.UpdateVariableMap(yaml.MapSlice{
		{Key: "n", Value: 5},
		{Key: "flag", Value: true},
		{Key: "status", Value: "response.status"},
		{Key: "raw", Value: "not-a-cel-expr {{"}, // 求值失败应回退为字面量
	})

	if got := c.VariableMap["n"]; got != 5 {
		t.Fatalf("n = %#v, want 5", got)
	}
	if got := c.VariableMap["flag"]; got != true {
		t.Fatalf("flag = %#v, want true", got)
	}
	if fmt.Sprint(c.VariableMap["status"]) != "200" {
		t.Fatalf("status = %#v", c.VariableMap["status"])
	}
	if got := c.VariableMap["raw"]; got != "not-a-cel-expr {{" {
		t.Fatalf("raw = %#v, want literal fallback", got)
	}
	if len(c.Result.Extractor) != 0 {
		t.Fatalf("output must not write Result.Extractor, got %#v", c.Result.Extractor)
	}
}

func TestTypedExtractorInvalidNameSkipped(t *testing.T) {
	c := newExtractorChecker()
	// 非法 name（含 -）应被跳过且不 panic
	c.UpdateVariableMapExtractor([]poc.Extractors{
		{Name: "bad-name", Type: "literal", Value: "x"},
	})
	if _, ok := c.VariableMap["bad-name"]; ok {
		t.Fatal("invalid name should be skipped")
	}
}

// 端到端：类型化提取器在真实 HTTP 规则里提取变量，并被顶层 expression 引用。
func TestTypedExtractorEndToEndHTTP(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{Timeout: 5, Retries: 0, MaxRespBodySize: 4096})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App", "demo")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"version":"9.9.9"}}`))
	}))
	defer srv.Close()

	pocYAML := []byte(`
id: typed-extractor-e2e
info:
  name: typed-extractor-e2e
  author: test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /api/version
    expression: response.status == 200
    extractors:
      - name: ver
        type: json
        path: $.data.version
      - name: server
        type: kval
        key: x-app
expression: r0() && ver == "9.9.9" && server == "demo"
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{Timeout: 5, Retries: 0, MaxRespBodySize: 4096, MaxHostError: 3}
	opt.Targets.Append(srv.URL)
	opt.Targets.SetNum(srv.URL, ActiveTarget)

	c := &Checker{
		Options:     opt,
		VariableMap: map[string]any{},
		Result:      &result.Result{},
		CustomLib:   NewCustomLib(),
	}
	if err := c.Check(srv.URL, pocItem); err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !c.Result.IsVul {
		t.Fatalf("expected IsVul=true, extractors=%#v", c.Result.Extractor)
	}
	if got := c.VariableMap["ver"]; got != "9.9.9" {
		t.Fatalf("ver = %#v", got)
	}
	if got := c.VariableMap["server"]; got != "demo" {
		t.Fatalf("server = %#v", got)
	}
	if len(c.Result.Extractor) < 2 {
		t.Fatalf("expected extractor results reported, got %#v", c.Result.Extractor)
	}
}
