package runner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

func TestDefaultUploadVarsInjected(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte(r.Header.Get("X-Boundary") + "\n" + string(body)))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: upload-default-vars
info:
  name: upload-default-vars
  author: test
  severity: info
rules:
  r0:
    request:
      method: POST
      path: /
      headers:
        X-Boundary: "{{rboundary}}"
      body: |
        filename={{rfilename}}
        marker={{rbody}}
    expression: |
      response.status == 200 &&
      response.body.bcontains(bytes(rboundary)) &&
      response.body.bcontains(bytes(rfilename)) &&
      response.body.bcontains(bytes(rbody))
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
		MaxHostError:    3,
	}
	opt.Targets.Append(srv.URL)
	opt.Targets.SetNum(srv.URL, ActiveTarget)

	c := &Checker{
		Options:     opt,
		VariableMap: map[string]any{},
		Result:      &result.Result{},
		CustomLib:   NewCustomLib(),
	}

	if err := c.Check(srv.URL, pocItem); err != nil {
		t.Fatalf("checker check error: %v", err)
	}
	if !c.Result.IsVul {
		t.Fatalf("expected IsVul=true, got false")
	}

	for _, key := range []string{"rboundary", "rfilename", "rbody"} {
		v, ok := c.VariableMap[key].(string)
		if !ok || v == "" {
			t.Fatalf("expected %s to be a non-empty string, got %#v", key, c.VariableMap[key])
		}
	}
}

func TestDefaultUploadVarsCanBeOverriddenBySet(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte(r.Header.Get("X-Boundary") + "\n" + string(body)))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: upload-default-vars-override
info:
  name: upload-default-vars-override
  author: test
  severity: info
set:
  rboundary: fixedboundary
  rfilename: fixedfile
  rbody: fixedmarker
rules:
  r0:
    request:
      method: POST
      path: /
      headers:
        X-Boundary: "{{rboundary}}"
      body: |
        filename={{rfilename}}
        marker={{rbody}}
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"fixedboundary") &&
      response.body.bcontains(b"fixedfile") &&
      response.body.bcontains(b"fixedmarker")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
		MaxHostError:    3,
	}
	opt.Targets.Append(srv.URL)
	opt.Targets.SetNum(srv.URL, ActiveTarget)

	c := &Checker{
		Options:     opt,
		VariableMap: map[string]any{},
		Result:      &result.Result{},
		CustomLib:   NewCustomLib(),
	}

	if err := c.Check(srv.URL, pocItem); err != nil {
		t.Fatalf("checker check error: %v", err)
	}
	if !c.Result.IsVul {
		t.Fatalf("expected IsVul=true, got false")
	}

	if got := c.VariableMap["rboundary"]; got != "fixedboundary" {
		t.Fatalf("expected set rboundary override, got %#v", got)
	}
	if got := c.VariableMap["rfilename"]; got != "fixedfile" {
		t.Fatalf("expected set rfilename override, got %#v", got)
	}
	if got := c.VariableMap["rbody"]; got != "fixedmarker" {
		t.Fatalf("expected set rbody override, got %#v", got)
	}

	// Confirm the response echoed the overridden values instead of generated defaults.
	rawResp, ok := c.VariableMap["response"].(*proto.Response)
	if ok && !strings.Contains(string(rawResp.Body), "fixedboundary") {
		t.Fatalf("expected echoed response to contain fixedboundary, got %q", string(rawResp.Body))
	}
}

// TestDeclareRuntimeVars 验证运行期写入变量表的键（如 javascript 的 ExportAs 产物）
// 能被 rule expression 直接引用，且不会覆盖已有的类型声明。
func TestDeclareRuntimeVars(t *testing.T) {
	c := &Checker{
		VariableMap: map[string]any{
			"banner":        "SSH-2.0-OpenSSH_9.6",
			"code":          int64(220),
			"response_text": "hello",
			"Host":          "1.2.3.4",
			"bad-key":       "ignored",
		},
		CustomLib: NewCustomLib(),
	}
	// 预先声明的键不应被动态类型覆盖
	c.CustomLib.UpdateCompileOption("Host", decls.String)

	c.declareRuntimeVars()

	out, err := c.CustomLib.RunEval(
		`banner.contains("OpenSSH") && code == 220 && response_text.contains("hello")`, c.VariableMap)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if b, ok := out.Value().(bool); !ok || !b {
		t.Fatalf("expected true, got %#v", out.Value())
	}

	if got := c.CustomLib.varTypes["Host"]; got != decls.String {
		t.Fatalf("existing declaration overwritten: %#v", got)
	}
	if _, ok := c.CustomLib.varTypes["response_text"]; ok {
		t.Fatalf("response_text should not be re-declared")
	}
	if _, ok := c.CustomLib.varTypes["bad-key"]; ok {
		t.Fatalf("invalid identifier should be skipped")
	}
}

// TestDeclareJSExportVars 验证脚本里的 ExportAs 键会被预声明并给出空串默认值，
// 因此未执行到的分支不会导致 expression 编译失败。
func TestDeclareJSExportVars(t *testing.T) {
	c := &Checker{VariableMap: map[string]any{}, CustomLib: NewCustomLib()}
	c.declareJSExportVars(`
		if (false) { ExportAs("banner", "SSH-2.0"); }
		ExportAs('status', 220);
	`)

	out, err := c.CustomLib.RunEval(`banner == "" && status == ""`, c.VariableMap)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if b, ok := out.Value().(bool); !ok || !b {
		t.Fatalf("expected true, got %#v", out.Value())
	}
}
