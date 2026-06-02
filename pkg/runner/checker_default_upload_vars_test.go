package runner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
