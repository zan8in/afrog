package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

func TestHTTPBruteWinnerEarlyStop(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	var mu sync.Mutex
	seen := make([]string, 0, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		mu.Lock()
		seen = append(seen, u)
		mu.Unlock()
		if u == "b" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("WIN"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-test
info:
  name: brute-test
  author: test
  severity: info
rules:
  r0:
    stop_if_match: true
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"WIN")
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

	v, ok := c.VariableMap["user"].(string)
	if !ok || v != "b" {
		t.Fatalf("expected winner user=b, got %#v", c.VariableMap["user"])
	}

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 brute requests (a,b) then early stop, got %d: %#v", len(got), got)
	}
	if got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected brute order [a b], got %#v", got)
	}
}

func TestStopIfMatchSkipsFollowingRules(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 2,
	})

	var mu sync.Mutex
	paths := make([]string, 0, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()

		if r.URL.Path == "/r1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("R1"))
			return
		}

		u := r.URL.Query().Get("u")
		if u == "b" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("WIN"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: stop-if-match-skip-rules
info:
  name: stop-if-match-skip-rules
  author: test
  severity: info
rules:
  r0:
    stop_if_match: true
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /r0?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"WIN")
  r1:
    request:
      method: GET
      path: /r1
    expression: response.status == 700
expression: r0() && r1()
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

	mu.Lock()
	got := append([]string(nil), paths...)
	mu.Unlock()

	for _, p := range got {
		if p == "/r1" {
			t.Fatalf("expected r1 to be skipped, got request to /r1: %#v", got)
		}
	}
}

func TestHTTPBruteNoMatchKeepsLastResponse(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 32,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("u=" + u))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-no-match-keeps-last-response
info:
  name: brute-no-match-keeps-last-response
  author: test
  severity: info
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"NEVER")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 32,
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
	if c.Result.IsVul {
		t.Fatalf("expected IsVul=false, got true")
	}

	resp, ok := c.VariableMap["response"].(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("expected response to be kept, got %#v", c.VariableMap["response"])
	}
	if string(resp.GetBody()) != "u=c" {
		t.Fatalf("expected last response body u=c, got %q", string(resp.GetBody()))
	}
}

func TestHTTPBruteCommitNoneKeepsResponseButNotPayloadVars(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 32,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		w.WriteHeader(http.StatusOK)
		if u == "b" {
			_, _ = w.Write([]byte("WIN"))
			return
		}
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-commit-none
info:
  name: brute-commit-none
  author: test
  severity: info
rules:
  r0:
    stop_if_match: true
    brute:
      mode: clusterbomb
      commit: none
      continue: false
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"WIN")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 32,
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
	if _, exists := c.VariableMap["user"]; exists {
		t.Fatalf("expected brute payload var user to not be committed")
	}

	resp, ok := c.VariableMap["response"].(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("expected response to be kept, got %#v", c.VariableMap["response"])
	}
	if string(resp.GetBody()) != "WIN" {
		t.Fatalf("expected response body WIN, got %q", string(resp.GetBody()))
	}
}

func TestCELUpdateCompileOptionDeduplicatesByName(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("x", decls.String)
	lib.UpdateCompileOption("x", decls.Int)

	val, err := lib.RunEval("x + 1 == 2", map[string]any{"x": int64(1)})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got, ok := val.Value().(bool); !ok || !got {
		t.Fatalf("expected true, got %#v", val)
	}
}

func TestHTTPBruteCommitWinnerContinueKeepsFirstMatch(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 64,
	})

	var mu sync.Mutex
	seen := make([]string, 0, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		mu.Lock()
		seen = append(seen, u)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if u == "b" || u == "c" {
			_, _ = w.Write([]byte("WIN-" + u))
			return
		}
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-commit-winner-continue
info:
  name: brute-commit-winner-continue
  author: test
  severity: info
rules:
  r0:
    stop_if_match: true
    brute:
      mode: clusterbomb
      commit: winner
      continue: true
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"WIN")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 64,
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

	if v, ok := c.VariableMap["user"].(string); !ok || v != "b" {
		t.Fatalf("expected committed user=b, got %#v", c.VariableMap["user"])
	}
	resp, ok := c.VariableMap["response"].(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("expected response, got %#v", c.VariableMap["response"])
	}
	if string(resp.GetBody()) != "WIN-b" {
		t.Fatalf("expected committed response WIN-b, got %q", string(resp.GetBody()))
	}

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected brute order [a b c], got %#v", got)
	}
}

func TestHTTPBruteCommitLastContinueKeepsLastMatch(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 64,
	})

	var mu sync.Mutex
	seen := make([]string, 0, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		mu.Lock()
		seen = append(seen, u)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if u == "b" || u == "c" {
			_, _ = w.Write([]byte("WIN-" + u))
			return
		}
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-commit-last-continue
info:
  name: brute-commit-last-continue
  author: test
  severity: info
rules:
  r0:
    stop_if_match: true
    brute:
      mode: clusterbomb
      commit: last
      continue: true
      user:
        - a
        - b
        - c
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"WIN")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 64,
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

	if v, ok := c.VariableMap["user"].(string); !ok || v != "c" {
		t.Fatalf("expected committed user=c, got %#v", c.VariableMap["user"])
	}
	resp, ok := c.VariableMap["response"].(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("expected response, got %#v", c.VariableMap["response"])
	}
	if string(resp.GetBody()) != "WIN-c" {
		t.Fatalf("expected committed response WIN-c, got %q", string(resp.GetBody()))
	}

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected brute order [a b c], got %#v", got)
	}
}

func TestHTTPBruteMaxRequestsTruncated(t *testing.T) {
	retryhttpclient.Init(&retryhttpclient.Options{
		Proxy:           "",
		Timeout:         5,
		Retries:         0,
		MaxRespBodySize: 64,
	})

	var mu sync.Mutex
	seen := make([]string, 0, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		mu.Lock()
		seen = append(seen, u)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NO"))
	}))
	defer srv.Close()

	var pocYAML = []byte(`
id: brute-max-requests-truncates
info:
  name: brute-max-requests-truncates
  author: test
  severity: info
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: true
      user:
        - a
        - b
        - c
        - d
    request:
      method: GET
      path: /?u={{user}}
    expression: response.status == 200 && response.body.bcontains(b"NEVER")
expression: r0()
`)

	pocItem := &poc.Poc{}
	if err := yaml.Unmarshal(pocYAML, pocItem); err != nil {
		t.Fatalf("unmarshal poc yaml: %v", err)
	}

	opt := &config.Options{
		Timeout:          5,
		Retries:          0,
		MaxRespBodySize:  64,
		MaxHostError:     3,
		BruteMaxRequests: 2,
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
	if c.Result.IsVul {
		t.Fatalf("expected IsVul=false, got true")
	}

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected only first 2 brute requests [a b], got %#v", got)
	}

	if v, ok := c.VariableMap["__brute_truncated_r0"].(bool); !ok || !v {
		t.Fatalf("expected __brute_truncated_r0=true, got %#v", c.VariableMap["__brute_truncated_r0"])
	}

	if len(c.Result.AllPocResult) != 1 {
		t.Fatalf("expected 1 poc result, got %d", len(c.Result.AllPocResult))
	}
	if !c.Result.AllPocResult[0].BruteTruncated {
		t.Fatalf("expected poc result brute truncated true, got false")
	}
	if c.Result.AllPocResult[0].BruteRequests != 2 {
		t.Fatalf("expected brute requests 2, got %d", c.Result.AllPocResult[0].BruteRequests)
	}
}

func TestShouldCountHostError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "context canceled", err: context.Canceled, want: false},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "url deadline exceeded", err: &url.Error{Op: "Get", URL: "http://example.com", Err: context.DeadlineExceeded}, want: true},
		{name: "net op error", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, want: true},
		{name: "eof string", err: errors.New("EOF"), want: true},
		{name: "status not live", err: errors.New("status code is not live 500"), want: false},
		{name: "parse error", err: errors.New("parse \"http://[::1\": missing ']' in host"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldCountHostError(tc.err); got != tc.want {
				t.Fatalf("shouldCountHostError(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
