package runner

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
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
