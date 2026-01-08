package retryhttpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestDefaultAcceptDisabled(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2, DefaultAccept: false}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	rule := poc.Rule{
		Request: poc.RuleRequest{
			Method: http.MethodGet,
			Path:   "/",
		},
	}
	if err := Request(srv.URL, nil, rule, map[string]any{}); err != nil {
		t.Fatalf("request: %v", err)
	}

	if got != "" {
		t.Fatalf("expected empty Accept, got %q", got)
	}
}

func TestDefaultAcceptEnabledAddsHeader(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2, DefaultAccept: true}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	rule := poc.Rule{
		Request: poc.RuleRequest{
			Method: http.MethodGet,
			Path:   "/",
		},
	}
	if err := Request(srv.URL, nil, rule, map[string]any{}); err != nil {
		t.Fatalf("request: %v", err)
	}

	if got != "*/*" {
		t.Fatalf("expected Accept */*, got %q", got)
	}
}

func TestDefaultAcceptEnabledDoesNotOverridePocAccept(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2, DefaultAccept: true}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	rule := poc.Rule{
		Request: poc.RuleRequest{
			Method: http.MethodGet,
			Path:   "/",
			Headers: map[string]string{
				"accept": "text/html",
			},
		},
	}
	if err := Request(srv.URL, nil, rule, map[string]any{}); err != nil {
		t.Fatalf("request: %v", err)
	}

	if got != "text/html" {
		t.Fatalf("expected Accept text/html, got %q", got)
	}
}
