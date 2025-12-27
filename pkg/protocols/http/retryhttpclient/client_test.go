package retryhttpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
)

func TestRequest_GlobalHostHeaderAndLowercaseRequestHeaders(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		t.Fatalf("Init error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{}
	rule := poc.Rule{}
	rule.Request.Method = http.MethodGet
	rule.Request.Path = "/"
	rule.Request.FollowRedirects = false

	err := Request(srv.URL, []string{"Host: override.example", "X-Foo: v1"}, rule, variableMap)
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}

	reqV := variableMap["request"]
	req, ok := reqV.(*proto.Request)
	if !ok || req == nil {
		t.Fatalf("request type mismatch: %T", reqV)
	}

	h := req.GetHeaders()
	if h["x-foo"] != "v1" {
		t.Fatalf("request.headers lowercase mismatch: got=%q", h["x-foo"])
	}

	raw := string(req.GetRaw())
	if raw == "" {
		t.Fatalf("request raw empty")
	}
	if !strings.Contains(raw, "Host: override.example\n") {
		t.Fatalf("raw host mismatch: %q", raw)
	}
}
