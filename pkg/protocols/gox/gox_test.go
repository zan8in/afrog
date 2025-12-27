package gox

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
)

func TestMain(m *testing.M) {
	if err := retryhttpclient.Init(&retryhttpclient.Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "retryhttpclient.Init error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestDoHTTP_FullTargetRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{}
	_, err := DoHTTP(http.MethodGet, srv.URL+"/redir", nil, nil, true, variableMap)
	if err != nil {
		t.Fatalf("DoHTTP error: %v", err)
	}

	got, _ := variableMap["fulltarget"].(string)
	want := srv.URL + "/final"
	if got != want {
		t.Fatalf("fulltarget mismatch: got=%q want=%q", got, want)
	}
}

func TestDoHTTP_GlobalHeaderMerge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s\n", r.Host)
		fmt.Fprintf(w, "cookie=%s\n", r.Header.Get("Cookie"))
		fmt.Fprintf(w, "x-foo=%s\n", strings.Join(r.Header.Values("X-Foo"), ","))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{
		"__global_headers": []string{
			"Host: h1.example",
			"Host: h2.example",
			"Cookie: c1=1",
			"Cookie: c2=2",
			"X-Foo: v1",
			"X-Foo: v2",
		},
	}

	resp, err := DoHTTP(http.MethodGet, srv.URL+"/headers", nil, nil, false, variableMap)
	if err != nil {
		t.Fatalf("DoHTTP error: %v", err)
	}

	body := string(resp.GetBody())
	if !strings.Contains(body, "host=h2.example\n") {
		t.Fatalf("host merge mismatch, body=%q", body)
	}
	if !strings.Contains(body, "cookie=c2=2\n") {
		t.Fatalf("cookie merge mismatch, body=%q", body)
	}
	if !strings.Contains(body, "x-foo=v1,v2\n") {
		t.Fatalf("x-foo merge mismatch, body=%q", body)
	}
}

func TestDoHTTP_PostDefaultContentType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "content-type=%s\n", r.Header.Get("Content-Type"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := DoHTTP(http.MethodPost, srv.URL+"/post", []byte("a=1"), nil, false, map[string]any{})
	if err != nil {
		t.Fatalf("DoHTTP error: %v", err)
	}

	body := string(resp.GetBody())
	if !strings.Contains(body, "content-type=application/x-www-form-urlencoded\n") {
		t.Fatalf("content-type mismatch, body=%q", body)
	}
}

func TestFetchLimited_GlobalHeadersAndVars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s\n", r.Host)
		fmt.Fprintf(w, "x-foo=%s\n", strings.Join(r.Header.Values("X-Foo"), ","))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{
		"__global_headers": []string{
			"Host: override.example",
			"X-Foo: v1",
		},
	}

	data, status, _, err := FetchLimited(http.MethodGet, srv.URL+"/headers", nil, nil, false, 0, 0, variableMap)
	if err != nil {
		t.Fatalf("FetchLimited error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status mismatch: got=%d", status)
	}

	body := string(data)
	if !strings.Contains(body, "host=override.example\n") {
		t.Fatalf("host mismatch, body=%q", body)
	}
	if !strings.Contains(body, "x-foo=v1\n") {
		t.Fatalf("x-foo mismatch, body=%q", body)
	}

	ft, _ := variableMap["fulltarget"].(string)
	if ft != srv.URL+"/headers" {
		t.Fatalf("fulltarget mismatch: got=%q want=%q", ft, srv.URL+"/headers")
	}

	reqV := variableMap["request"]
	req, ok := reqV.(*proto.Request)
	if !ok || req == nil {
		t.Fatalf("request type mismatch: %T", reqV)
	}
	if req.GetHeaders()["x-foo"] != "v1" {
		t.Fatalf("request.headers mismatch: got=%q", req.GetHeaders()["x-foo"])
	}
	if !strings.Contains(string(req.GetRaw()), "Host: override.example\n") {
		t.Fatalf("request.raw host mismatch: %q", string(req.GetRaw()))
	}
}

func TestFetchLimited_ContextFromVariableMap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	variableMap := map[string]any{retryhttpclient.ContextVarKey: ctx}
	_, _, _, err := FetchLimited(http.MethodGet, srv.URL, nil, nil, false, 5, 0, variableMap)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestShiroKey_Detect(t *testing.T) {
	keyB64 := "kPH+bIxk5D2deZiIxcaaaA=="
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("decode key error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("rememberMe")
		if err != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if ck.Value == "123" {
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("delete"))
			return
		}

		raw, err := base64.StdEncoding.DecodeString(ck.Value)
		if err != nil || len(raw) < aes.BlockSize || (len(raw)-aes.BlockSize)%aes.BlockSize != 0 {
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("bad"))
			return
		}

		iv := raw[:aes.BlockSize]
		ct := raw[aes.BlockSize:]
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("new cipher error: %v", err)
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)

		unpadded, ok := pkcs7Unpad(pt, aes.BlockSize)
		if !ok || !bytes.Equal(unpadded, shiroCheckPayload) {
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("reject"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("accept"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{}
	if err := shiro_key(srv.URL, variableMap); err != nil {
		t.Fatalf("shiro_key error: %v", err)
	}

	respV := variableMap["response"]
	resp, ok := respV.(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("response type mismatch: %T", respV)
	}
	if !bytes.Contains(resp.GetRaw(), []byte("ShiroKey:"+keyB64)) {
		t.Fatalf("marker not found, raw=%q", string(resp.GetRaw()))
	}

	reqV := variableMap["request"]
	req, ok := reqV.(*proto.Request)
	if !ok || req == nil {
		t.Fatalf("request type mismatch: %T", reqV)
	}
	if !strings.Contains(req.GetHeaders()["cookie"], "rememberMe=") {
		t.Fatalf("cookie not found in request headers: %v", req.GetHeaders())
	}
}

func TestShiroKey_NoBaselineDeleteMe_NoMarker(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{}
	if err := shiro_key(srv.URL, variableMap); err != nil {
		t.Fatalf("shiro_key error: %v", err)
	}

	respV := variableMap["response"]
	resp, ok := respV.(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("response type mismatch: %T", respV)
	}
	if bytes.Contains(resp.GetRaw(), []byte("ShiroKey:")) {
		t.Fatalf("unexpected marker, raw=%q", string(resp.GetRaw()))
	}
}

func TestShiroKey_WAFOnly123_NoMarker(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("rememberMe")
		if err != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if ck.Value == "123" {
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	variableMap := map[string]any{}
	if err := shiro_key(srv.URL, variableMap); err != nil {
		t.Fatalf("shiro_key error: %v", err)
	}

	respV := variableMap["response"]
	resp, ok := respV.(*proto.Response)
	if !ok || resp == nil {
		t.Fatalf("response type mismatch: %T", respV)
	}
	if bytes.Contains(resp.GetRaw(), []byte("ShiroKey:")) {
		t.Fatalf("unexpected marker, raw=%q", string(resp.GetRaw()))
	}
}

func pkcs7Unpad(in []byte, blockSize int) ([]byte, bool) {
	if len(in) == 0 || blockSize <= 0 || len(in)%blockSize != 0 {
		return nil, false
	}
	padLen := int(in[len(in)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(in) {
		return nil, false
	}
	for i := 0; i < padLen; i++ {
		if in[len(in)-1-i] != byte(padLen) {
			return nil, false
		}
	}
	return in[:len(in)-padLen], true
}
