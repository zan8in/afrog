package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSETransport(t *testing.T) {
	srv := newTestServer()
	ts := httptest.NewServer(NewSSEHandler(srv, "").Routes())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect sse: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("unexpected content type: %q", ct)
	}

	reader := bufio.NewReader(resp.Body)
	endpoint := readSSEData(t, reader, "endpoint")
	if !strings.Contains(endpoint, "/messages?sessionId=") {
		t.Fatalf("unexpected endpoint: %q", endpoint)
	}

	postResp, err := http.Post(ts.URL+endpoint, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatalf("post message: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("post status = %d, want 202", postResp.StatusCode)
	}

	msg := readSSEData(t, reader, "message")
	var out struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("decode message: %v (%s)", err, msg)
	}
	if out.Result.ProtocolVersion == "" || out.Result.ServerInfo.Name != "afrog" {
		t.Fatalf("unexpected initialize result: %s", msg)
	}
}

func TestSSERequiresToken(t *testing.T) {
	srv := newTestServer()
	ts := httptest.NewServer(NewSSEHandler(srv, "secret").Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/sse")
	if err != nil {
		t.Fatalf("get sse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:16870", true},
		{"localhost:16870", true},
		{"[::1]:16870", true},
		{"0.0.0.0:16870", false},
		{":16870", false},
		{"192.168.1.10:16870", false},
	}
	for _, c := range cases {
		if got := isLoopbackAddr(c.addr); got != c.want {
			t.Fatalf("isLoopbackAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func readSSEData(t *testing.T, r *bufio.Reader, event string) string {
	t.Helper()
	current := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read sse (waiting %q): %v", event, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "event: ") {
			current = strings.TrimPrefix(line, "event: ")
			continue
		}
		if strings.HasPrefix(line, "data: ") && current == event {
			return strings.TrimPrefix(line, "data: ")
		}
	}
}
