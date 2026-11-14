package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postStreamable(t *testing.T, url, session, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, data
}

func TestStreamableHTTPInitializeAndTools(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("unexpected content type: %q", ct)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize must return Mcp-Session-Id")
	}

	var init struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &init); err != nil {
		t.Fatalf("decode initialize: %v (%s)", err, body)
	}
	if init.Result.ProtocolVersion != "2025-06-18" {
		t.Fatalf("unexpected protocol version: %q", init.Result.ProtocolVersion)
	}

	// 通知：202 且没有响应体。
	notifyResp, notifyBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if notifyResp.StatusCode != http.StatusAccepted || len(notifyBody) != 0 {
		t.Fatalf("notification = %d %q, want 202 empty", notifyResp.StatusCode, notifyBody)
	}

	// 带会话调 tools/list。
	listResp, listBody := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", listResp.StatusCode, listBody)
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode tools/list: %v (%s)", err, listBody)
	}
	if len(list.Result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %+v", list.Result.Tools)
	}
}

func TestStreamableHTTPBatch(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch status = %d: %s", resp.StatusCode, body)
	}

	var out []struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode batch: %v (%s)", err, body)
	}
	if len(out) != 1 || string(out[0].ID) != "1" {
		t.Fatalf("batch must return only the request with id: %s", body)
	}
}

func TestStreamableHTTPUnknownSession(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, _ := postStreamable(t, ts.URL+"/mcp", "not-a-session",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestStreamableHTTPGetNotAllowed(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestStreamableHTTPDeleteSession(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), ""))
	defer ts.Close()

	_, _ = postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	// 重新拿一个会话 id（initialize 响应头已消费在上面的 helper 里）。
	resp, body := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("missing session id: %s", body)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/mcp", nil)
	req.Header.Set("Mcp-Session-Id", session)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", delResp.StatusCode)
	}

	after, _ := postStreamable(t, ts.URL+"/mcp", session,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("after delete status = %d, want 404", after.StatusCode)
	}
}

func TestStreamableHTTPRequiresToken(t *testing.T) {
	ts := httptest.NewServer(newHTTPMux(newTestServer(), "secret"))
	defer ts.Close()

	resp, _ := postStreamable(t, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
