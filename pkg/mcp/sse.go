package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// sseHandler 实现 MCP 的 HTTP+SSE 传输：
//
//	GET  /sse           建立事件流，首帧 endpoint 告知消息投递地址
//	POST /messages      投递一条 JSON-RPC 请求，响应从事件流回传
//
// 与 stdio 传输共用同一个 Server，因此工具、策略、预算完全一致。
type sseHandler struct {
	srv   *Server
	token string

	mu       sync.Mutex
	sessions map[string]chan []byte
}

// NewSSEHandler 创建一个 SSE 传输处理器。
func NewSSEHandler(srv *Server, token string) *sseHandler {
	return &sseHandler{
		srv:      srv,
		token:    strings.TrimSpace(token),
		sessions: make(map[string]chan []byte),
	}
}

// Routes 返回挂载了 /sse 与 /messages 的 HTTP 处理器。
func (h *sseHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/sse", h.handleSSE)
	mux.HandleFunc("/messages", h.handleMessage)
	return mux
}

func (h *sseHandler) authorized(r *http.Request) bool {
	return tokenAllowed(r, h.token)
}

func (h *sseHandler) handleSSE(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	id, err := sessionID()
	if err != nil {
		http.Error(w, "cannot create session", http.StatusInternalServerError)
		return
	}
	ch := make(chan []byte, 32)
	h.addSession(id, ch)
	defer h.removeSession(id)

	// 登记该会话的服务端推送通道：SSE 是长连接，资源订阅的变更通知在调用之外
	// （如后台长任务收尾）也能推到这条事件流上。
	unregisterPush := h.srv.RegisterResourcePush(id, h.notifyFn(ch))
	defer unregisterPush()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	endpoint := strings.TrimSuffix(r.URL.Path, "/sse") + "/messages?sessionId=" + id
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case msg := <-ch:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (h *sseHandler) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("sessionId")
	ch, ok := h.session(id)
	if !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		h.deliver(ch, &response{JSONRPC: "2.0", Error: &rpcError{Code: codeParseError, Message: "parse error"}})
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp, notify := h.srv.handle(withSession(r.Context(), id), &req, h.notifyFn(ch))
	if !notify && resp != nil {
		h.deliver(ch, resp)
	}
	w.WriteHeader(http.StatusAccepted)
}

// notifyFn 让一次调用在跑的过程中把服务端通知（notifications/progress、
// notifications/message）推进该会话的事件流：SSE 是长连接，中途有地方塞通知，
// 这是它相对 Streamable HTTP 的优势。资源变更通知则经 RegisterResourcePush 登记，
// 可在调用之外送达。
func (h *sseHandler) notifyFn(ch chan []byte) notifyFunc {
	return func(method string, params any) {
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
		if err != nil {
			return
		}
		h.deliverRaw(ch, b)
	}
}

func (h *sseHandler) deliver(ch chan []byte, resp *response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	h.deliverRaw(ch, b)
}

func (h *sseHandler) deliverRaw(ch chan []byte, b []byte) {
	select {
	case ch <- b:
	case <-time.After(5 * time.Second):
		// 客户端读得太慢时丢弃单条消息，避免阻塞 HTTP 处理协程；
		// MCP 客户端会因超时重试请求。
	}
}

func (h *sseHandler) addSession(id string, ch chan []byte) {
	h.mu.Lock()
	h.sessions[id] = ch
	h.mu.Unlock()
}

func (h *sseHandler) removeSession(id string) {
	h.mu.Lock()
	delete(h.sessions, id)
	h.mu.Unlock()
}

func (h *sseHandler) session(id string) (chan []byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.sessions[id]
	return ch, ok
}

func sessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
