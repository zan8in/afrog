package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// newHTTPMux 把两种 HTTP 传输挂到同一个监听上：
//
//	/sse + /messages  经典 HTTP+SSE（2024-11-05）
//	/mcp              Streamable HTTP（2025-03-26 起）
//
// 工具、策略、预算、会话互不影响，客户端按自己支持的协议选入口即可。
func newHTTPMux(srv *Server, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	sse := NewSSEHandler(srv, token)
	mux.Handle("/sse", withOriginGuard(http.HandlerFunc(sse.handleSSE)))
	mux.Handle("/messages", withOriginGuard(http.HandlerFunc(sse.handleMessage)))

	mux.Handle("/mcp", withOriginGuard(&streamableHandler{
		srv:      srv,
		token:    strings.TrimSpace(token),
		sessions: make(map[string]struct{}),
	}))
	return mux
}

// withOriginGuard 拦掉「浏览器发起的跨站请求」。
//
// MCP 规范要求 Streamable HTTP 服务端校验 Origin（防 DNS rebinding）：本机监听尤其
// 需要——否则任意网页都能借浏览器把请求打进来，驱动这个具备发包能力的本地服务。
// 判定见 originAllowed：没有 Origin 的（curl、原生客户端、stdio）一律放行，只有
// 「带 Origin 且既非本机来源、又非同源」才拒绝。它不替代 token 鉴权，两者叠加。
func withOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed 判断请求来源是否可信：
//   - 没有 Origin 头：非浏览器客户端（curl、MCP 原生客户端），放行；
//   - Origin 为 "null"：来自 sandbox iframe / file:// 这类无来源上下文，正是需
//     要防的一类，拒绝；
//   - Origin 主机是本机（localhost / 127.0.0.0/8 / ::1）：放行；
//   - Origin 主机与请求 Host 相同（同源，只是端口可能不同）：放行；
//   - 其余：拒绝。
func originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return false
	}
	if isLoopbackAddr(host) {
		return true
	}
	reqHost, _, err := net.SplitHostPort(strings.TrimSpace(r.Host))
	if err != nil {
		reqHost = strings.TrimSpace(r.Host)
	}
	return strings.EqualFold(host, reqHost)
}

// tokenAllowed 是两种 HTTP 传输共用的鉴权判定，使用常量时间比较避免时序泄露。
func tokenAllowed(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	provided := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		provided = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if provided == "" {
		provided = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

// streamableHandler 实现 MCP Streamable HTTP：一个端点承载请求/响应与通知。
//
// 本服务没有服务端主动推送的需求，因此不提供 GET 的 SSE 流（按规范返回 405）。
// 一个 POST 就是「一问一答」，中途没有地方塞通知，所以进度通知在本传输下不可用
// （notify 传 nil）；需要进度的客户端走 /sse 或 stdio。
type streamableHandler struct {
	srv   *Server
	token string

	mu       sync.Mutex
	sessions map[string]struct{}
}

func (h *streamableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !tokenAllowed(r, h.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodGet:
		// 没有服务端推送流；按规范用 405 明确拒绝，避免客户端挂死等待。
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "server-initiated stream is not supported", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "POST, GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *streamableHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID != "" && !h.hasSession(sessionID) {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// JSON-RPC 批量请求：依次处理，只回有 id 的那些。
	if body[0] == '[' {
		var reqs []request
		if err := json.Unmarshal(body, &reqs); err != nil {
			writeRPCError(w, http.StatusBadRequest, codeParseError, "parse error")
			return
		}
		responses := make([]*response, 0, len(reqs))
		for i := range reqs {
			h.maybeStartSession(w, &reqs[i], sessionID)
			resp, notify := h.srv.handle(r.Context(), &reqs[i], nil)
			if !notify && resp != nil {
				responses = append(responses, resp)
			}
		}
		if len(responses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, responses)
		return
	}

	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, codeParseError, "parse error")
		return
	}

	h.maybeStartSession(w, &req, sessionID)
	resp, notify := h.srv.handle(r.Context(), &req, nil)
	if notify {
		// 通知没有响应体，按规范回 202。
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *streamableHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID != "" {
		h.mu.Lock()
		delete(h.sessions, sessionID)
		h.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// maybeStartSession 在 initialize 时分配会话 id，并通过响应头回给客户端。
func (h *streamableHandler) maybeStartSession(w http.ResponseWriter, req *request, current string) {
	if req.Method != "initialize" || current != "" {
		return
	}
	id, err := sessionID()
	if err != nil {
		return
	}
	h.mu.Lock()
	h.sessions[id] = struct{}{}
	h.mu.Unlock()
	w.Header().Set("Mcp-Session-Id", id)
}

func (h *streamableHandler) hasSession(id string) bool {
	if id == "" {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.sessions[id]
	return ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRPCError(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, response{JSONRPC: "2.0", Error: &rpcError{Code: code, Message: message}})
}
