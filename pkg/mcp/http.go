package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
		sessions: make(map[string]*streamableSession),
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
// 推送按规范走 GET 的 SSE 流：一个 POST 是「一问一答」，响应只能带回这一次调用的
// 结果，中途没有地方塞通知；因此长任务要中途报进度/日志，客户端得另开一条 GET。
//
//	POST    /mcp   投递请求，回一次响应（通知回 202）
//	GET     /mcp   开服务端推送流（每会话至多一条），进度/日志从这里下发
//	DELETE  /mcp   终止会话，顺带关掉它的推送流
//
// 客户端没开 GET 流时推送就丢弃：进度与日志都是可选增强，缺了不影响结果正确性——
// 长任务仍可用 task.status / task.events 主动拉取（见 Instructions）。
type streamableHandler struct {
	srv   *Server
	token string

	mu       sync.Mutex
	sessions map[string]*streamableSession
}

// streamableSession 是一个 Streamable HTTP 会话。请求/响应各走各的 POST，但服务端
// 主动推送只能经会话的 GET 流送达，所以会话要挂着这条流。
//
// stream 为 nil 表示客户端没开 GET 流（推送被丢弃）。
type streamableSession struct {
	stream *notifyStream
}

// notifyStream 是一条 GET 的 SSE 流。
//
// msgs 由服务端写、GET 处理协程读，且**永不关闭**：关闭它会让「正在发送通知的
// 调用协程」与「终止会话的 DELETE」竞争同一句 send，可能撞上 send on closed channel
// 而 panic。改用 done 单向下发终止信号，发送方 select 到 done 就放弃这条通知。
type notifyStream struct {
	msgs chan []byte
	done chan struct{}
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
		h.handleStream(w, r)
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
		notify := h.notifyFn(sessionID)
		for i := range reqs {
			h.maybeStartSession(w, &reqs[i], sessionID)
			resp, isNotify := h.srv.handle(r.Context(), &reqs[i], notify)
			if !isNotify && resp != nil {
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
	resp, isNotify := h.srv.handle(r.Context(), &req, h.notifyFn(sessionID))
	if isNotify {
		// 通知没有响应体，按规范回 202。
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleStream 实现 GET：一条服务端 → 客户端的 SSE 流，承载
// notifications/progress 与 notifications/message。
//
// 规范要求 GET 必须带 Mcp-Session-Id，且一个会话同时只允许一条流（重复开回 409）。
// 没有可用会话就直接 404，避免客户端挂在一个永远不会来的流上。
func (h *streamableHandler) handleStream(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID == "" || !h.hasSession(sessionID) {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	stream := &notifyStream{msgs: make(chan []byte, 32), done: make(chan struct{})}
	if !h.attachStream(sessionID, stream) {
		http.Error(w, "session already has an active stream", http.StatusConflict)
		return
	}
	defer h.detachStream(sessionID, stream)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// 周期性注释帧兼作保活：中间代理与客户端的读超时都靠它续命。
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-stream.done:
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case msg := <-stream.msgs:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

// notifyFn 返回把服务端通知投递到该会话 GET 流的回调。
//
// 没有会话（客户端没走 initialize，或没带 Mcp-Session-Id）时返回 nil：此时传输确实
// 没有可推送的通道，工具侧会跳过进度/日志接线（见 callTool）。开了会话但没开 GET 流
// 的情况不返回 nil——通知会被静默丢弃，但工具不必为「客户端没听」改变行为。
func (h *streamableHandler) notifyFn(sessionID string) notifyFunc {
	if sessionID == "" || !h.hasSession(sessionID) {
		return nil
	}
	return func(method string, params any) {
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
		if err != nil {
			return
		}
		h.deliverTo(sessionID, b)
	}
}

// deliverTo 把一条通知写进会话的 GET 流。没有流就丢弃。
func (h *streamableHandler) deliverTo(sessionID string, b []byte) {
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	var stream *notifyStream
	if ok {
		stream = sess.stream
	}
	h.mu.Unlock()
	if stream == nil {
		return
	}
	select {
	case stream.msgs <- b:
	case <-stream.done:
	case <-time.After(5 * time.Second):
		// 客户端读得太慢：丢弃这一条，不阻塞发起调用的 HTTP 处理协程。
	}
}

// attachStream 把 GET 流挂到会话上；会话已经有流则返回 false。
func (h *streamableHandler) attachStream(sessionID string, stream *notifyStream) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok || sess.stream != nil {
		return false
	}
	sess.stream = stream
	return true
}

// detachStream 在 GET 流结束时摘掉它（客户端断开、会话终止、服务端关停都会走到）。
func (h *streamableHandler) detachStream(sessionID string, stream *notifyStream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sess, ok := h.sessions[sessionID]; ok && sess.stream == stream {
		sess.stream = nil
	}
}

func (h *streamableHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID != "" {
		h.mu.Lock()
		if sess, ok := h.sessions[sessionID]; ok {
			// 终止会话时先让它的 GET 流收尾：done 是单向信号，发送方据此放弃未发出的通知。
			if sess.stream != nil {
				close(sess.stream.done)
				sess.stream = nil
			}
			delete(h.sessions, sessionID)
		}
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
	h.sessions[id] = &streamableSession{}
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
