package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
// 客户端没开 GET 流时通知只进会话的事件缓冲，等它重连带 Last-Event-ID 再补发：进度与
// 日志都是可选增强，缺了不影响结果正确性——长任务仍可用 task.status / task.events
// 主动拉取（见 Instructions）。这条缓冲也是「GET 流中途断了」的兜底（见 handleStream）。
type streamableHandler struct {
	srv   *Server
	token string

	mu       sync.Mutex
	sessions map[string]*streamableSession

	drops dropCounter
}

// streamableSession 是一个 Streamable HTTP 会话。请求/响应各走各的 POST，但服务端
// 主动推送只能经会话的 GET 流送达，所以会话要挂着这条流。
//
// stream 为 nil 表示客户端暂时没开 GET 流（通知只进 events 缓冲）。
type streamableSession struct {
	// unregisterPush 注销该会话在 Server 上登记的资源变更推送通道（见 handleDelete）。
	unregisterPush func()

	// mu 保护 stream 与 events：stream 会被 GET 的挂载/摘除、DELETE 的收尾与推送方
	// 同时读写；events 则供 GET 重连时按 Last-Event-ID 补发。
	//
	// 加锁顺序固定为「先 handler.mu，再 session.mu」，两个方向都不能反过来。
	mu     sync.Mutex
	stream *notifyStream
	events eventBuffer
}

// closeStream 收尾会话的 GET 流：done 是单向信号，发送方据此放弃未发出的通知。
func (s *streamableSession) closeStream() {
	s.mu.Lock()
	stream := s.stream
	s.stream = nil
	s.mu.Unlock()
	if stream != nil {
		close(stream.done)
	}
}

// notifyStream 是一条 GET 的 SSE 流。
//
// msgs 由服务端写、GET 处理协程读，且**永不关闭**：关闭它会让「正在发送通知的
// 调用协程」与「终止会话的 DELETE」竞争同一句 send，可能撞上 send on closed channel
// 而 panic。改用 done 单向下发终止信号，发送方 select 到 done 就放弃这条通知。
type notifyStream struct {
	msgs chan sseEvent
	done chan struct{}
}

// sseEvent 是一条待下发的 SSE 事件：id 进 `id:` 字段（客户端断线重连时以它作
// Last-Event-ID），data 是 JSON-RPC 报文。
type sseEvent struct {
	id   int
	data []byte
}

// writeSSEMessage 按 SSE 帧格式下发一条消息事件。
func writeSSEMessage(w io.Writer, ev sseEvent) {
	fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", ev.id, ev.data)
}

const (
	// sseResumeEvents 是每个会话保留的最近事件条数，供 Last-Event-ID 续传。
	sseResumeEvents = 128
	// sseResumeMaxBytes 是单条事件的续传上限：更大的报文照常下发，但不进缓冲——
	// 缓冲最多几十条，塞进 MB 级响应只会白占内存。
	sseResumeMaxBytes = 256 << 10
)

// eventBuffer 是会话级的「最近事件」环形缓冲，供 GET 流断线重连时按 Last-Event-ID 补发。
//
// 规范把断线续传定义在 Streamable HTTP 上（经典 HTTP+SSE 传输的会话与连接同生共死，
// 结构上没有地方带 Last-Event-ID），所以只有这里用它。
type eventBuffer struct {
	// max 是保留条数上限，maxLen 是单条事件的字节上限。
	max    int
	maxLen int
	events []sseEvent
	// nextID 是下一个待分配的 id：只增不减，客户端据此判断「有没有漏事件」。
	nextID int
}

func newEventBuffer() eventBuffer {
	return eventBuffer{max: sseResumeEvents, maxLen: sseResumeMaxBytes}
}

// push 给事件分配递增 id 并记进缓冲，返回可直接下发的 sseEvent。
func (b *eventBuffer) push(data []byte) sseEvent {
	ev := sseEvent{id: b.nextID, data: data}
	b.nextID++
	if b.maxLen > 0 && len(data) > b.maxLen {
		return ev
	}
	b.events = append(b.events, ev)
	if len(b.events) > b.max {
		b.events = b.events[len(b.events)-b.max:]
	}
	return ev
}

// since 返回 id 严格大于 lastID 的缓冲事件。
//
// lastID 为空或不是数字时返回 nil：客户端没声明断点（首次连接、或压根不认 id），
// 就不该凭空补发一批它可能已经处理过的事件。
func (b *eventBuffer) since(lastID string) []sseEvent {
	last, err := strconv.Atoi(strings.TrimSpace(lastID))
	if err != nil {
		return nil
	}
	out := make([]sseEvent, 0, len(b.events))
	for _, ev := range b.events {
		if ev.id > last {
			out = append(out, ev)
		}
	}
	return out
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
		ctx := withSession(r.Context(), sessionID)
		for i := range reqs {
			h.maybeStartSession(w, &reqs[i], sessionID)
			resp, isNotify := h.srv.handle(ctx, &reqs[i], notify)
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
	resp, isNotify := h.srv.handle(withSession(r.Context(), sessionID), &req, h.notifyFn(sessionID))
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
//
// 带 Last-Event-ID 重连时，先把缓冲里 id 更大的事件按原 id 补发，再转入实时下发：
// 一次工具调用期间断流，客户端补上即可拿到漏掉的进度/日志，不必等下一次调用才发现
// 自己错过了通知。
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

	stream := &notifyStream{msgs: make(chan sseEvent, 32), done: make(chan struct{})}
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

	for _, ev := range h.eventsSince(sessionID, r.Header.Get("Last-Event-ID")) {
		writeSSEMessage(w, ev)
		flusher.Flush()
	}

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
		case ev := <-stream.msgs:
			writeSSEMessage(w, ev)
			flusher.Flush()
		}
	}
}

// eventsSince 取会话缓冲里 id 大于 lastID 的事件，供 GET 重连补发。
func (h *streamableHandler) eventsSince(sessionID, lastID string) []sseEvent {
	if strings.TrimSpace(lastID) == "" {
		return nil
	}
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.events.since(lastID)
}

// notifyFn 返回把服务端通知投递到该会话 GET 流的回调。
//
// 没有会话（客户端没走 initialize，或没带 Mcp-Session-Id）时返回 nil：此时传输确实
// 没有可推送的通道，工具侧会跳过进度/日志接线（见 callTool）。开了会话但没开 GET 流
// 的情况不返回 nil——通知进会话的续传缓冲，客户端补开流后能按 Last-Event-ID 取回；
// 工具也不必为「客户端暂时没听」改变行为。
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

// deliverTo 把一条通知写进会话的 GET 流，并记进续传缓冲。
//
// 没有流时就只缓冲：客户端重连带 Last-Event-ID 能补回来。有流但客户端读得太慢（5 秒
// 还没读走一条）则丢弃这一条并计数，不阻塞发起调用的 HTTP 处理协程——丢掉的这条仍在
// 缓冲里，客户端重连一样能补回。
func (h *streamableHandler) deliverTo(sessionID string, b []byte) {
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	h.mu.Unlock()
	if !ok {
		return
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	ev := sess.events.push(b)
	stream := sess.stream
	if stream == nil {
		return
	}
	select {
	case stream.msgs <- ev:
	case <-stream.done:
	case <-time.After(deliverTimeout):
		// 客户端读得太慢：丢弃这一条，不阻塞调用协程。
		h.drops.note("streamable-http", sessionID)
	}
}

// attachStream 把 GET 流挂到会话上；会话已经有流则返回 false。
func (h *streamableHandler) attachStream(sessionID string, stream *notifyStream) bool {
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	h.mu.Unlock()
	if !ok {
		return false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.stream != nil {
		return false
	}
	sess.stream = stream
	return true
}

// detachStream 在 GET 流结束时摘掉它（客户端断开、会话终止、服务端关停都会走到）。
func (h *streamableHandler) detachStream(sessionID string, stream *notifyStream) {
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	h.mu.Unlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.stream == stream {
		sess.stream = nil
	}
}

func (h *streamableHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID != "" {
		h.mu.Lock()
		sess, ok := h.sessions[sessionID]
		if ok {
			delete(h.sessions, sessionID)
		}
		h.mu.Unlock()
		if ok {
			// 终止会话时先让它的 GET 流收尾（done 是单向信号，发送方据此放弃未发出的
			// 通知），再注销登记的推送通道与订阅，免得在 Server 上留下永不复用的条目。
			sess.closeStream()
			if sess.unregisterPush != nil {
				sess.unregisterPush()
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// maybeStartSession 在 initialize 时分配会话 id，并通过响应头回给客户端。
//
// 顺带把该会话的服务端通知通道登记到 Server 上：资源订阅的变更通知要在调用之外送达
// （如后台长任务收尾），而 POST 的一次「一问一答」没有地方塞通知，只能经会话的 GET 流。
func (h *streamableHandler) maybeStartSession(w http.ResponseWriter, req *request, current string) {
	if req.Method != "initialize" || current != "" {
		return
	}
	id, err := sessionID()
	if err != nil {
		return
	}
	h.mu.Lock()
	sess := &streamableSession{events: newEventBuffer()}
	h.sessions[id] = sess
	h.mu.Unlock()

	// 会话已入表再挂推送通道：notifyFn 会先确认会话存在（见 hasSession），
	// 且它自己也要拿 h.mu，不能在上面的临界区里调。
	sess.unregisterPush = h.srv.RegisterResourcePush(id, h.notifyFn(id))
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
