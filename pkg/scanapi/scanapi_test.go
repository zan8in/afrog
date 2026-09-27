package scanapi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	testToken = "test-api-token"
	bufSize   = 1024 * 1024
)

// ---------------------------------------------------------------------------
// 测试替身：用函数直接编排执行器行为，避免依赖真实 afrog 二进制。
// ---------------------------------------------------------------------------

type scriptHandle struct {
	events   chan *scanstream.Event
	done     chan struct{}
	pauseErr error

	once sync.Once
	mu   sync.Mutex
	paused bool
	ended  bool
}

func (h *scriptHandle) Events() <-chan *scanstream.Event { return h.events }
func (h *scriptHandle) Done() <-chan struct{}            { return h.done }
func (h *scriptHandle) Err() error                       { return nil }
func (h *scriptHandle) PID() int                         { return 1 }

func (h *scriptHandle) Pause() error {
	if h.pauseErr != nil {
		return h.pauseErr
	}
	h.mu.Lock()
	h.paused = true
	h.mu.Unlock()
	return nil
}

func (h *scriptHandle) Resume() error {
	if h.pauseErr != nil {
		return h.pauseErr
	}
	h.mu.Lock()
	h.paused = false
	h.mu.Unlock()
	return nil
}

func (h *scriptHandle) Cancel() error {
	h.mu.Lock()
	already := h.ended
	h.ended = true
	h.mu.Unlock()
	if already {
		return executor.ErrAlreadyDone
	}
	h.once.Do(func() {
		close(h.events)
		close(h.done)
	})
	return nil
}

type scriptExecutor struct {
	mu      sync.Mutex
	handles map[string]*scriptHandle
	specs   map[string]*executor.Spec
	started chan string
	startErr error
	pauseErr error
}

func newScriptExecutor() *scriptExecutor {
	return &scriptExecutor{
		handles: map[string]*scriptHandle{},
		specs:   map[string]*executor.Spec{},
		started: make(chan string, 16),
	}
}

func (e *scriptExecutor) Start(_ context.Context, taskID string, spec *executor.Spec) (executor.Handle, error) {
	e.mu.Lock()
	if e.startErr != nil {
		err := e.startErr
		e.mu.Unlock()
		return nil, err
	}
	h := &scriptHandle{
		events:   make(chan *scanstream.Event, 256),
		done:     make(chan struct{}),
		pauseErr: e.pauseErr,
	}
	e.handles[taskID] = h
	e.specs[taskID] = spec
	e.mu.Unlock()

	select {
	case e.started <- taskID:
	default:
	}
	return h, nil
}

func (e *scriptExecutor) handle(taskID string) (*scriptHandle, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h, ok := e.handles[taskID]
	return h, ok
}

func (e *scriptExecutor) spec(taskID string) (*executor.Spec, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.specs[taskID]
	return s, ok
}

func (e *scriptExecutor) emit(t *testing.T, taskID, typ string, fill func(*scanstream.Event)) {
	t.Helper()
	h, ok := e.handle(taskID)
	if !ok {
		t.Fatalf("executor never started task %s", taskID)
	}
	ev := &scanstream.Event{Type: typ}
	if fill != nil {
		fill(ev)
	}
	h.events <- ev
}

func (e *scriptExecutor) finish(t *testing.T, taskID, doneStatus string) {
	t.Helper()
	e.emit(t, taskID, scanstream.TypeDone, func(ev *scanstream.Event) {
		ev.Done = &scanstream.DoneEvent{Status: doneStatus, Summary: &scanstream.Summary{Executed: 3, Found: 1}}
	})
	if err := e.mustHandle(t, taskID).Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
		t.Fatalf("finish: %v", err)
	}
}

func (e *scriptExecutor) mustHandle(t *testing.T, taskID string) *scriptHandle {
	t.Helper()
	h, ok := e.handle(taskID)
	if !ok {
		t.Fatalf("executor never started task %s", taskID)
	}
	return h
}

func (e *scriptExecutor) waitStarted(t *testing.T, taskID string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case id := <-e.started:
			if id == taskID {
				return
			}
		case <-deadline:
			t.Fatalf("executor never started task %s", taskID)
		}
	}
}

// ---------------------------------------------------------------------------
// 测试脚手架：真实的 gRPC 服务 + bufconn 连接
// ---------------------------------------------------------------------------

func newTestClient(t *testing.T, script *scriptExecutor) (afrogv1.AfrogScannerClient, *scantask.Manager) {
	t.Helper()

	mgr, err := scantask.New(scantask.Options{Executor: script, MaxRunning: 4, EventBuffer: 64})
	if err != nil {
		t.Fatalf("scantask.New: %v", err)
	}
	srv, err := New(Options{Manager: mgr, Token: testToken, Version: "test-version"})
	if err != nil {
		t.Fatalf("scanapi.New: %v", err)
	}

	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuth(testToken)),
		grpc.StreamInterceptor(StreamAuth(testToken)),
	)
	afrogv1.RegisterAfrogScannerServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return afrogv1.NewAfrogScannerClient(conn), mgr
}

func authCtx(t *testing.T) context.Context {
	t.Helper()
	return WithToken(context.Background(), testToken)
}

// submit 提交一次扫描并等执行器真正拉起子进程。
func submit(t *testing.T, script *scriptExecutor, client afrogv1.AfrogScannerClient, targets ...string) string {
	t.Helper()
	if len(targets) == 0 {
		targets = []string{"http://a.example"}
	}
	resp, err := client.SubmitScan(authCtx(t), &afrogv1.SubmitScanRequest{
		Spec: &afrogv1.ScanSpec{Targets: targets, TaskName: "smoke"},
	})
	if err != nil {
		t.Fatalf("SubmitScan: %v", err)
	}
	if resp.GetTaskId() == "" {
		t.Fatal("SubmitScan returned an empty task_id")
	}
	if resp.GetNode() != "local" {
		t.Fatalf("node = %q, want local", resp.GetNode())
	}
	script.waitStarted(t, resp.GetTaskId(), 5*time.Second)
	return resp.GetTaskId()
}

// bodyType 从 oneof 反推事件类型，用于验证 proto 事件与内部事件一一对应。
func bodyType(ev *afrogv1.ScanEvent) string {
	switch ev.GetBody().(type) {
	case *afrogv1.ScanEvent_Status:
		return scanstream.TypeStatus
	case *afrogv1.ScanEvent_ScanInfo:
		return scanstream.TypeScanInfo
	case *afrogv1.ScanEvent_Progress:
		return scanstream.TypeProgress
	case *afrogv1.ScanEvent_Phase:
		return scanstream.TypePhase
	case *afrogv1.ScanEvent_Result:
		return scanstream.TypeResult
	case *afrogv1.ScanEvent_Port:
		return scanstream.TypePort
	case *afrogv1.ScanEvent_Webprobe:
		return scanstream.TypeWebProbe
	case *afrogv1.ScanEvent_Host:
		return scanstream.TypeHost
	case *afrogv1.ScanEvent_Log:
		return scanstream.TypeLog
	case *afrogv1.ScanEvent_Done:
		return scanstream.TypeDone
	case *afrogv1.ScanEvent_Error:
		return scanstream.TypeError
	default:
		return "unknown"
	}
}

type received struct {
	seq  uint64
	typ  string
	body *afrogv1.ScanEvent
}

// streamAll 读完一个事件流直到服务端结束。
func streamAll(t *testing.T, stream afrogv1.AfrogScanner_StreamEventsClient) []received {
	t.Helper()
	var out []received
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		out = append(out, received{seq: ev.GetSeq(), typ: bodyType(ev), body: ev})
	}
}

// ---------------------------------------------------------------------------
// F3：外部客户端能提交扫描并实时接收事件
// ---------------------------------------------------------------------------

func TestSubmitScan_StreamsEventsToExternalClient(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	taskID := submit(t, script, client, "http://a.example")

	stream, err := client.StreamEvents(authCtx(t), &afrogv1.StreamEventsRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}

	script.emit(t, taskID, scanstream.TypeScanInfo, func(ev *scanstream.Event) {
		ev.ScanInfo = &scanstream.ScanInfoEvent{TotalTargets: 1, TotalPocs: 2, TotalScans: 3, OOBEnabled: true, OOBStatus: "ok"}
	})
	script.emit(t, taskID, scanstream.TypeProgress, func(ev *scanstream.Event) {
		ev.Progress = &scanstream.ProgressEvent{Percent: 66, Finished: 2, Total: 3, ElapsedMs: 1200}
	})
	script.emit(t, taskID, scanstream.TypeResult, func(ev *scanstream.Event) {
		ev.Result = &scanstream.ResultEvent{
			Severity: "high", PocID: "poc-1", PocName: "demo", Target: "http://a.example",
			Evidence: &scanstream.Evidence{Exchanges: []scanstream.Exchange{{Request: "GET / HTTP/1.1", Response: "200 OK", Matched: true}}},
		}
	})
	script.emit(t, taskID, scanstream.TypePort, func(ev *scanstream.Event) {
		ev.Port = &scanstream.PortEvent{Host: "a.example", Port: 443}
	})
	script.finish(t, taskID, "completed")

	events := streamAll(t, stream)
	want := []string{
		scanstream.TypeStatus,   // starting
		scanstream.TypeStatus,   // running
		scanstream.TypeScanInfo, // 引擎上报
		scanstream.TypeProgress,
		scanstream.TypeResult,
		scanstream.TypePort,
		scanstream.TypeDone,
		scanstream.TypeProgress, // 收尾补发
		scanstream.TypeScanInfo, // 收尾补发
		scanstream.TypeStatus,   // completed
	}
	if len(events) != len(want) {
		t.Fatalf("got %d events (%v), want %d (%v)", len(events), typesOf(events), len(want), want)
	}
	for i := range want {
		if events[i].typ != want[i] {
			t.Fatalf("event %d = %s, want %s (all: %v)", i, events[i].typ, want[i], typesOf(events))
		}
		if events[i].seq != uint64(i+1) {
			t.Fatalf("event %d seq = %d, want %d", i, events[i].seq, i+1)
		}
		if events[i].body.GetTask() != taskID {
			t.Fatalf("event %d task = %q, want %q", i, events[i].body.GetTask(), taskID)
		}
		if events[i].body.GetV() != scanstream.Version || events[i].body.GetNode() != "local" {
			t.Fatalf("event %d envelope = %s/%s", i, events[i].body.GetV(), events[i].body.GetNode())
		}
	}

	// 载荷要逐字段对上，不能只对类型。
	if got := events[2].body.GetScanInfo(); got.GetTotalPocs() != 2 || !got.GetOobEnabled() {
		t.Fatalf("scan_info payload = %+v", got)
	}
	if got := events[3].body.GetProgress(); got.GetPercent() != 66 || got.GetTotal() != 3 {
		t.Fatalf("progress payload = %+v", got)
	}
	res := events[4].body.GetResult()
	if res.GetPocId() != "poc-1" || res.GetSeverity() != "high" {
		t.Fatalf("result payload = %+v", res)
	}
	if len(res.GetEvidence().GetExchanges()) != 1 || res.GetEvidence().GetExchanges()[0].GetRequest() != "GET / HTTP/1.1" {
		t.Fatalf("result evidence = %+v", res.GetEvidence())
	}
	if got := events[5].body.GetPort(); got.GetPort() != 443 {
		t.Fatalf("port payload = %+v", got)
	}
	if got := events[6].body.GetDone(); got.GetStatus() != "completed" || got.GetSummary().GetExecuted() != 3 {
		t.Fatalf("done payload = %+v", got)
	}
}

// ---------------------------------------------------------------------------
// F4：断线重连靠 seq 补齐，不丢不重
// ---------------------------------------------------------------------------

func TestStreamEvents_ReconnectResumesWithoutLossOrDuplicate(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	taskID := submit(t, script, client, "http://a.example")
	script.emit(t, taskID, scanstream.TypeScanInfo, func(ev *scanstream.Event) {
		ev.ScanInfo = &scanstream.ScanInfoEvent{TotalTargets: 1, TotalPocs: 2, TotalScans: 3}
	})
	for i := 1; i <= 3; i++ {
		n := i
		script.emit(t, taskID, scanstream.TypeProgress, func(ev *scanstream.Event) {
			ev.Progress = &scanstream.ProgressEvent{Percent: n * 33, Finished: int64(n), Total: 3}
		})
	}
	script.finish(t, taskID, "completed")

	// 参考序列：从头完整读一遍。
	fullStream, err := client.StreamEvents(authCtx(t), &afrogv1.StreamEventsRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	full := streamAll(t, fullStream)
	if len(full) < 6 {
		t.Fatalf("reference stream too short: %v", typesOf(full))
	}

	// 模拟断线：只读前 3 条就取消。
	ctx, cancel := context.WithCancel(authCtx(t))
	partialStream, err := client.StreamEvents(ctx, &afrogv1.StreamEventsRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("StreamEvents(partial): %v", err)
	}
	var partial []received
	for i := 0; i < 3; i++ {
		ev, err := partialStream.Recv()
		if err != nil {
			t.Fatalf("partial Recv %d: %v", i, err)
		}
		partial = append(partial, received{seq: ev.GetSeq(), typ: bodyType(ev)})
	}
	cancel()

	lastSeq := partial[len(partial)-1].seq
	if lastSeq != 3 {
		t.Fatalf("partial last seq = %d, want 3", lastSeq)
	}

	// 重连：带上 last_seq，必须只拿到之后的事件。
	resumeStream, err := client.StreamEvents(authCtx(t), &afrogv1.StreamEventsRequest{TaskId: taskID, FromSeq: lastSeq})
	if err != nil {
		t.Fatalf("StreamEvents(resume): %v", err)
	}
	rest := streamAll(t, resumeStream)

	if len(partial)+len(rest) != len(full) {
		t.Fatalf("partial(%d) + rest(%d) != full(%d); rest=%v", len(partial), len(rest), len(full), typesOf(rest))
	}
	merged := append(append([]received{}, partial...), rest...)
	for i := range full {
		if merged[i].seq != full[i].seq || merged[i].typ != full[i].typ {
			t.Fatalf("event %d = %d/%s, want %d/%s", i, merged[i].seq, merged[i].typ, full[i].seq, full[i].typ)
		}
	}
	// 补发的第一条必须正好是 last_seq 的下一条。
	if rest[0].seq != lastSeq+1 {
		t.Fatalf("resume started at seq %d, want %d", rest[0].seq, lastSeq+1)
	}
}

// 订阅一个已经结束的任务：补发完就结束，不再挂起。
func TestStreamEvents_FinishedTaskReplaysAndCloses(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	taskID := submit(t, script, client, "http://a.example")
	script.finish(t, taskID, "completed")

	// 等任务收尾
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := client.GetStatus(authCtx(t), &afrogv1.GetStatusRequest{TaskId: taskID})
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if st.GetStatus() == string(scantask.StatusCompleted) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status = %s, want completed", st.GetStatus())
		}
		time.Sleep(5 * time.Millisecond)
	}

	stream, err := client.StreamEvents(authCtx(t), &afrogv1.StreamEventsRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	done := make(chan []received, 1)
	go func() { done <- streamAll(t, stream) }()

	select {
	case events := <-done:
		types := typesOf(events)
		if types[len(types)-1] != scanstream.TypeStatus {
			t.Fatalf("last event = %s, want a status event (%v)", types[len(types)-1], types)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream of a finished task never closed")
	}
}

// ---------------------------------------------------------------------------
// F5 的一部分：凭据校验
// ---------------------------------------------------------------------------

func TestAuth_RejectsMissingOrWrongCredentials(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	req := &afrogv1.SubmitScanRequest{Spec: &afrogv1.ScanSpec{Targets: []string{"http://a.example"}}}

	if _, err := client.SubmitScan(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: err = %v, want Unauthenticated", err)
	}
	if _, err := client.SubmitScan(WithToken(context.Background(), "wrong"), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token: err = %v, want Unauthenticated", err)
	}

	// 流式接口同样要校验（StreamAuth 拦截器）。
	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := client.StreamEvents(streamCtx, &afrogv1.StreamEventsRequest{TaskId: "whatever"})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream without token: err = %v, want Unauthenticated", err)
	}
}

// ---------------------------------------------------------------------------
// 参数校验与错误映射
// ---------------------------------------------------------------------------

func TestSubmitScan_ValidatesTargets(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	_, err := client.SubmitScan(authCtx(t), &afrogv1.SubmitScanRequest{Spec: &afrogv1.ScanSpec{}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

// OOB 凭据没有 CLI 通道，必须明确拒绝而不是静默忽略。
func TestSubmitScan_RejectsUnmappableOOBCredentials(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	_, err := client.SubmitScan(authCtx(t), &afrogv1.SubmitScanRequest{Spec: &afrogv1.ScanSpec{
		Targets:   []string{"http://a.example"},
		EnableOob: true,
		OobKey:    "secret-key",
	}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}

	// 只给 adapter 是允许的（凭据来自节点自己的 afrog-config.yaml）。
	if _, err := client.SubmitScan(authCtx(t), &afrogv1.SubmitScanRequest{Spec: &afrogv1.ScanSpec{
		Targets:    []string{"http://a.example"},
		EnableOob:  true,
		OobAdapter: "dnslogcn",
	}}); err != nil {
		t.Fatalf("adapter-only OOB should be accepted, got %v", err)
	}
}

func TestGetStatus_UnknownTaskIsNotFound(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	_, err := client.GetStatus(authCtx(t), &afrogv1.GetStatusRequest{TaskId: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

// 规格要原样传到执行器：参数不能在中途被吞掉。
func TestSubmitScan_PassesSpecToExecutor(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	taskID := submit(t, script, client, "http://a.example", "http://b.example")
	spec, ok := script.spec(taskID)
	if !ok {
		t.Fatalf("no spec recorded for %s", taskID)
	}
	if len(spec.Targets) != 2 {
		t.Fatalf("targets = %v, want 2", spec.Targets)
	}
}

func TestControl_UnknownTaskIsNotFound(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	_, err := client.Control(authCtx(t), &afrogv1.ControlRequest{TaskId: "nope", Action: afrogv1.ControlAction_PAUSE})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestListCapabilities(t *testing.T) {
	script := newScriptExecutor()
	client, _ := newTestClient(t, script)

	resp, err := client.ListCapabilities(authCtx(t), &afrogv1.ListCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("ListCapabilities: %v", err)
	}
	if resp.GetVersion() != "test-version" {
		t.Fatalf("version = %q", resp.GetVersion())
	}
	if resp.GetProtocolVersion() != scanstream.Version {
		t.Fatalf("protocol version = %q, want %q", resp.GetProtocolVersion(), scanstream.Version)
	}
	if resp.GetPausable() != executor.PauseSupported {
		t.Fatalf("pausable = %v, want %v", resp.GetPausable(), executor.PauseSupported)
	}
	if len(resp.GetNodes()) != 1 || resp.GetNodes()[0] != "local" {
		t.Fatalf("nodes = %v", resp.GetNodes())
	}
}

func typesOf(events []received) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.typ)
	}
	return out
}
