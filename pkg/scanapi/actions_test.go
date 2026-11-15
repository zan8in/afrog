package scanapi

import (
	"context"
	"errors"
	"net"
	"strings"
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

// ---------------------------------------------------------------------------
// SubmitActions 的测试替身：假派发后端记录收到的批量并返回与执行面同形的句柄，
// 使工具面动作能走完整任务生命周期而不依赖 pkg/mcp。
// ---------------------------------------------------------------------------

type scriptDispatcher struct {
	mu       sync.Mutex
	supports map[scantask.ActionKind]bool
	batches  map[string]scantask.Batch
	handles  map[string]*scriptHandle
}

func newScriptDispatcher(kinds ...scantask.ActionKind) *scriptDispatcher {
	d := &scriptDispatcher{
		supports: make(map[scantask.ActionKind]bool, len(kinds)),
		batches:  map[string]scantask.Batch{},
		handles:  map[string]*scriptHandle{},
	}
	for _, k := range kinds {
		d.supports[k] = true
	}
	return d
}

func (d *scriptDispatcher) Supports(kind scantask.ActionKind) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.supports[kind]
}

func (d *scriptDispatcher) Dispatch(_ context.Context, taskID string, batch scantask.Batch) (executor.Handle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h := &scriptHandle{events: make(chan *scanstream.Event, 16), done: make(chan struct{})}
	d.handles[taskID] = h
	d.batches[taskID] = batch
	return h, nil
}

func (d *scriptDispatcher) batch(t *testing.T, taskID string) scantask.Batch {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.batches[taskID]
	if !ok {
		t.Fatalf("dispatcher never received task %s", taskID)
	}
	return b
}

// finish 追加 done 事件并结束事件流，模拟工具面动作跑完。
func (d *scriptDispatcher) finish(t *testing.T, taskID string) {
	t.Helper()
	d.mu.Lock()
	h := d.handles[taskID]
	d.mu.Unlock()
	if h == nil {
		t.Fatalf("dispatcher never received task %s", taskID)
	}
	h.events <- &scanstream.Event{Type: scanstream.TypeDone, Done: &scanstream.DoneEvent{Status: "completed"}}
	if err := h.Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
		t.Fatalf("finish: %v", err)
	}
}

// newActionClient 起一个带工具面派发后端的控制面，跑真实的 gRPC 往返。
func newActionClient(t *testing.T) (afrogv1.AfrogScannerClient, *scriptExecutor, *scriptDispatcher) {
	t.Helper()

	script := newScriptExecutor()
	disp := newScriptDispatcher(
		scantask.ActionProbeHTTP, scantask.ActionReplayEvidence,
		scantask.ActionBrute, scantask.ActionOOBWait,
	)
	return buildClient(t, script, disp), script, disp
}

// buildClient 用给定的执行器与派发后端装配控制面，返回连上的客户端。
func buildClient(t *testing.T, ex executor.Executor, disp scantask.Dispatcher) afrogv1.AfrogScannerClient {
	t.Helper()

	mgr, err := scantask.New(scantask.Options{
		Executor: ex, Dispatcher: disp, MaxRunning: 4, EventBuffer: 64,
	})
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

	return afrogv1.NewAfrogScannerClient(conn)
}

// 工具面动作：动作被原样交给派发后端（kind / target / params 一字不差），并拿到任务 ID。
func TestSubmitActions_ToolFaceGoesToDispatcher(t *testing.T) {
	client, script, disp := newActionClient(t)

	resp, err := client.SubmitActions(authCtx(t), &afrogv1.SubmitActionsRequest{
		Spec: &afrogv1.ScanSpec{TaskName: "probe-batch"},
		Actions: []*afrogv1.ActionSpec{
			{Kind: "probe_http", Target: "http://a.example", ParamsJson: `{"method":"GET"}`},
			{Kind: "probe_http", Target: "http://b.example"},
		},
	})
	if err != nil {
		t.Fatalf("SubmitActions: %v", err)
	}
	if resp.GetTaskId() == "" {
		t.Fatal("SubmitActions returned an empty task_id")
	}
	if resp.GetNode() != "local" {
		t.Fatalf("node = %q, want local", resp.GetNode())
	}

	batch := disp.batch(t, resp.GetTaskId())
	if len(batch.Actions) != 2 {
		t.Fatalf("dispatched %d actions, want 2", len(batch.Actions))
	}
	if batch.Actions[0].Kind != scantask.ActionProbeHTTP {
		t.Fatalf("kind = %s, want probe_http", batch.Actions[0].Kind)
	}
	if batch.Actions[0].Target != "http://a.example" {
		t.Fatalf("target = %q, want http://a.example", batch.Actions[0].Target)
	}
	if string(batch.Actions[0].Params) != `{"method":"GET"}` {
		t.Fatalf("params = %s, want the params_json passthrough", batch.Actions[0].Params)
	}
	if batch.Options.TaskName != "probe-batch" {
		t.Fatalf("task name = %q, want probe-batch", batch.Options.TaskName)
	}
	// 工具面动作不该落到执行面上。
	select {
	case id := <-script.started:
		t.Fatalf("tool-face action reached the CLI executor: %s", id)
	default:
	}

	disp.finish(t, resp.GetTaskId())
}

// 执行面动作：显式给出 run_poc 时照旧走 CLI 子进程，而不是派发后端。
func TestSubmitActions_ExecutionFaceGoesToExecutor(t *testing.T) {
	client, script, disp := newActionClient(t)

	resp, err := client.SubmitActions(authCtx(t), &afrogv1.SubmitActionsRequest{
		Spec:    &afrogv1.ScanSpec{TaskName: "poc-run"},
		Actions: []*afrogv1.ActionSpec{{Kind: "run_poc", Target: "http://a.example"}},
	})
	if err != nil {
		t.Fatalf("SubmitActions: %v", err)
	}
	script.waitStarted(t, resp.GetTaskId(), 5*time.Second)

	spec, ok := script.spec(resp.GetTaskId())
	if !ok {
		t.Fatal("executor never received a spec")
	}
	if len(spec.Targets) != 1 || spec.Targets[0] != "http://a.example" {
		t.Fatalf("spec targets = %v, want [http://a.example]", spec.Targets)
	}
	disp.mu.Lock()
	dispatched := len(disp.batches)
	disp.mu.Unlock()
	if dispatched != 0 {
		t.Fatalf("execution-face action was dispatched to the tool face (%d batches)", dispatched)
	}
}

// 参数非法一律在受理阶段挡掉，且用 InvalidArgument 说清楚哪一条错了。
func TestSubmitActions_RejectsBadRequests(t *testing.T) {
	client, _, _ := newActionClient(t)

	cases := []struct {
		name string
		req  *afrogv1.SubmitActionsRequest
	}{
		{
			name: "no spec",
			req:  &afrogv1.SubmitActionsRequest{Actions: []*afrogv1.ActionSpec{{Kind: "probe_http", Target: "http://a.example"}}},
		},
		{
			name: "no actions",
			req:  &afrogv1.SubmitActionsRequest{Spec: &afrogv1.ScanSpec{}},
		},
		{
			name: "missing kind",
			req: &afrogv1.SubmitActionsRequest{
				Spec:    &afrogv1.ScanSpec{},
				Actions: []*afrogv1.ActionSpec{{Target: "http://a.example"}},
			},
		},
		{
			name: "unknown kind",
			req: &afrogv1.SubmitActionsRequest{
				Spec:    &afrogv1.ScanSpec{},
				Actions: []*afrogv1.ActionSpec{{Kind: "teleport", Target: "http://a.example"}},
			},
		},
		{
			name: "missing target",
			req: &afrogv1.SubmitActionsRequest{
				Spec:    &afrogv1.ScanSpec{},
				Actions: []*afrogv1.ActionSpec{{Kind: "run_poc", Target: "  "}},
			},
		},
		{
			name: "mixed kinds",
			req: &afrogv1.SubmitActionsRequest{
				Spec: &afrogv1.ScanSpec{},
				Actions: []*afrogv1.ActionSpec{
					{Kind: "run_poc", Target: "http://a.example"},
					{Kind: "probe_http", Target: "http://b.example"},
				},
			},
		},
		{
			name: "malformed params_json",
			req: &afrogv1.SubmitActionsRequest{
				Spec:    &afrogv1.ScanSpec{},
				Actions: []*afrogv1.ActionSpec{{Kind: "probe_http", Target: "http://a.example", ParamsJson: "{not json"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.SubmitActions(authCtx(t), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
		})
	}
}

// 没有派发后端却提交工具面动作：明确报 FailedPrecondition，而不是受理后静默失败。
func TestSubmitActions_ToolFaceWithoutDispatcherIsRejected(t *testing.T) {
	client := buildClient(t, newScriptExecutor(), nil)

	_, err := client.SubmitActions(authCtx(t), &afrogv1.SubmitActionsRequest{
		Spec:    &afrogv1.ScanSpec{},
		Actions: []*afrogv1.ActionSpec{{Kind: "probe_http", Target: "http://a.example"}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "no dispatcher") {
		t.Fatalf("err = %v, want it to say the dispatcher is missing", err)
	}
}

// 派发后端不认这个类型时同样拒绝：Supports 为假即受理阶段失败。
func TestSubmitActions_UnsupportedKindIsRejected(t *testing.T) {
	client := buildClient(t, newScriptExecutor(), newScriptDispatcher(scantask.ActionProbeHTTP))

	_, err := client.SubmitActions(authCtx(t), &afrogv1.SubmitActionsRequest{
		Spec:    &afrogv1.ScanSpec{},
		Actions: []*afrogv1.ActionSpec{{Kind: "oob_wait", Target: "http://a.example"}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}
