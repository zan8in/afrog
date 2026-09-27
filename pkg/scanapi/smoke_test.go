package scanapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// TestSmoke_RealBinarySubmitStreamReconnectResults 用真实 afrog 二进制把 F3/F4 走一遍：
//
//	客户端 ──gRPC──▶ 控制面 ──LocalProcess──▶ 真实 afrog 子进程
//
// 覆盖：提交扫描、实时收事件、带 from_seq 重连补发、按 task_id 查结果。
//
// 默认跳过（需要 go 工具链、会真实启动子进程并写入本机 afrog 数据库）：
//
//	AFROG_SCANAPI_SMOKE=1 go test ./pkg/scanapi -run TestSmoke -v
func TestSmoke_RealBinarySubmitStreamReconnectResults(t *testing.T) {
	if os.Getenv("AFROG_SCANAPI_SMOKE") != "1" {
		t.Skip("set AFROG_SCANAPI_SMOKE=1 to run the scanapi smoke test")
	}

	bin := buildAfrogBinary(t)

	// 用临时 HOME：既能验证「子进程写库 → 控制面按 task_id 查到」这条链路，
	// 又不会把测试数据写进用户真实的 ~/.config/afrog/afrog.db。
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	// 关掉 curated 挂载，避免测试触发外部网络请求。
	if err := os.WriteFile(filepath.Join(configDir, "afrog-config.yaml"), []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	const token = "AFROG_SCANAPI_SMOKE_TOKEN"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "afrog-scanapi-smoke/1.0")
		_, _ = w.Write([]byte("<html><title>smoke</title>" + token + "</html>"))
	}))
	defer srv.Close()

	pocPath := writeSmokePoc(t, "afrog-scanapi-smoke", token)

	// 控制面：真实本地进程执行器 + 真实 gRPC 服务
	lp := &executor.LocalProcess{BinaryPath: bin, ExtraArgs: []string{"-duc"}}
	mgr, err := scantask.New(scantask.Options{Executor: lp, MaxRunning: 2, EventBuffer: 1024})
	if err != nil {
		t.Fatalf("scantask.New: %v", err)
	}
	impl, err := New(Options{Manager: mgr, Token: testToken, Version: "smoke"})
	if err != nil {
		t.Fatalf("scanapi.New: %v", err)
	}

	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuth(testToken)),
		grpc.StreamInterceptor(StreamAuth(testToken)),
	)
	afrogv1.RegisterAfrogScannerServer(grpcSrv, impl)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := afrogv1.NewAfrogScannerClient(conn)

	// 结果查询依赖控制面的 sqlite；顺带验证「子进程写库 → 控制面按 task_id 查到」。
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("init sqlite: %v", err)
	}
	defer sqlite.CloseX()

	ctx, cancel := context.WithTimeout(authCtx(t), 90*time.Second)
	defer cancel()

	submit, err := client.SubmitScan(ctx, &afrogv1.SubmitScanRequest{Spec: &afrogv1.ScanSpec{
		Targets:  []string{srv.URL},
		PocFile:  pocPath,
		TaskName: "scanapi-smoke",
	}})
	if err != nil {
		t.Fatalf("SubmitScan: %v", err)
	}
	taskID := submit.GetTaskId()
	t.Logf("submitted task %s on node %s", taskID, submit.GetNode())

	// 第一段订阅：读到第一条结果就断开，模拟客户端掉线。
	firstCtx, firstCancel := context.WithCancel(ctx)
	stream, err := client.StreamEvents(firstCtx, &afrogv1.StreamEventsRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}

	var lastSeq uint64
	var sawScanInfo bool
readLoop:
	for {
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv before first result: %v", err)
		}
		lastSeq = ev.GetSeq()
		switch bodyType(ev) {
		case scanstream.TypeScanInfo:
			sawScanInfo = true
		case scanstream.TypeResult:
			if ev.GetResult().GetPocId() != "afrog-scanapi-smoke" {
				t.Fatalf("unexpected poc id %q", ev.GetResult().GetPocId())
			}
			break readLoop
		}
	}

	firstCancel()
	if !sawScanInfo {
		t.Fatal("no scan_info event before the first result")
	}
	if lastSeq == 0 {
		t.Fatal("no events received before disconnecting")
	}
	t.Logf("disconnected after seq=%d", lastSeq)

	// 第二段订阅：带 from_seq 续订，必须无重复地从 lastSeq+1 开始。
	resumeStream, err := client.StreamEvents(ctx, &afrogv1.StreamEventsRequest{TaskId: taskID, FromSeq: lastSeq})
	if err != nil {
		t.Fatalf("StreamEvents(resume): %v", err)
	}

	var resumed int
	var firstResumed uint64
	sawDone := false
	for {
		ev, err := resumeStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv while resuming: %v", err)
		}
		if ev.GetSeq() <= lastSeq {
			t.Fatalf("resume replayed seq=%d which was already received (last_seq=%d)", ev.GetSeq(), lastSeq)
		}
		if resumed == 0 {
			firstResumed = ev.GetSeq()
		}
		resumed++
		if bodyType(ev) == scanstream.TypeDone {
			sawDone = true
		}
	}
	if resumed == 0 {
		t.Fatal("resume received no events")
	}
	if firstResumed != lastSeq+1 {
		t.Fatalf("resume started at seq=%d, want %d", firstResumed, lastSeq+1)
	}
	if !sawDone {
		t.Fatal("resume never saw the done event")
	}
	t.Logf("resumed %d events starting at seq=%d", resumed, firstResumed)

	statusResp, err := client.GetStatus(ctx, &afrogv1.GetStatusRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if statusResp.GetStatus() != string(scantask.StatusCompleted) {
		t.Fatalf("status = %q, want completed", statusResp.GetStatus())
	}
	if statusResp.GetNode() != "local" {
		t.Fatalf("node = %q, want local", statusResp.GetNode())
	}
	if got := statusResp.GetProgress().GetTotal(); got == 0 {
		t.Fatal("progress total = 0")
	}
	if statusResp.GetSummary().GetFound() == 0 {
		t.Fatal("summary.found = 0, want at least one hit")
	}

	// 子进程是异步写库的，轮询等它落地。
	var results *afrogv1.GetResultsResponse
	deadline := time.Now().Add(15 * time.Second)
	for {
		results, err = client.GetResults(ctx, &afrogv1.GetResultsRequest{TaskId: taskID, Detail: afrogv1.DetailLevel_FULL})
		if err != nil {
			t.Fatalf("GetResults: %v", err)
		}
		if len(results.GetItems()) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(results.GetItems()) == 0 {
		t.Fatal("GetResults returned nothing: 子进程写库的结果没有按 task_id 关联到控制面")
	}
	item := results.GetItems()[0]
	if item.GetPocId() != "afrog-scanapi-smoke" {
		t.Fatalf("result poc id = %q", item.GetPocId())
	}
	if len(item.GetEvidence().GetExchanges()) == 0 {
		t.Fatal("FULL detail should carry request/response evidence")
	}
	t.Logf("GetResults: total=%d items=%d", results.GetTotal(), len(results.GetItems()))
}

// buildAfrogBinary 把 cmd/afrog 编译成临时二进制。
func buildAfrogBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "afrog-smoke")
	build := exec.Command("go", "build", "-o", bin, "./cmd/afrog")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build afrog: %v\n%s", err, out)
	}
	return bin
}

// writeSmokePoc 写一个「响应体包含 token 即命中」的最小 PoC。
func writeSmokePoc(t *testing.T, id, token string) string {
	t.Helper()
	pocPath := filepath.Join(t.TempDir(), id+".yaml")
	poc := fmt.Sprintf(`id: %s
info:
  name: %s
  author: afrog-test
  severity: info
  description: scanapi smoke poc
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body.bcontains(b"%s")
expression: r0()
`, id, id, token)
	if err := os.WriteFile(pocPath, []byte(poc), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}
	return pocPath
}

// repoRoot 返回仓库根目录（本文件位于 <root>/pkg/scanapi）。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
