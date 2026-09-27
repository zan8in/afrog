package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// buildAfrogBinary 把 cmd/afrog 编译成临时二进制，供冒烟测试拉起子进程。
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
	poc := "id: " + id + "\n" +
		"info:\n" +
		"  name: " + id + "\n" +
		"  author: afrog-test\n" +
		"  severity: info\n" +
		"  description: executor smoke poc\n" +
		"rules:\n" +
		"  r0:\n" +
		"    request:\n" +
		"      method: GET\n" +
		"      path: /probe?q=1\n" +
		"    expression: response.status == 200 && response.body.bcontains(b\"" + token + "\")\n" +
		"expression: r0()\n"
	if err := os.WriteFile(pocPath, []byte(poc), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}
	return pocPath
}

// isolateHome 把 HOME 指向临时目录，避免冒烟测试拉起子进程时把扫描记录写进
// 用户真实的 ~/.config/afrog（sqlite / curated 状态），同时关掉 curated 挂载，
// 免得测试触发外部网络请求。
func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "afrog-config.yaml"), []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestLocalProcessSmoke 用真实 afrog 二进制端到端跑一次本地扫描：
// 编译 cmd/afrog → 起一个本地 httptest 服务 → 用一个匹配该服务的 PoC 走 LocalProcess。
//
// 默认跳过（需要 go 工具链并会真实启动子进程），用 AFROG_EXECUTOR_SMOKE=1 开启：
//
//	AFROG_EXECUTOR_SMOKE=1 go test ./pkg/executor -run TestLocalProcessSmoke -v
func TestLocalProcessSmoke(t *testing.T) {
	if os.Getenv("AFROG_EXECUTOR_SMOKE") != "1" {
		t.Skip("set AFROG_EXECUTOR_SMOKE=1 to run the local-process smoke test")
	}

	isolateHome(t)
	bin := buildAfrogBinary(t)

	const token = "AFROG_EXECUTOR_SMOKE_TOKEN"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "afrog-smoke/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>afrog smoke</title>" + token + "</html>"))
	}))
	defer srv.Close()

	pocPath := writeSmokePoc(t, "afrog-executor-smoke", token)

	var mu sync.Mutex
	var stderrTail []string
	lp := &LocalProcess{
		BinaryPath: bin,
		// -duc 关闭更新检查，避免子进程访问网络。
		ExtraArgs: []string{"-duc"},
		OnStderr: func(line string) {
			mu.Lock()
			defer mu.Unlock()
			if len(stderrTail) < 20 {
				stderrTail = append(stderrTail, line)
			}
		},
	}

	spec := &Spec{
		Targets:        []string{srv.URL},
		PocFile:        pocPath,
		TimeoutSeconds: 10,
		Concurrency:    5,
	}

	h, err := lp.Start(context.Background(), "smoke-task", spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	var types []string
	for ev := range h.Events() {
		types = append(types, ev.Type)
	}
	<-h.Done()

	t.Logf("event types: %v", types)
	if err := h.Err(); err != nil {
		mu.Lock()
		tail := append([]string(nil), stderrTail...)
		mu.Unlock()
		t.Fatalf("Err = %v\nstderr tail: %v", err, tail)
	}

	found := false
	for _, ty := range types {
		if ty == scanstream.TypeResult {
			found = true
		}
	}
	if !found {
		t.Fatalf("no result event: %v", types)
	}

	// 等子进程写完 sqlite（异步 worker），顺带确认父任务 ID 被注入。
	time.Sleep(500 * time.Millisecond)
}

// TestLocalProcessSmoke_ConcurrentSpecsDoNotInterfere 是 F1 的验收测试：
// 同时运行 3 个并发数/限速/目标数各不相同的扫描，验证
//  1. 每个任务的事件信封都带自己的 task ID（没有串流）；
//  2. 每个任务只拿到自己目标上的结果（没有串扰）；
//  3. 每个任务的 scan_info 反映自己的规格（没有互相覆盖参数）。
//
// 这正是 sdk 的进程级全局状态（HTTP 客户端/限速器/协议探测缓存）会造成的问题，
// 进程隔离后必须全部消失。
//
//	AFROG_EXECUTOR_SMOKE=1 go test ./pkg/executor -run ConcurrentSpecs -v
func TestLocalProcessSmoke_ConcurrentSpecsDoNotInterfere(t *testing.T) {
	if os.Getenv("AFROG_EXECUTOR_SMOKE") != "1" {
		t.Skip("set AFROG_EXECUTOR_SMOKE=1 to run the local-process smoke test")
	}

	isolateHome(t)

	const scans = 3
	bin := buildAfrogBinary(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>afrog iso token</html>"))
	}))
	defer srv.Close()

	type scanOutcome struct {
		results      []string // 命中的 poc_id@target
		totalTargets int
		doneStatus   string
		err          error
		mislabeled   []string // 事件信封里 task 字段与本任务不符的记录
	}

	var (
		mu       sync.Mutex
		outcomes = make([]scanOutcome, scans)
		wg       sync.WaitGroup
	)

	lp := &LocalProcess{BinaryPath: bin, ExtraArgs: []string{"-duc"}}

	for n := 0; n < scans; n++ {
		taskID := fmt.Sprintf("iso-task-%d", n)
		pocID := fmt.Sprintf("afrog-iso-%d", n)
		pocPath := writeSmokePoc(t, pocID, "afrog iso token")

		targets := make([]string, 0, n+1)
		for k := 0; k <= n; k++ {
			targets = append(targets, fmt.Sprintf("%s/t%d", srv.URL, k))
		}

		spec := &Spec{
			Targets: targets,
			PocFile: pocPath,
			// 每个任务一套不同的性能参数：旧实现里它们会互相覆盖。
			Concurrency:    1 + n*4,
			RateLimit:      10 + n*50,
			TimeoutSeconds: 10,
		}

		wg.Add(1)
		go func(n int, taskID string, spec *Spec) {
			defer wg.Done()
			out := scanOutcome{}
			h, err := lp.Start(context.Background(), taskID, spec)
			if err != nil {
				out.err = err
				mu.Lock()
				outcomes[n] = out
				mu.Unlock()
				return
			}
			for ev := range h.Events() {
				if ev.Task != taskID {
					out.mislabeled = append(out.mislabeled, ev.Type+":"+ev.Task)
				}
				switch ev.Type {
				case scanstream.TypeResult:
					if ev.Result != nil {
						out.results = append(out.results, ev.Result.PocID+"@"+ev.Result.Target)
					}
				case scanstream.TypeScanInfo:
					if ev.ScanInfo != nil {
						out.totalTargets = ev.ScanInfo.TotalTargets
					}
				case scanstream.TypeDone:
					if ev.Done != nil {
						out.doneStatus = ev.Done.Status
					}
				}
			}
			<-h.Done()
			if err := h.Err(); err != nil {
				out.err = err
			}
			mu.Lock()
			outcomes[n] = out
			mu.Unlock()
		}(n, taskID, spec)
	}
	wg.Wait()

	for n, out := range outcomes {
		if out.err != nil {
			t.Fatalf("scan %d failed: %v", n, out.err)
		}
		if len(out.mislabeled) > 0 {
			t.Fatalf("scan %d received events for another task: %v", n, out.mislabeled)
		}
		if out.totalTargets != n+1 {
			t.Fatalf("scan %d scan_info.total_targets = %d, want %d (参数被其他扫描覆盖)",
				n, out.totalTargets, n+1)
		}
		if out.doneStatus != "completed" {
			t.Fatalf("scan %d done status = %q, want completed", n, out.doneStatus)
		}
		if len(out.results) != n+1 {
			t.Fatalf("scan %d got %d results %v, want %d", n, len(out.results), out.results, n+1)
		}
		wantPocID := fmt.Sprintf("afrog-iso-%d", n)
		for _, got := range out.results {
			if !strings.HasPrefix(got, wantPocID+"@") {
				t.Fatalf("scan %d result %q does not belong to poc %q", n, got, wantPocID)
			}
		}
	}
}

// repoRoot 返回本仓库根目录（本测试文件位于 <root>/pkg/executor）。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
