package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/policy"
)

// 反向 PoC 的语义差分：引擎在缺反连平台时会把反向 PoC 记成「未命中」——那是一个说不
// 清楚的假阴性。工具面在这里补上两条明确路径：
//   有反连后端 → 真的接上（把适配器名交给子进程）；
//   没有后端   → fail-closed 明确报错，绝不下空结论。
//
// 本文件锁的就是这两条路径，以及「非反向 PoC 不受影响」。单 PoC 实跑入口是 poc.submit
// （verify.poc 已随 SDK 一起退出）。

// writeReversePoC 落一份最小反向 PoC，形态与 pocs/oob-http.yaml 一致：
// 请求带 {{oob.HTTP}}，判定靠 oobCheck(...)。不下发回连就永远拿不到结论。
func writeReversePoC(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp-verify-oob.yaml")
	body := `id: mcp-verify-oob
info:
  name: mcp verify oob
  author: afrog-test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /?http=curl%20{{oob.HTTP}}
    expression: oobCheck(oob.ProtocolHTTP, 3)
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write reverse poc: %v", err)
	}
	return path
}

// newOOBVerifyServer 用放行单 PoC 实跑的策略装配工具面（full + destructive），并把 HOME
// 指向临时目录，避免测试碰到开发机真实的 ~/.config/afrog。预算不限额：这里测的是 OOB 语义。
//
// 开启子进程测试时注入本地进程执行器（必须在切 HOME 之前构建，否则会拿到空模块缓存）；
// 未开启也不影响「未触及执行器」的用例——缺后端时会在拉起子进程之前就 fail-closed。
func newOOBVerifyServer(t *testing.T, oob OOBSource) *Server {
	t.Helper()
	var ex executor.Executor
	if subprocessEnabled() {
		ex = subprocessExecutor(t)
	}
	t.Setenv("HOME", t.TempDir())
	return New(Options{
		Policy:   &policy.Policy{Mode: policy.ModeFull, Destructive: true},
		OOB:      oob,
		Executor: ex,
	})
}

// analyzePoc 是单 PoC 实跑判断「要不要接反连平台」的唯一依据，识别口径回归即失败。
func TestAnalyzePocFlagsOutOfBandPoCs(t *testing.T) {
	head := "id: t\ninfo:\n  name: t\n  author: t\n  severity: info\nrules:\n  r0:\n    request:\n      method: GET\n      path: "

	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "reverse var and oobCheck",
			yaml: head + "/?http=curl%20{{oob.HTTP}}\n    expression: oobCheck(oob.ProtocolHTTP, 3)\nexpression: r0()\n",
			want: true,
		},
		{
			name: "reverse var only",
			yaml: head + "/?d={{oob.DNS}}\n    expression: response.status == 200\nexpression: r0()\n",
			want: true,
		},
		{
			name: "oobCheck only",
			yaml: head + "/\n    expression: oobCheckToken(oob.ProtocolDNS, 3)\nexpression: r0()\n",
			want: true,
		},
		{
			name: "plain poc",
			yaml: head + "/\n    expression: response.status == 200\nexpression: r0()\n",
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := analyzePoc([]byte(tc.yaml)).NeedsOOB; got != tc.want {
				t.Fatalf("analyzePoc().NeedsOOB = %v, want %v", got, tc.want)
			}
		})
	}

	// 解析不出 PoC 时按「不依赖反连」保守处理，但仍要给出请求数上限。
	est := analyzePoc([]byte("not: [a poc"))
	if est.NeedsOOB {
		t.Fatal("unparseable PoC must not be treated as out of band")
	}
	if est.Requests != defaultVerifyReserve {
		t.Fatalf("requests = %d, want %d", est.Requests, defaultVerifyReserve)
	}
}

// 未配置反连后端：反向 PoC 必须 fail-closed 明确报错，而不是静默返回 found=false。
func TestPocSubmitReverseWithoutBackendFailsClosed(t *testing.T) {
	s := newOOBVerifyServer(t, nil)

	out, err := s.tools["poc.submit"].Handler(context.Background(),
		mustJSON(t, map[string]any{"poc_path": writeReversePoC(t), "target": "http://127.0.0.1:1"}))
	if err == nil {
		t.Fatalf("result = %#v, want a fail-closed error for an out-of-band PoC without a backend", out)
	}
	if !errors.Is(err, errOOBUnavailable) {
		t.Fatalf("err = %v, want it to wrap errOOBUnavailable", err)
	}
}

// adapterSpy 记录 Adapter() 有没有被问过：这是「反向 PoC 真被接进执行器」的证据。
type adapterSpy struct {
	*fakeOOB
	adapterCalls int
}

func (a *adapterSpy) Adapter() string {
	a.adapterCalls++
	return a.fakeOOB.Adapter()
}

// 配了反连后端：不再 fail-closed，而是把适配器名交给子进程（由子进程自己读凭据）。
func TestPocSubmitReverseWithBackendInjectsAdapter(t *testing.T) {
	requireSubprocess(t)
	spy := &adapterSpy{fakeOOB: &fakeOOB{adapter: "alphalog"}}
	s := newOOBVerifyServer(t, spy)

	// 靶标不可达：这里不关心命中，只关心「有没有走到接反连这条路上」。
	out, err := s.tools["poc.submit"].Handler(context.Background(),
		mustJSON(t, map[string]any{"poc_path": writeReversePoC(t), "target": "http://127.0.0.1:1"}))
	if err != nil {
		t.Fatalf("poc.submit: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result = %#v, want a map", out)
	}
	if res["submitted"] != false {
		t.Fatalf("submitted = %v, want false on an unreachable target", res["submitted"])
	}
	if spy.adapterCalls == 0 {
		t.Fatal("the OOB backend was never consulted: the reverse PoC was not wired to it")
	}
}

// 非反向 PoC 不受影响：没有反连后端也照常执行，不命中就是不命中，不报错。
func TestPocSubmitPlainPoCUnaffectedByMissingOOB(t *testing.T) {
	requireSubprocess(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>nothing to see here</html>"))
	}))
	t.Cleanup(srv.Close)

	s := newOOBVerifyServer(t, nil)

	out, err := s.tools["poc.submit"].Handler(context.Background(),
		mustJSON(t, map[string]any{"poc_path": writeHitPoc(t), "target": srv.URL}))
	if err != nil {
		t.Fatalf("poc.submit: %v", err)
	}
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result = %#v, want a map", out)
	}
	if res["submitted"] != false {
		t.Fatalf("submitted = %v, want false (marker absent)", res["submitted"])
	}
}
