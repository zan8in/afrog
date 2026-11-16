package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/policy"
)

// 本文件提供「真正拉起 afrog 子进程」的测试底座。
//
// MCP 的扫描动作（scan.start / verify.replay / poc.submit / act.brute）都改走子进程
// 执行器，理由是 pkg/sdk 的 HTTP 客户端、限速器与协议探测缓存是进程级全局状态，同进程
// 并发 scanner 会互相污染参数。测试因此不能再断言「进程内 SDK」，而必须构建真实二进制
// 并以子进程形式驱动——这与线上完全同一口径。
//
// 这些测试需要 go 工具链并会真实启动子进程，默认跳过，用 AFROG_MCP_SUBPROCESS=1 开启：
//
//	AFROG_MCP_SUBPROCESS=1 go test ./pkg/mcp -v

// subprocessEnabled 报告调用方是否显式开启了子进程测试。
func subprocessEnabled() bool { return os.Getenv("AFROG_MCP_SUBPROCESS") == "1" }

// requireSubprocess 在未开启子进程测试时跳过，并给出可复制的运行命令。
func requireSubprocess(t *testing.T) {
	t.Helper()
	if !subprocessEnabled() {
		t.Skip("set AFROG_MCP_SUBPROCESS=1 to run tests that build and drive the afrog binary")
	}
}

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

// afrogBinary 构建（一次）并返回 cmd/afrog 的临时二进制路径。
//
// 必须在切换 HOME 之前调用：go 的 GOCACHE / GOMODCACHE 默认挂在 HOME 下，先换 HOME
// 再 build 会拿到空模块缓存，进而重新下载 go.mod 声明的 toolchain，离线环境下会卡到超时。
func afrogBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "afrog-mcp-bin-*")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "afrog")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/afrog")
		cmd.Dir = mcpRepoRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build afrog: %v\n%s", err, out)
			return
		}
		builtBin = bin
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	return builtBin
}

// isolateAfrogHome 把 HOME 指向临时目录并关掉 curated 源：子进程因此只跑内置/本地 PoC，
// 既不访问网络，也不会碰用户真实的 afrog-config.yaml。
func isolateAfrogHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	confDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "afrog-config.yaml"), []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return home
}

// pocsMyDir 返回（必要时创建）临时 HOME 下的 pocs-my 目录。
func pocsMyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".config", "afrog", "pocs-my")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir pocs-my: %v", err)
	}
	return dir
}

// installPoc 把一份 PoC 落到临时 HOME 的 pocs-my：子进程的 -s / 仓库解析才能按 id 找到它。
func installPoc(t *testing.T, id, body string) string {
	t.Helper()
	path := filepath.Join(pocsMyDir(t), id+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write poc %s: %v", id, err)
	}
	return path
}

// subprocessExecutor 返回一个指向刚构建好的 afrog 二进制的本地进程执行器。
//
// -duc 关闭更新检查，避免子进程访问网络。
func subprocessExecutor(t *testing.T) executor.Executor {
	t.Helper()
	return &executor.LocalProcess{
		BinaryPath: afrogBinary(t),
		ExtraArgs:  []string{"-duc"},
	}
}

// newSubprocessServer 装配一个真正会拉起 afrog 子进程的工具面。
//
// 与 newIntegrationServer 的区别：这里注入本地进程执行器（否则懒加载会拿测试二进制
// 当 afrog 用），并显式要求开启子进程测试。二进制必须早于隔离 HOME 构建——go 的模块
// 缓存挂在 HOME 下，先换 HOME 再 build 会拿到空缓存。
func newSubprocessServer(t *testing.T, policyYAML string) *Server {
	t.Helper()
	requireSubprocess(t)
	bin := afrogBinary(t)
	isolateAfrogHome(t)

	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return New(Options{
		Policy:   p,
		Executor: &executor.LocalProcess{BinaryPath: bin, ExtraArgs: []string{"-duc"}},
	})
}

// runTool 是子进程测试里调用工具处理器的简写。
func runTool(t *testing.T, s *Server, name string, args map[string]any) any {
	t.Helper()
	out, err := s.tools[name].Handler(context.Background(), mustJSON(t, args))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

// mcpRepoRoot 返回本仓库根目录（本文件位于 <root>/pkg/mcp）。
func mcpRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
