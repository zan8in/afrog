package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAgentSectionKeepsMCPSubsection 回归「保存策略抹掉 agent.mcp 子段」。
//
// agent 段是整块替换（见 replaceTopLevelSection），内容由 agentSectionLines 生成。
// 若它只输出 policy/audit/oob 而漏掉 mcp，则用户随后在控制台保存「策略与审计」时会把
// agent.mcp 整段抹掉且无任何提示。这里验证：带 mcp 往返、只改 policy 时 mcp 仍在、
// 清空后子段被移除。
func TestAgentSectionKeepsMCPSubsection(t *testing.T) {
	path := filepath.Join(t.TempDir(), afrogConfigFilename)
	if err := os.WriteFile(path, []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	full := Agent{
		Policy: "/tmp/p.yaml",
		Audit:  "/tmp/a.jsonl",
		OOB:    "ceyeio",
		MCP:    AgentMCP{Listen: "127.0.0.1:16870", Token: "deadbeef"},
	}
	if err := UpdateAgentSection(path, full); err != nil {
		t.Fatalf("write agent section: %v", err)
	}

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if cfg.Agent.MCP.Listen != "127.0.0.1:16870" || cfg.Agent.MCP.Token != "deadbeef" {
		t.Fatalf("mcp round-trip failed: %+v", cfg.Agent.MCP)
	}
	if cfg.Agent.Policy != "/tmp/p.yaml" {
		t.Fatalf("policy = %q, want /tmp/p.yaml", cfg.Agent.Policy)
	}

	// 模拟「保存策略」：带上当前 mcp 原样回写，mcp 必须还在。
	if err := UpdateAgentSection(path, Agent{
		Policy: "/tmp/p2.yaml",
		Audit:  "/tmp/a.jsonl",
		OOB:    "ceyeio",
		MCP:    cfg.Agent.MCP,
	}); err != nil {
		t.Fatalf("rewrite agent section: %v", err)
	}
	cfg2, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("read back 2: %v", err)
	}
	if cfg2.Agent.MCP.Listen != "127.0.0.1:16870" {
		t.Fatalf("mcp lost after policy save: %+v", cfg2.Agent.MCP)
	}
	if cfg2.Agent.Policy != "/tmp/p2.yaml" {
		t.Fatalf("policy not updated: %q", cfg2.Agent.Policy)
	}

	// 清空 mcp：listen/token 都空时应移除整个子段，避免留下空壳。
	if err := UpdateAgentSection(path, Agent{Policy: "/tmp/p2.yaml"}); err != nil {
		t.Fatalf("clear mcp: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "mcp:") {
		t.Fatalf("empty mcp should be omitted, got:\n%s", raw)
	}
}

// TestReadConfigurationNotBrokenByConcurrentWrite 回归「配置写回把读方坑成 io.EOF」。
//
// 配置写回原先用 os.WriteFile，语义是「先截断、再写入」。同一台机器上并发启动的多个
// afrog 进程会同时读同一个 ~/.config/afrog/afrog-config.yaml，读方恰好落进截断窗口
// 就会读到 0 字节，yaml 解码返回 io.EOF，NewConfig 失败、整个扫描零事件退出（命令行
// 上只留下一句没头没尾的 [ERR] EOF）。
//
// 这里让读方与写方并发跑同一份文件，断言读方永远拿不到 io.EOF：写回改成
// 「临时文件 + rename」后，读方只可能看到完整的新旧内容。
func TestReadConfigurationNotBrokenByConcurrentWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), afrogConfigFilename)

	seed := "curated:\n  enabled: \"off\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		eofHit int
		others []error
	)

	const writers = 3
	const readers = 3
	const writeRounds = 300
	const readRounds = 300

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writeRounds; j++ {
				cfg := defaultConfig()
				cfg.Curated.Enabled = "off"
				if err := WriteConfiguration(cfg, path); err != nil {
					mu.Lock()
					others = append(others, err)
					mu.Unlock()
				}
				if err := ensureInteractshSection(path, Interactsh{Server: "oast.pro"}); err != nil {
					mu.Lock()
					others = append(others, err)
					mu.Unlock()
				}
			}
		}()
	}

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < readRounds; j++ {
				if _, err := ReadConfiguration(path); err != nil {
					mu.Lock()
					if errors.Is(err, io.EOF) {
						eofHit++
					} else {
						others = append(others, err)
					}
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	for _, err := range others {
		t.Errorf("unexpected read/write error: %v", err)
	}
	if eofHit > 0 {
		t.Fatalf("ReadConfiguration hit io.EOF %d time(s): 配置文件被并发写回截断", eofHit)
	}
}
