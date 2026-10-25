package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

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
