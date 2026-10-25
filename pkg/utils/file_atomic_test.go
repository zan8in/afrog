package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// WriteFileAtomic 必须整体替换内容：读方在任意时刻只能看到完整的旧内容或新内容，
// 不允许看到 0 字节或半截。os.WriteFile 的「先截断、再写入」正是这么暴露的。
//
// 本用例对旧实现（os.WriteFile）会稳定失败：写方持续覆盖 256KB 内容，读方迟早落进
// 截断窗口读到一个长度对不上的文件。
func TestWriteFileAtomicNeverExposesPartialContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")

	contentA := bytes.Repeat([]byte("A"), 256*1024)
	contentB := bytes.Repeat([]byte("B"), 256*1024)

	if err := WriteFileAtomic(target, contentA, 0o644); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	const (
		writers    = 2
		readers    = 4
		iterations = 200
	)

	start := make(chan struct{})
	stopReaders := make(chan struct{})

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				payload := contentA
				if (id+i)%2 == 1 {
					payload = contentB
				}
				if err := WriteFileAtomic(target, payload, 0o644); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(w)
	}

	var rg sync.WaitGroup
	for r := 0; r < readers; r++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			<-start
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				got, err := os.ReadFile(target)
				if err != nil {
					t.Errorf("read: %v", err)
					return
				}
				if !bytes.Equal(got, contentA) && !bytes.Equal(got, contentB) {
					t.Errorf("读到半截内容: len=%d", len(got))
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(stopReaders)
	rg.Wait()
}

// 临时文件不能残留在目标目录里（否则 ~/.config/afrog 会被 .afrog-*.tmp 塞满）。
func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")

	for i := 0; i < 5; i++ {
		if err := WriteFileAtomic(target, []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("目录里应只剩目标文件，实际: %v", names)
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// CreateTemp 建出来是 0600，必须还原成调用方给的权限。
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("权限应为 0600，实际 %o", perm)
	}
}

// 目标目录不存在时自动创建，语义与原有 utils.WriteFile 保持一致。
func TestWriteFileAtomicCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "deep", "state.json")

	if err := WriteFileAtomic(target, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("content = %q", got)
	}
}
