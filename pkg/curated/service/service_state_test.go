package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRuntimeTimestamps(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := &Service{cfg: Config{Channel: "stable"}}

	if err := s.updateRuntimeUpdated("/tmp/pocs-curated", "m-1"); err != nil {
		t.Fatalf("updateRuntimeUpdated error: %v", err)
	}
	st1, err := s.Status(context.Background())
	if err != nil {
		t.Fatalf("status error: %v", err)
	}
	if st1.State == nil {
		t.Fatalf("state is nil")
	}
	if st1.State.LastCheckAt.IsZero() || st1.State.LastUpdateAt.IsZero() {
		t.Fatalf("expected non-zero timestamps, got check=%v update=%v", st1.State.LastCheckAt, st1.State.LastUpdateAt)
	}
	prevUpdate := st1.State.LastUpdateAt

	if err := s.updateRuntimeCheck("/tmp/pocs-curated", "m-1", ""); err != nil {
		t.Fatalf("updateRuntimeCheck error: %v", err)
	}
	st2, err := s.Status(context.Background())
	if err != nil {
		t.Fatalf("status error: %v", err)
	}
	if st2.State == nil {
		t.Fatalf("state is nil")
	}
	if st2.State.LastCheckAt.IsZero() {
		t.Fatalf("expected non-zero last_check_at")
	}
	if !st2.State.LastUpdateAt.Equal(prevUpdate) {
		t.Fatalf("expected last_update_at unchanged, prev=%v got=%v", prevUpdate, st2.State.LastUpdateAt)
	}
}

// 失败时不能推进 last_check_at：否则「下次是否重试」会被 6 小时门槛挡住，
// 而这次其实什么都没拿到（这正是「必须手动 -curated-force-update」的成因之一）。
func TestUpdateRuntimeFailedKeepsLastCheckAt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	s := &Service{cfg: Config{Channel: "stable"}}

	if err := s.updateRuntimeUpdated("/tmp/pocs-curated", "m-1"); err != nil {
		t.Fatalf("updateRuntimeUpdated error: %v", err)
	}
	before, err := s.Status(context.Background())
	if err != nil || before.State == nil {
		t.Fatalf("status: err=%v state=%v", err, before.State)
	}
	prevCheck := before.State.LastCheckAt
	prevUpdate := before.State.LastUpdateAt

	if err := s.updateRuntimeFailed("/tmp/pocs-curated", "m-1", "invalid license (unauthorized)"); err != nil {
		t.Fatalf("updateRuntimeFailed error: %v", err)
	}
	after, err := s.Status(context.Background())
	if err != nil || after.State == nil {
		t.Fatalf("status: err=%v state=%v", err, after.State)
	}
	if !after.State.LastCheckAt.Equal(prevCheck) {
		t.Fatalf("last_check_at 不应被推进: before=%v after=%v", prevCheck, after.State.LastCheckAt)
	}
	if !after.State.LastUpdateAt.Equal(prevUpdate) {
		t.Fatalf("last_update_at 不应变化: before=%v after=%v", prevUpdate, after.State.LastUpdateAt)
	}
	if after.State.LastError != "invalid license (unauthorized)" {
		t.Fatalf("last_error = %q", after.State.LastError)
	}
}

// refresh 失败后的回退登录判定：只对鉴权类错误放行，限流/超时等不应触发重登（避免登录风暴）。
func TestShouldReloginAfterRefreshError(t *testing.T) {
	yes := []string{
		"invalid refresh token",
		"refresh token unauthorized",
		"invalid license (unauthorized)",
		"Unauthorized",
		"invalid token",
		"Forbidden",
	}
	for _, m := range yes {
		if !shouldReloginAfterRefreshError(m) {
			t.Errorf("%q 应触发回退登录", m)
		}
	}

	no := []string{
		"",
		"context deadline exceeded",
		"too many requests",
		"no artifact available",
		"invalid auth state checksum",
	}
	for _, m := range no {
		if shouldReloginAfterRefreshError(m) {
			t.Errorf("%q 不应触发回退登录", m)
		}
	}
}

// curated-auth.json 是 fail-closed 的：readAuth 读到半截 JSON 或校验和失配就直接判
// 「未登录」。写方用「先截断再写」，读方落进窗口就会莫名掉登录；原子写后任何一次读
// 都必须是完整内容。
func TestWriteAuthIsAtomicUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "curated-auth.json")

	base := authState{
		LicenseKey:        "lk",
		AccountID:         "acct",
		DeviceID:          "dev",
		DeviceFingerprint: "fp",
		AccessToken:       "at",
		RefreshToken:      "rt",
		AccessExpiresAt:   time.Now().Add(time.Hour),
		RefreshExpiresAt:  time.Now().Add(24 * time.Hour),
		UpdatedAt:         time.Now(),
	}
	if err := writeAuth(path, &base); err != nil {
		t.Fatalf("seed writeAuth: %v", err)
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
				st := base
				// 变动 LicenseKey 会同时改变 checksum，覆盖「内容变了」的真实场景。
				st.LicenseKey = fmt.Sprintf("lk-%d-%d", id, i)
				if err := writeAuth(path, &st); err != nil {
					t.Errorf("writeAuth: %v", err)
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
				if _, err := readAuth(path); err != nil {
					t.Errorf("readAuth 读到不完整内容: %v", err)
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

// curated-state.json 被 CLI 横幅（pkg/config/banner.go）直接读取，半截内容会让横幅
// 渲染失败。写方是四个 updateRuntime* 入口，全部走原子写后读方不再报错。
func TestUpdateRuntimeIsAtomicUnderConcurrency(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	s := &Service{cfg: Config{Channel: "stable"}}
	if err := s.updateRuntimeUpdated("/tmp/pocs-curated", "m-0"); err != nil {
		t.Fatalf("seed updateRuntimeUpdated: %v", err)
	}

	cfgDir, err := configDir()
	if err != nil {
		t.Fatalf("configDir: %v", err)
	}
	path := filepath.Join(cfgDir, "curated-state.json")

	const (
		writers    = 2
		readers    = 4
		iterations = 100
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
				manifestID := fmt.Sprintf("m-%d-%d", id, i)
				var werr error
				if i%2 == 0 {
					werr = s.updateRuntimeCheck("/tmp/pocs-curated", manifestID, "")
				} else {
					werr = s.updateRuntimeFailed("/tmp/pocs-curated", manifestID, "boom")
				}
				if werr != nil {
					t.Errorf("updateRuntime: %v", werr)
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
				if _, err := readRuntime(path); err != nil {
					t.Errorf("readRuntime 读到不完整内容: %v", err)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(stopReaders)
	rg.Wait()

	// 收尾后目录里不应残留临时文件。
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "curated-state.json" {
			t.Fatalf("目录里出现意外文件: %v", e.Name())
		}
	}
}
