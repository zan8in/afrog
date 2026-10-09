package service

import (
	"context"
	"testing"
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
