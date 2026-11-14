package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/guard"
)

// withGuardAuditFile 把审计文件指到临时目录，避免测试写用户目录。
func withGuardAuditFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guard_audit.jsonl")
	prev := securityAuditPathOverride
	securityAuditPathOverride = path
	t.Cleanup(func() { securityAuditPathOverride = prev })
	return path
}

// appendRawAuditLine 直接追加一行原文，用于模拟掉电留下的损坏记录。
func appendRawAuditLine(t *testing.T, line string) {
	t.Helper()
	f, err := os.OpenFile(securityAuditPathOverride, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("write audit line: %v", err)
	}
	_ = f.Close()
}

// TestGuardAuditRoundTrip 锁定落盘格式与读取口径：最新在前、坏行跳过。
func TestGuardAuditRoundTrip(t *testing.T) {
	withGuardAuditFile(t)

	now := time.Now()
	for _, entry := range []guard.Entry{
		{Time: now.Add(-2 * time.Minute), Action: guard.ActionClusterDispatch, Target: "a.example", Mode: guard.ModeAllow, Allowed: true},
		{Time: now.Add(-time.Minute), Action: guard.ActionExposureProbe, Target: "b.example:8443", Mode: guard.ModeDeny, Reason: "目标不在安全白名单内"},
		{Time: now, Action: guard.ActionClusterDispatch, Target: "c.example", Mode: guard.ModeAsk, Reason: "需要人工确认"},
	} {
		appendGuardAudit(entry)
	}
	// 模拟掉电留下的半行：解析失败应被跳过，而不是让整个审计不可读。
	appendRawAuditLine(t, `{"action":"truncated"`)

	got := loadGuardAudit(10)
	if len(got) != 3 {
		t.Fatalf("审计条数 = %d, want 3", len(got))
	}
	if got[0].Target != "c.example" || got[2].Target != "a.example" {
		t.Fatalf("审计顺序 = %+v, want 最新在前", got)
	}
	if got[0].Allowed {
		t.Fatalf("ask 不应被记为放行: %+v", got[0])
	}

	// limit 只取最后 N 条。
	if short := loadGuardAudit(2); len(short) != 2 || short[0].Target != "c.example" {
		t.Fatalf("limit=2 结果 = %+v", short)
	}
}

// TestSecurityPolicyHandlerReturnsPersistedAudit 锁定接口口径：
// 重启后内存审计为空，但接口仍要返回落盘记录。
func TestSecurityPolicyHandlerReturnsPersistedAudit(t *testing.T) {
	withGuardAuditFile(t)

	appendGuardAudit(guard.Entry{
		Time: time.Now(), Action: guard.ActionClusterDispatch,
		Target: "evil.example", Mode: guard.ModeDeny, Reason: "目标不在安全白名单内",
	})

	rec := httptest.NewRecorder()
	securityPolicyHandler(rec, httptest.NewRequest(http.MethodGet, "/api/security/policy", nil))

	var resp struct {
		Success bool       `json:"success"`
		Data    guard.View `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Fatalf("接口返回失败: %s", rec.Body.String())
	}
	if len(resp.Data.Audit) != 1 || resp.Data.Audit[0].Target != "evil.example" {
		t.Fatalf("审计 = %+v, want 落盘记录", resp.Data.Audit)
	}
	if len(resp.Data.AllowTargets) != 0 || resp.Data.AllowTargets == nil {
		t.Fatalf("allow_targets 应为空数组而非 nil: %#v", resp.Data.AllowTargets)
	}
}
