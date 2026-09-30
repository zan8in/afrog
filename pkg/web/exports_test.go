package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/webreport"
)

func TestParseExportFormat(t *testing.T) {
	cases := []struct {
		in     string
		want   exportFormat
		wantOK bool
	}{
		{"", formatHTML, true},
		{"html", formatHTML, true},
		{"HTML", formatHTML, true},
		{" xlsx ", formatXLSX, true},
		{"md", formatMarkdown, true},
		{"pdf", "", false},
		{"csv", "", false},
	}
	for _, c := range cases {
		got, ok := parseExportFormat(c.in)
		if ok != c.wantOK || got != c.want {
			t.Errorf("parseExportFormat(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestExportFormatContentTypes(t *testing.T) {
	if got := exportContentType(formatXLSX); !strings.Contains(got, "spreadsheetml") {
		t.Errorf("xlsx content type = %q", got)
	}
	if got := exportContentType(formatHTML); !strings.Contains(got, "text/html") {
		t.Errorf("html content type = %q", got)
	}
	if got := exportContentType(formatMarkdown); !strings.Contains(got, "text/markdown") {
		t.Errorf("md content type = %q", got)
	}

	if got := exportExtension(formatMarkdown); got != "md" {
		t.Errorf("md extension = %q", got)
	}
}

// TestContentDispositionHandlesChineseName 保证中文报告名能正确落地：
// 既要有 ASCII 回退名，也要有 RFC 5987 的 UTF-8 名。
func TestContentDispositionHandlesChineseName(t *testing.T) {
	got := contentDisposition("attachment", "afrog-测试项目-20260928.html")

	if !strings.HasPrefix(got, "attachment;") {
		t.Fatalf("missing disposition: %q", got)
	}
	if !strings.Contains(got, `filename="afrog-`) {
		t.Fatalf("missing ascii fallback: %q", got)
	}
	if strings.Contains(got, `filename="afrog-测`) {
		t.Fatalf("ascii fallback still contains raw UTF-8: %q", got)
	}
	if !strings.Contains(got, "filename*=UTF-8''afrog-%E6%B5%8B%E8%AF%95") {
		t.Fatalf("missing rfc5987 filename: %q", got)
	}

	// 引号与反斜杠必须被替换，避免响应头被截断
	injected := contentDisposition("inline", `a"b\c.html`)
	if strings.Contains(injected, `"a"b`) {
		t.Fatalf("quote not sanitized: %q", injected)
	}
}

func TestDistinctTargetsDedupesAndKeepsOrder(t *testing.T) {
	rows := []db.ResultData{
		{Target: "http://b.example"},
		{Target: "http://a.example"},
		{Target: "http://b.example"},
		{Target: "   "},
		{Target: "http://c.example"},
	}

	got := distinctTargets(rows)
	want := []string{"http://b.example", "http://a.example", "http://c.example"}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}

	if got := distinctTargets(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil rows should yield an empty slice, got %v", got)
	}
}

// exportTestRows 提供一份最小的真实数据形状。
func exportTestRows() []db.ResultData {
	return []db.ResultData{
		{
			ID: 2, TaskID: "t-1", VulID: "poc-a", VulName: "测试漏洞",
			Target: "http://a.example", FullTarget: "http://a.example/1",
			Severity: "HIGH", Created: "2026-09-28 10:00:00",
			ResultList: []db.PocResult{{FullTarget: "http://a.example/1", Request: "GET /1 HTTP/1.1", Response: "HTTP/1.1 200 OK"}},
		},
		{
			ID: 1, TaskID: "t-1", VulID: "poc-b", VulName: "另一个漏洞",
			Target: "http://a.example", FullTarget: "http://a.example/2",
			Severity: "LOW", Created: "2026-09-28 10:01:00",
		},
	}
}

func exportTestMeta() webreport.Meta {
	return webreport.Meta{
		Title:       "扫描报告",
		Subject:     "测试任务",
		TaskIDs:     []string{"t-1"},
		Targets:     []string{"http://a.example"},
		GeneratedAt: time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC),
	}
}

// renderExportForTest 通过 renderExport 走一遍真实的响应写入路径。
func renderExportForTest(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/exports/task/t-1"+query, nil)
	rec := httptest.NewRecorder()
	renderExport(rec, req, exportTestMeta(), exportTestRows())
	return rec
}

func TestRenderExportMarkdownIsAvailableToFreeUsers(t *testing.T) {
	// 单元测试进程里没有注入 curated 服务，因此当前角色必然是 free。
	if curatedRole() != "free" {
		t.Fatalf("precondition failed: role = %q, want free", curatedRole())
	}

	rec := renderExportForTest(t, "?format=md")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Fatalf("content type = %q", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".md") {
		t.Fatalf("content disposition = %q", cd)
	}
	if body := rec.Body.String(); !strings.Contains(body, "# 扫描报告") || !strings.Contains(body, "poc-a") {
		t.Fatalf("markdown body unexpected: %s", body)
	}
}

// TestRenderExportBlocksMemberFormatsForFreeUsers 是本功能的安全边界：
// HTML / Excel（以及由 HTML 打印出的 PDF）不能只靠前端隐藏来收费。
func TestRenderExportBlocksMemberFormatsForFreeUsers(t *testing.T) {
	if curatedRole() != "free" {
		t.Skip("curated 服务已注入，跳过免费用户场景")
	}

	for _, query := range []string{"?format=html", "?format=xlsx", "?format=html&print=1"} {
		rec := renderExportForTest(t, query)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", query, rec.Code)
		}
		var resp APIResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s body is not json: %s", query, rec.Body.String())
		}
		if resp.Success {
			t.Fatalf("%s should report failure", query)
		}
		if !strings.Contains(resp.Message, "Curated") {
			t.Fatalf("%s message = %q", query, resp.Message)
		}
	}
}

func TestRenderExportRejectsUnknownFormat(t *testing.T) {
	rec := renderExportForTest(t, "?format=pdf")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "format") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestExportFormatAllowedMatrix(t *testing.T) {
	if !exportFormatAllowed(formatMarkdown) {
		t.Fatal("markdown should be allowed for free users")
	}
	// 无 curated 服务时，会员格式必须被拒绝
	if exportFormatAllowed(formatHTML) || exportFormatAllowed(formatXLSX) {
		t.Fatal("member-only formats must not be allowed for free users")
	}
}
