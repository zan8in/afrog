package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
)

// withCuratedSection 把会员配置指向一个临时文件，并在用例结束后复原，避免污染真实配置。
func withCuratedSection(t *testing.T, body string) string {
	t.Helper()
	prevCfg, prevPath := currentCuratedSection()
	prevSvc := getCuratedService()
	t.Cleanup(func() {
		SetCuratedService(prevSvc)
		setCuratedSection(prevCfg, prevPath)
	})

	path := filepath.Join(t.TempDir(), "afrog-config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	setCuratedSection(config.Curated{}, path)
	return path
}

// 保存会员配置：文件必须写成功；即使随后拉取 PoC 失败，也不能回滚配置或报成失败。
//
// 把 HOME 指向临时目录，隔离 curated-auth.json / curated-state.json / pocs-curated，
// 否则这条用例会改写开发者本机的会员运行态。
func TestCuratedConfigPut_SavesFileEvenWhenMountFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	path := withCuratedSection(t, "server: :16869\n\ncurated:\n  enabled: \"auto\"\n  endpoint: \"\"\n")

	body := `{"enabled":"on","endpoint":"` + upstream.URL + `","channel":"",` +
		`"license_key":"LIC_test","auto_update":false,"timeout_sec":0}`
	rec := httptest.NewRecorder()
	curatedConfigPutHandler(rec, httptest.NewRequest(http.MethodPut, "/api/curated/config", strings.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("配置已写入就应返回 200，实际 %d %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Config curatedConfigPayload `json:"config"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v\n%s", err, rec.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success 应为 true：%s", rec.Body.String())
	}
	if !strings.Contains(resp.Message, "拉取 PoC 失败") {
		t.Fatalf("应说明拉取失败而不是含糊成功：%q", resp.Message)
	}
	// 归一化：channel 留空回落 stable，timeout_sec=0 回落 10，enabled 保持 on
	if resp.Data.Config.Channel != "stable" || resp.Data.Config.TimeoutSec != 10 ||
		resp.Data.Config.Enabled != "on" {
		t.Fatalf("归一化结果不对: %+v", resp.Data.Config)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	text := string(got)
	if !strings.Contains(text, "server: :16869") {
		t.Fatalf("其它段落被破坏：\n%s", text)
	}
	if !strings.Contains(text, `endpoint: "`+upstream.URL+`"`) {
		t.Fatalf("endpoint 未写入：\n%s", text)
	}
	if !strings.Contains(text, `license_key: "LIC_test"`) || !strings.Contains(text, "auto_update: false") {
		t.Fatalf("license / 自动更新未写入：\n%s", text)
	}
}

// 非法地址在写文件之前就该被拦下，文件不能被改动。
func TestCuratedConfigPut_RejectsBadEndpoint(t *testing.T) {
	original := "curated:\n  enabled: \"auto\"\n"
	path := withCuratedSection(t, original)

	rec := httptest.NewRecorder()
	curatedConfigPutHandler(rec, httptest.NewRequest(http.MethodPut, "/api/curated/config",
		strings.NewReader(`{"enabled":"on","endpoint":"afrogx.com:8787"}`)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法地址应 400，实际 %d %s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if string(got) != original {
		t.Fatalf("校验失败时不应改动文件：\n%s", got)
	}
}

// GET 回显的就是注入的 curated 段，且总是带一个具体路径，界面才能如实告诉用户写的是哪个文件。
func TestCuratedConfigGet_EchoesSection(t *testing.T) {
	path := withCuratedSection(t, "curated:\n  enabled: \"auto\"\n")
	autoUpdate := true
	setCuratedSection(config.Curated{
		Enabled:    "ON",
		AutoUpdate: &autoUpdate,
		Endpoint:   " http://afrogx.com:8787/ ",
		Channel:    "",
		LicenseKey: " LIC_1 ",
	}, path)

	rec := httptest.NewRecorder()
	curatedConfigGetHandler(rec, httptest.NewRequest(http.MethodGet, "/api/curated/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 应 200，实际 %d", rec.Code)
	}

	var resp struct {
		Data curatedConfigPayload `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v\n%s", err, rec.Body.String())
	}
	if resp.Data.Enabled != "on" {
		t.Fatalf("enabled 应归一成小写 on: %q", resp.Data.Enabled)
	}
	if resp.Data.Endpoint != "http://afrogx.com:8787/" || resp.Data.LicenseKey != "LIC_1" {
		t.Fatalf("应去掉首尾空白但保留原值: %+v", resp.Data)
	}
	if resp.Data.Channel != "stable" {
		t.Fatalf("空渠道应回落 stable: %q", resp.Data.Channel)
	}
	if resp.Data.ConfigPath != path {
		t.Fatalf("config_path = %q，期望 %q", resp.Data.ConfigPath, path)
	}
}
