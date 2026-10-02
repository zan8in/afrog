package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// withProjectFixture 准备隔离环境：临时 HOME 会带来独立的 sqlite 与 projects.json，
// 测试之间以及与本机真实数据互不影响。
func withProjectFixture(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("NewWebSqliteDB: %v", err)
	}
	if err := sqlite.InitX(); err != nil {
		t.Fatalf("InitX: %v", err)
	}
	t.Cleanup(sqlite.CloseX)
}

func postProject(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(body))
	projectSaveHandler(rec, req)
	return rec
}

func getProjectView(t *testing.T, id string) projectView {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects/"+id, nil)
	req = mux.SetURLVars(req, map[string]string{"id": id})
	projectGetHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("取项目 status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data projectView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	return resp.Data
}

// onlyProject 返回当前唯一的项目，顺便断言确实只有一个。
func onlyProject(t *testing.T) Project {
	t.Helper()
	store, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(store.Items) != 1 {
		t.Fatalf("项目数 = %d, want 1", len(store.Items))
	}
	return store.Items[0]
}

// TestProjectTargetsComeFromText 锁定「文本框是项目目标的唯一入口」：
// 粘贴的地址会入库为资产，并成为项目成员。
func TestProjectTargetsComeFromText(t *testing.T) {
	withProjectFixture(t)

	body := `{"name":"客户A","targets_text":"https://a.example\n10.0.0.0/24\n\n  \nhttps://a.example"}`
	if rec := postProject(t, body); rec.Code != http.StatusOK {
		t.Fatalf("保存项目 status = %d, body = %s", rec.Code, rec.Body.String())
	}

	p := onlyProject(t)
	// 空行忽略、重复地址只算一次
	targets := resolveProjectTargets(p.ID)
	if len(targets) != 2 {
		t.Fatalf("项目目标 = %v, want 2 项（空行与重复应被忽略）", targets)
	}

	// 粘进来的地址同时成为资产
	n, err := sqlite.CountAssets()
	if err != nil {
		t.Fatalf("CountAssets: %v", err)
	}
	if n != 2 {
		t.Fatalf("资产总数 = %d, want 2（粘贴的目标要入库）", n)
	}
}

// TestProjectSaveReplacesAllTargets 保存即全量替换：文本里删掉的行 = 移除该目标。
func TestProjectSaveReplacesAllTargets(t *testing.T) {
	withProjectFixture(t)

	postProject(t, `{"name":"客户A","targets_text":"https://a.example\nhttps://b.example\nhttps://c.example"}`)
	p := onlyProject(t)
	if got := len(resolveProjectTargets(p.ID)); got != 3 {
		t.Fatalf("初始目标数 = %d, want 3", got)
	}

	// 只留一条：另外两条必须从项目里消失
	body := `{"id":"` + p.ID + `","name":"客户A","targets_text":"https://b.example"}`
	if rec := postProject(t, body); rec.Code != http.StatusOK {
		t.Fatalf("再次保存 status = %d, body = %s", rec.Code, rec.Body.String())
	}
	targets := resolveProjectTargets(p.ID)
	if len(targets) != 1 || targets[0] != "https://b.example" {
		t.Fatalf("全量替换后目标 = %v, want [https://b.example]", targets)
	}

	// 清空文本框：成员清空，但资产本身保留（资产是独立存在的）
	if rec := postProject(t, `{"id":"`+p.ID+`","name":"客户A","targets_text":""}`); rec.Code != http.StatusOK {
		t.Fatalf("清空保存 status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := resolveProjectTargets(p.ID); len(got) != 0 {
		t.Fatalf("清空后目标 = %v, want 空", got)
	}
	if n, _ := sqlite.CountAssets(); n != 3 {
		t.Fatalf("资产总数 = %d, want 3（清空项目不应删除资产）", n)
	}
}

// TestProjectGetReturnsTargetsForEditing 单个项目要带上完整目标，供编辑时回填文本框。
func TestProjectGetReturnsTargetsForEditing(t *testing.T) {
	withProjectFixture(t)

	postProject(t, `{"name":"导出用","targets_text":"https://a.example\nhttps://b.example"}`)
	p := onlyProject(t)

	view := getProjectView(t, p.ID)
	if view.AssetCount != 2 {
		t.Fatalf("asset_count = %d, want 2", view.AssetCount)
	}
	if len(view.Targets) != 2 {
		t.Fatalf("targets = %v, want 2 项（编辑需要回填）", view.Targets)
	}
}

// TestDeleteAssetsCascadesProjectMembership 删除资产必须连带清掉项目成员。
func TestDeleteAssetsCascadesProjectMembership(t *testing.T) {
	withProjectFixture(t)

	postProject(t, `{"name":"客户A","targets_text":"https://a.example\nhttps://b.example"}`)
	p := onlyProject(t)

	if _, err := sqlite.DeleteAssets([]string{"https://a.example"}); err != nil {
		t.Fatalf("DeleteAssets: %v", err)
	}
	targets := resolveProjectTargets(p.ID)
	if len(targets) != 1 || targets[0] != "https://b.example" {
		t.Fatalf("删除资产后目标 = %v, want [https://b.example]", targets)
	}
}

// 删除项目要连任务归属一起解除：留着的话，台账里这些命中会继续挂着一个已删除的
// project_id（界面只能显示裸 ID），按项目筛选也仍会命中它们。
func TestProjectDeleteUnlinksTasks(t *testing.T) {
	withProjectFixture(t)

	postProject(t, `{"name":"客户Z","targets_text":"https://z.example"}`)
	p := onlyProject(t)

	if err := sqlite.LinkTaskProject("t-linked", p.ID); err != nil {
		t.Fatalf("登记任务归属失败：%v", err)
	}
	if got, err := sqlite.SelectTaskProject("t-linked"); err != nil || got != p.ID {
		t.Fatalf("登记后的归属 = %q, %v；期望 %q", got, err, p.ID)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/projects/"+p.ID, nil)
	rec := httptest.NewRecorder()
	projectDeleteHandler(rec, mux.SetURLVars(req, map[string]string{"id": p.ID}))
	if rec.Code != http.StatusOK {
		t.Fatalf("删除项目应成功：%d %s", rec.Code, rec.Body.String())
	}

	got, err := sqlite.SelectTaskProject("t-linked")
	if err != nil {
		t.Fatalf("查询归属失败：%v", err)
	}
	if got != "" {
		t.Fatalf("删除项目后任务归属应被解除，实际 %q", got)
	}
}

// TestProjectSaveReportsIgnoredLines 无效行要被忽略并如实回报，不能悄悄吞掉。
func TestProjectSaveReportsIgnoredLines(t *testing.T) {
	withProjectFixture(t)

	rec := postProject(t, `{"name":"含脏数据","targets_text":"https://a.example\n这不是地址\n"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存 status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data projectSaveResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Data.Added != 1 || resp.Data.Invalid != 1 {
		t.Fatalf("入库统计 = %+v, want added=1 invalid=1", resp.Data)
	}
}

// TestProjectTargetsMigratedToAssetRefs 锁定旧数据升级：projects.json 里直接保存的目标
// 会被写成 project_asset 成员，且不再写出旧字段。
func TestProjectTargetsMigratedToAssetRefs(t *testing.T) {
	withProjectFixture(t)

	path, err := projectsFilePath()
	if err != nil {
		t.Fatalf("projectsFilePath: %v", err)
	}
	legacy := `{"items":[{"id":"p_legacy","name":"旧项目",` +
		`"targets":["https://old.example","1.2.3.4:8080"],"defaults":{},` +
		`"created_at":"2026-01-01 00:00:00","updated_at":"2026-01-01 00:00:00"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写入旧版 projects.json: %v", err)
	}

	migrateProjectsToAssets()

	if got := resolveProjectTargets("p_legacy"); len(got) != 2 {
		t.Fatalf("迁移后目标 = %v, want 2 项（旧目标应已入库）", got)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 projects.json: %v", err)
	}
	if strings.Contains(string(raw), `"targets"`) || strings.Contains(string(raw), `"asset_ids"`) {
		t.Fatalf("projects.json 仍写出旧的目标字段: %s", string(raw))
	}
}
