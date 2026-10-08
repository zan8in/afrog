package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// freeProjectLimit 是免费版可创建的项目数量上限，Curated 不限。
const freeProjectLimit = 1

// ProjectDefaults 是项目的默认扫描参数，选中项目时一键带入扫描表单。
//
// 采用稀疏的「请求字段名 → 值」对象：只包含被显式覆盖的项，缺省的键表示沿用内置默认。
// 后端只做透传（存 + 回显），不解释内容——前端用 toProjectDefaults / scanParamsFromProject
// 读写，因此这里保持不透明，避免在 Go 侧再维护一张与前端字段表平行的结构。
type ProjectDefaults map[string]any

// MarshalJSON 让空值也输出 {}，避免前端在 defaults 上拿到 null。
func (d ProjectDefaults) MarshalJSON() ([]byte, error) {
	if d == nil {
		return []byte("{}"), nil
	}
	// 借用别名类型，避免递归调用本方法
	type plain ProjectDefaults
	return json.Marshal(plain(d))
}

// Project 是一个资产空间：引用一组资产 + 默认配置 +（后续）扫描历史与台账。
//
// 成员关系存在 SQLite 的 project_asset 表里（一个项目可能引用上万条资产），
// 这里只留名称与默认参数这类轻量字段。
type Project struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Defaults    ProjectDefaults `json:"defaults"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`

	// Legacy* 只用于读取旧版 projects.json（那里把目标直接存成了列表）。
	// 启动时由 migrateProjectsToAssets 转成 project_asset 成员，之后不再写出。
	LegacyAssetIDs []string `json:"asset_ids,omitempty"`
	LegacyTargets  []string `json:"targets,omitempty"`
}

// projectView 是返回给前端的项目视图。
//
// 列表不回传目标明细（可能上万条）：只给数量与前几条预览。
// 编辑时前端需要把目标回填进文本框，所以只有「取单个项目」会带上完整 Targets。
type projectView struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	AssetCount  int64           `json:"asset_count"`
	Preview     []string        `json:"preview"`
	Defaults    ProjectDefaults `json:"defaults"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
	ScanCount   int64           `json:"scan_count"`
	// Targets 仅由 projectGetHandler 填充（编辑时回填文本框用）。
	Targets []string `json:"targets,omitempty"`
}

type projectStore struct {
	Items []Project `json:"items"`
}

var projectMu sync.Mutex

func projectsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "projects.json"), nil
}

func loadProjects() (*projectStore, error) {
	path, err := projectsFilePath()
	if err != nil {
		return nil, err
	}
	store := &projectStore{Items: []Project{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, store); err != nil {
			return nil, err
		}
	}
	if store.Items == nil {
		store.Items = []Project{}
	}
	return store, nil
}

func saveProjects(store *projectStore) error {
	path, err := projectsFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// normalizeProjectTargets 归一化目标：去空白、丢弃非法、按序去重。
func normalizeProjectTargets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, t := range in {
		ts := strings.TrimSpace(t)
		if ts == "" || !isValidAddress(ts) {
			continue
		}
		nt := normalizeAddress(ts)
		if seen[nt] {
			continue
		}
		seen[nt] = true
		out = append(out, nt)
	}
	return out
}

// ensureProjectAssets 保证这些地址都在资产表里存在——目标是唯一真源，
// 项目只持有引用，所以用户粘贴进来的新地址要先入库，引用才不是悬空的。
// 已存在的资产原样保留（含用户自己打的标签、收藏等）。
func ensureProjectAssets(projectID string, addresses []string) error {
	inputs := make([]sqlite.AssetInput, 0, len(addresses))
	for _, addr := range addresses {
		if t := strings.TrimSpace(addr); t != "" {
			inputs = append(inputs, sqlite.AssetInput{Address: t, Type: classifyAddress(t)})
		}
	}
	if len(inputs) == 0 {
		return nil
	}
	_, err := sqlite.CreateAssets("project", projectID, nil, inputs)
	return err
}

// resolveProjectTargets 返回项目成员的可扫描地址，供起扫与报告头使用。
func resolveProjectTargets(projectID string) []string {
	targets, err := sqlite.ProjectAssetAddresses(projectID)
	if err != nil {
		gologger.Warning().Msgf("resolve project %s assets failed: %v", projectID, err)
		return []string{}
	}
	if targets == nil {
		return []string{}
	}
	return targets
}

// toProjectView 组装返回给前端的项目视图：只给数量与少量预览，不回传全量目标。
func toProjectView(p Project, scanCount int64) projectView {
	count, err := sqlite.CountProjectAssets(p.ID)
	if err != nil {
		gologger.Warning().Msgf("count project %s assets failed: %v", p.ID, err)
	}
	preview, err := sqlite.ProjectAssetPreview(p.ID, 3)
	if err != nil {
		gologger.Warning().Msgf("preview project %s assets failed: %v", p.ID, err)
		preview = []string{}
	}
	return projectView{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		AssetCount:  count,
		Preview:     preview,
		Defaults:    p.Defaults,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
		ScanCount:   scanCount,
	}
}

// saveProjectTargets 把文本框里的目标写进项目。
//
// 文本框就是项目目标的唯一入口（新建与编辑都走这里）：先保证地址都入库为资产，
// 再用这批地址整体替换项目成员——保存即全量替换，删掉的行就等于移除目标。
func saveProjectTargets(projectID, targetsText string) (sqlite.AssetSinkResult, error) {
	out := sqlite.AssetSinkResult{}
	inputs, invalid := buildAssetInputs(strings.Split(targetsText, "\n"))
	out.Invalid = invalid

	addresses := make([]string, 0, len(inputs))
	for _, in := range inputs {
		addresses = append(addresses, in.Address)
	}

	// 没有有效目标时清空成员，避免旧目标残留。
	if len(addresses) > 0 {
		res, err := sqlite.CreateAssets("project", projectID, nil, inputs)
		if err != nil {
			return out, err
		}
		out.Added = res.Added
		out.Existing = res.Existing
	}

	if _, err := sqlite.ReplaceProjectAssets(projectID, addresses); err != nil {
		return out, err
	}
	return out, nil
}

// migrateProjectsToAssets 是一次性升级：把旧版 projects.json 里直接保存的目标列表
// 转成 project_asset 成员，并把目标补进资产表。幂等：迁移后旧字段被清空。
func migrateProjectsToAssets() {
	projectMu.Lock()
	defer projectMu.Unlock()

	store, err := loadProjects()
	if err != nil {
		gologger.Warning().Msgf("migrate projects failed: %v", err)
		return
	}

	changed := false
	for i := range store.Items {
		p := &store.Items[i]
		legacy := p.LegacyAssetIDs
		if len(legacy) == 0 {
			legacy = p.LegacyTargets
		}
		if len(legacy) == 0 {
			continue
		}

		ids := normalizeProjectTargets(legacy)
		if len(ids) > 0 {
			if err := ensureProjectAssets(p.ID, ids); err != nil {
				// 入库失败就整条跳过，下次启动再试，避免丢掉旧目标。
				gologger.Warning().Msgf("migrate project %s targets failed: %v", p.ID, err)
				continue
			}
			if _, err := sqlite.ReplaceProjectAssets(p.ID, ids); err != nil {
				gologger.Warning().Msgf("migrate project %s membership failed: %v", p.ID, err)
				continue
			}
		}
		p.LegacyAssetIDs = nil
		p.LegacyTargets = nil
		changed = true
	}
	if !changed {
		return
	}
	if err := saveProjects(store); err != nil {
		gologger.Warning().Msgf("migrate projects save failed: %v", err)
		return
	}
	gologger.Info().Msg("已将旧项目的目标迁移为资产引用")
}

// findProject 返回指定项目及其是否存在。
func findProject(id string) (Project, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Project{}, false
	}
	store, err := loadProjects()
	if err != nil {
		return Project{}, false
	}
	for _, p := range store.Items {
		if p.ID == id {
			return p, true
		}
	}
	return Project{}, false
}

// projectsListHandler 返回项目列表。免费版有数量上限，通过 limit 告知前端。
func projectsListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	projectMu.Lock()
	store, err := loadProjects()
	projectMu.Unlock()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目读取失败"})
		return
	}

	items := append([]Project{}, store.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt > items[j].UpdatedAt })

	// 附带每个项目的扫描次数（来自 task_project 归属表）与解析后的目标地址。
	out := make([]projectView, 0, len(items))
	for _, p := range items {
		n, _ := sqlite.CountTasksByProject(p.ID)
		out = append(out, toProjectView(p, n))
	}

	limit := freeProjectLimit
	if curatedRole() == "curated" {
		limit = -1
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]interface{}{
		"items": out,
		"total": len(out),
		"limit": limit,
	}})
}

// projectGetHandler 返回单个项目。
func projectGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["id"])
	p, ok := findProject(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目不存在"})
		return
	}
	n, _ := sqlite.CountTasksByProject(p.ID)
	view := toProjectView(p, n)
	// 编辑时要把目标回填进文本框，所以单个项目才带上完整清单。
	view.Targets = resolveProjectTargets(p.ID)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: view})
}

type projectSaveRequest struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// TargetsText 是项目的全部目标（一行一个）。保存即全量替换成员，
	// 与「资产只在资产库存一份」并不冲突：地址会先入库为资产，再建立引用。
	TargetsText string          `json:"targets_text"`
	Defaults    ProjectDefaults `json:"defaults,omitempty"`
}

// projectSaveResponse 是保存项目的返回：项目视图 + 本次目标的入库统计。
type projectSaveResponse struct {
	Project  projectView `json:"project"`
	Added    int         `json:"added"`
	Existing int         `json:"existing"`
	Invalid  int         `json:"invalid"`
}

// projectSaveHandler 新建或更新项目。免费版最多 1 个项目。
func projectSaveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req projectSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目名称不能为空"})
		return
	}

	projectMu.Lock()
	defer projectMu.Unlock()

	store, err := loadProjects()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目读取失败"})
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	if id := strings.TrimSpace(req.ID); id != "" {
		idx := -1
		for i := range store.Items {
			if store.Items[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目不存在"})
			return
		}
		store.Items[idx].Name = name
		store.Items[idx].Description = strings.TrimSpace(req.Description)
		store.Items[idx].LegacyAssetIDs = nil
		store.Items[idx].LegacyTargets = nil
		store.Items[idx].Defaults = req.Defaults
		store.Items[idx].UpdatedAt = now
		if err := saveProjects(store); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目保存失败"})
			return
		}
		res, err := saveProjectTargets(id, req.TargetsText)
		if err != nil {
			gologger.Warning().Msgf("save project %s targets failed: %v", id, err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入项目目标失败"})
			return
		}
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已保存", Data: projectSaveResponse{
			Project: toProjectView(store.Items[idx], 0),
			Added:   res.Added, Existing: res.Existing, Invalid: res.Invalid,
		}})
		return
	}

	if curatedRole() != "curated" && len(store.Items) >= freeProjectLimit {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "免费版仅支持 1 个项目，升级 Curated 可创建多个",
		})
		return
	}

	p := Project{
		ID:          "p_" + utils.CreateRandomString(12),
		Name:        name,
		Description: strings.TrimSpace(req.Description),
		Defaults:    req.Defaults,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	store.Items = append(store.Items, p)
	if err := saveProjects(store); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目保存失败"})
		return
	}
	res, err := saveProjectTargets(p.ID, req.TargetsText)
	if err != nil {
		gologger.Warning().Msgf("save project %s targets failed: %v", p.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入项目目标失败"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已创建", Data: projectSaveResponse{
		Project: toProjectView(p, 0),
		Added:   res.Added, Existing: res.Existing, Invalid: res.Invalid,
	}})
}

// projectDeleteHandler 删除项目。
func projectDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持DELETE方法"})
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["id"])

	projectMu.Lock()
	defer projectMu.Unlock()

	store, err := loadProjects()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目读取失败"})
		return
	}

	idx := -1
	for i := range store.Items {
		if store.Items[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目不存在"})
		return
	}

	store.Items = append(store.Items[:idx], store.Items[idx+1:]...)
	if err := saveProjects(store); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "项目删除失败"})
		return
	}
	// 顺手清掉成员关系，避免在 project_asset 里留下孤儿行。
	if err := sqlite.DeleteProjectAssets(id); err != nil {
		gologger.Warning().Msgf("delete project %s assets failed: %v", id, err)
	}
	// 任务归属同理：留着的话，台账里这些命中会继续挂着一个已删除的 project_id，
	// 界面只能显示裸 ID，按项目筛选也仍会命中它们。
	if _, err := sqlite.UnlinkProjectTasks(id); err != nil {
		gologger.Warning().Msgf("delete project %s task links failed: %v", id, err)
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已删除"})
}
