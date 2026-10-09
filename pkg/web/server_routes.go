package web

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// setupHandler 构建并返回主 HTTP 路由
func setupHandler() (http.Handler, error) {
	// 主路由
	r := mux.NewRouter()

	// 全局中间件（安全与访问日志）
	r.Use(secureHeadersMiddleware)
	// r.Use(loggingMiddleware)

	// -----------------------
	// API 子路由（严格分离）
	// -----------------------
	api := r.PathPrefix("/api").Subrouter()
	api.Use(apiMiddleware)
	api.StrictSlash(true)

	registerAPIRoutes(api)
	api.NotFoundHandler = http.HandlerFunc(apiNotFoundHandler)

	// -----------------------
	// 兼容路由（无 /api 前缀）
	//
	// 旧版前端（当前嵌在 webpath 里的构建）只调用根路径接口，因此这组别名
	// 必须保留。但其中 /reports、/pocs、/projects、/ledger 与新前端的页面
	// 路由同名，且新前端只走 /api/*；两条规则路径完全一致，只能靠请求特征
	// 区分，见 legacyAPIRoute。
	//
	// 注意：定位了冲突的 4 条之外，其余别名与页面不重名，不需要这一层判定，
	// 这样直接拿浏览器打开 /me、/server/info 依然能看到 JSON。
	// -----------------------
	r.HandleFunc("/login", loginRateLimitMiddleware(loginHandler)).Methods(http.MethodPost)
	r.HandleFunc("/logout", jwtAuthMiddleware(logoutHandler)).Methods(http.MethodPost)
	r.HandleFunc("/vulns", jwtAuthMiddleware(vulnsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/reports", jwtAuthMiddleware(reportsHandler)).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/reports/detail/{id}", jwtAuthMiddleware(reportsDetailHandler)).Methods(http.MethodGet)
	r.HandleFunc("/reports/poc/{id}", jwtAuthMiddleware(pocDetailHandler)).Methods(http.MethodGet)
	r.HandleFunc("/pocs/stats", jwtAuthMiddleware(pocsStatsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/pocs", jwtAuthMiddleware(pocsListHandler)).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/pocs/yaml/{pocId}", jwtAuthMiddleware(pocsYamlHandler)).Methods(http.MethodGet)
	r.HandleFunc("/pocs/create", jwtAuthMiddleware(pocsCreateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/pocs/update/{id}", jwtAuthMiddleware(pocsUpdateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/pocs/{id}", jwtAuthMiddleware(pocsDeleteHandler)).Methods(http.MethodDelete)

	r.HandleFunc("/scans", jwtAuthMiddleware(scansCreateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/scans/{taskId}/events", jwtAuthMiddleware(scanEventsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/scans/{taskId}/status", jwtAuthMiddleware(scanStatusHandler)).Methods(http.MethodGet)
	// 目标清单按需下发：列表接口不带全量目标（否则轮询响应会到 MB 级），
	// 只有「重跑」这类要复用目标的动作才来取一次。
	r.HandleFunc("/scans/{taskId}/targets", jwtAuthMiddleware(scanTargetsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/scans/{taskId}/pause", jwtAuthMiddleware(scanPauseHandler)).Methods(http.MethodPost)
	r.HandleFunc("/scans/{taskId}/resume", jwtAuthMiddleware(scanResumeHandler)).Methods(http.MethodPost)
	r.HandleFunc("/scans/{taskId}/stop", jwtAuthMiddleware(scanStopHandler)).Methods(http.MethodPost)
	r.HandleFunc("/scans/{taskId}/diff", jwtAuthMiddleware(requireCurated(scanDiffHandler))).Methods(http.MethodGet)
	// 资产发现明细（端口 / Web 探测）：历史任务回看 + 手动加入资产
	r.HandleFunc("/scans/{taskId}/probes", jwtAuthMiddleware(scanProbesListHandler)).Methods(http.MethodGet)
	r.HandleFunc("/scans/{taskId}/probes/promote", jwtAuthMiddleware(scanProbesPromoteHandler)).Methods(http.MethodPost)

	// 计划扫描（Curated 会员）：定时/周期性地重跑同一份扫描配置。
	// 与 /reports 等同理：/schedules 也是新前端的页面路由，浏览器导航必须落到 SPA。
	r.HandleFunc("/schedules", jwtAuthMiddleware(requireCurated(schedulesListHandler))).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/schedules", jwtAuthMiddleware(requireCurated(schedulesSaveHandler))).Methods(http.MethodPost)
	r.HandleFunc("/schedules/{id}", jwtAuthMiddleware(requireCurated(schedulesDeleteHandler))).Methods(http.MethodDelete)
	r.HandleFunc("/schedules/{id}/toggle", jwtAuthMiddleware(requireCurated(schedulesToggleHandler))).Methods(http.MethodPost)
	r.HandleFunc("/schedules/{id}/run", jwtAuthMiddleware(requireCurated(schedulesRunHandler))).Methods(http.MethodPost)

	r.HandleFunc("/exports/task/{taskId}", jwtAuthMiddleware(exportTaskHandler)).Methods(http.MethodGet)
	r.HandleFunc("/exports/reports", jwtAuthMiddleware(exportReportsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/exports/project/{projectId}", jwtAuthMiddleware(exportProjectHandler)).Methods(http.MethodGet)

	r.HandleFunc("/me", jwtAuthMiddleware(meHandler)).Methods(http.MethodGet)
	r.HandleFunc("/nav/badges", jwtAuthMiddleware(navBadgesHandler)).Methods(http.MethodGet)
	r.HandleFunc("/curated/status", jwtAuthMiddleware(curatedStatusHandler)).Methods(http.MethodGet)
	r.HandleFunc("/curated/activate", jwtAuthMiddleware(curatedActivateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/curated/update", jwtAuthMiddleware(requireCurated(curatedUpdateHandler))).Methods(http.MethodPost)
	// curated/config 刻意不加 requireCurated：未激活（甚至未启用）时也必须能编辑这一段，
	// 否则"要填 endpoint 才能启用、没启用就不能编辑"会形成死锁。
	r.HandleFunc("/curated/config", jwtAuthMiddleware(curatedConfigGetHandler)).Methods(http.MethodGet)
	r.HandleFunc("/curated/config", jwtAuthMiddleware(curatedConfigPutHandler)).Methods(http.MethodPut)
	r.HandleFunc("/ledger", jwtAuthMiddleware(requireCurated(ledgerListHandler))).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/ledger/status", jwtAuthMiddleware(requireCurated(ledgerUpdateHandler))).Methods(http.MethodPost)
	r.HandleFunc("/projects", jwtAuthMiddleware(projectsListHandler)).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/projects", jwtAuthMiddleware(projectSaveHandler)).MatcherFunc(legacyAPIRoute).Methods(http.MethodPost)
	r.HandleFunc("/projects/{id}", jwtAuthMiddleware(projectGetHandler)).Methods(http.MethodGet)
	r.HandleFunc("/projects/{id}", jwtAuthMiddleware(projectDeleteHandler)).Methods(http.MethodDelete)
	r.HandleFunc("/notifications", jwtAuthMiddleware(requireCurated(notificationsGetHandler))).Methods(http.MethodGet)
	r.HandleFunc("/notifications", jwtAuthMiddleware(requireCurated(notificationsSaveHandler))).Methods(http.MethodPut)
	r.HandleFunc("/notifications/test", jwtAuthMiddleware(requireCurated(notificationsTestHandler))).Methods(http.MethodPost)
	r.HandleFunc("/notifications/logs", jwtAuthMiddleware(requireCurated(notificationsLogsHandler))).Methods(http.MethodGet)
	r.HandleFunc("/notifications/logs/resend", jwtAuthMiddleware(requireCurated(notificationsResendHandler))).Methods(http.MethodPost)
	r.HandleFunc("/server/info", jwtAuthMiddleware(serverInfoHandler)).Methods(http.MethodGet)
	r.HandleFunc("/instances", jwtAuthMiddleware(instancesListHandler)).Methods(http.MethodGet)
	r.HandleFunc("/instances/{instanceId}/force-stop", jwtAuthMiddleware(instanceForceStopHandler)).Methods(http.MethodPost)

	// 资产（目标唯一真源）：项目 / 扫描 / 计划任务都只引用资产，不再各自存一份目标。
	// /assets 同样是新前端的页面路由，浏览器导航必须落到 SPA。
	r.HandleFunc("/assets", jwtAuthMiddleware(assetsListHandler)).MatcherFunc(legacyAPIRoute).Methods(http.MethodGet)
	r.HandleFunc("/assets", jwtAuthMiddleware(assetsCreateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/assets/facets", jwtAuthMiddleware(assetsFacetsHandler)).Methods(http.MethodGet)
	r.HandleFunc("/assets/update", jwtAuthMiddleware(assetsUpdateHandler)).Methods(http.MethodPost)
	r.HandleFunc("/assets/delete", jwtAuthMiddleware(assetsDeleteHandler)).Methods(http.MethodPost)

	// -----------------------
	// 静态网站（SvelteKit 打包内容）
	// -----------------------
	buildRoot, err := fs.Sub(GetWebpathFS(), "webpath")
	if err != nil {
		return nil, fmt.Errorf("unable to load embedded web assets: %w", err)
	}

	indexPath := GetWebpathIndexPath()
	if _, statErr := fs.Stat(buildRoot, indexPath); statErr != nil {
		if _, placeholderErr := fs.Stat(buildRoot, "placeholder.html"); placeholderErr == nil {
			indexPath = "placeholder.html"
		}
	}
	spa := newSPAHandler(buildRoot, indexPath)

	// 常见特殊文件（可选，直出便于日志与缓存控制）
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		serveStaticFile(w, r, buildRoot, "favicon.ico")
	})
	r.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		serveStaticFile(w, r, buildRoot, "robots.txt")
	})
	r.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		serveStaticFile(w, r, buildRoot, "manifest.json")
	})

	// Catch-all 静态处理（放在 /api 之后，确保优先匹配 API）
	// 说明：PathPrefix("/") 会匹配所有非 /api/* 的请求；若 /api 子路由已匹配，则不会降级到此处。
	r.PathPrefix("/").Handler(spa)

	return r, nil
}

// -----------------------
// API 注册与中间件
// -----------------------

// legacyAPIRoute 只放行「程序调用」而把「浏览器导航」留给 SPA。
//
// 旧版前端的接口路径与新前端的页面路径存在同名冲突（/reports、/pocs、
// /projects、/ledger）。浏览器在地址栏访问或刷新页面时必定带
// Accept: text/html，而 XHR / fetch / 脚本工具默认是 */*，据此可以稳定区分：
//   - 浏览器导航 -> 本匹配器返回 false，请求继续落到 SPA，拿到页面
//   - 旧前端 XHR -> 命中根路径别名，仍返回 JSON
func legacyAPIRoute(r *http.Request, _ *mux.RouteMatch) bool {
	return !strings.Contains(r.Header.Get("Accept"), "text/html")
}

// 仅用于 /api/* 的中间件：统一设置 JSON 响应头、校验 Content-Type
func apiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API 响应统一 JSON + 不缓存
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")

		// 仅对写操作校验 Content-Type
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"message": "Content-Type必须为application/json",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// API 路由集中注册，避免与静态路由混淆
func registerAPIRoutes(api *mux.Router) {
	api.HandleFunc("/health", healthCheckHandler).Methods(http.MethodGet)

	// 认证与业务 API（复用现有处理器）
	api.HandleFunc("/login", loginRateLimitMiddleware(loginHandler)).Methods(http.MethodPost)
	api.HandleFunc("/logout", jwtAuthMiddleware(logoutHandler)).Methods(http.MethodPost)
	api.HandleFunc("/vulns", jwtAuthMiddleware(vulnsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/reports", jwtAuthMiddleware(reportsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/reports/detail/{id}", jwtAuthMiddleware(reportsDetailHandler)).Methods(http.MethodGet)
	api.HandleFunc("/reports/poc/{id}", jwtAuthMiddleware(pocDetailHandler)).Methods(http.MethodGet)
	api.HandleFunc("/pocs/stats", jwtAuthMiddleware(pocsStatsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/pocs", jwtAuthMiddleware(pocsListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/pocs/yaml/{pocId}", jwtAuthMiddleware(pocsYamlHandler)).Methods(http.MethodGet)
	// 漏洞库详情：单个 PoC 的完整元信息（含 description/reference/affected/solutions/CVE 等）
	api.HandleFunc("/pocs/detail/{pocId}", jwtAuthMiddleware(pocsDetailHandler)).Methods(http.MethodGet)
	// 编辑器校验：校验一段 YAML 并回传解析后的 info（实时预览用），不落盘
	api.HandleFunc("/pocs/validate", jwtAuthMiddleware(pocsValidateHandler)).Methods(http.MethodPost)
	// 新增：创建 POC
	api.HandleFunc("/pocs/create", jwtAuthMiddleware(pocsCreateHandler)).Methods(http.MethodPost)
	// 新增：更新指定 POC 的 YAML 内容（当前使用 POST）
	api.HandleFunc("/pocs/update/{id}", jwtAuthMiddleware(pocsUpdateHandler)).Methods(http.MethodPost)
	// 新增：删除指定 POC（仅允许删除 my 源）
	api.HandleFunc("/pocs/{id}", jwtAuthMiddleware(pocsDeleteHandler)).Methods(http.MethodDelete)

	api.HandleFunc("/scans", jwtAuthMiddleware(scansCreateHandler)).Methods(http.MethodPost)
	// 任务列表：让「不是本页面发起」的扫描（计划扫描）也能在前端可见。
	api.HandleFunc("/scans", jwtAuthMiddleware(scansListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/scans/{taskId}/events", jwtAuthMiddleware(scanEventsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/scans/{taskId}/status", jwtAuthMiddleware(scanStatusHandler)).Methods(http.MethodGet)
	// 目标清单按需下发：列表接口不带全量目标（否则轮询响应会到 MB 级），
	// 只有「重跑」这类要复用目标的动作才来取一次。
	api.HandleFunc("/scans/{taskId}/targets", jwtAuthMiddleware(scanTargetsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/scans/{taskId}/pause", jwtAuthMiddleware(scanPauseHandler)).Methods(http.MethodPost)
	api.HandleFunc("/scans/{taskId}/resume", jwtAuthMiddleware(scanResumeHandler)).Methods(http.MethodPost)
	api.HandleFunc("/scans/{taskId}/stop", jwtAuthMiddleware(scanStopHandler)).Methods(http.MethodPost)
	api.HandleFunc("/scans/{taskId}/diff", jwtAuthMiddleware(requireCurated(scanDiffHandler))).Methods(http.MethodGet)
	// 资产发现明细（端口 / Web 探测）：历史任务回看 + 手动加入资产
	api.HandleFunc("/scans/{taskId}/probes", jwtAuthMiddleware(scanProbesListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/scans/{taskId}/probes/promote", jwtAuthMiddleware(scanProbesPromoteHandler)).Methods(http.MethodPost)

	// 计划扫描（Curated 会员）
	api.HandleFunc("/schedules", jwtAuthMiddleware(requireCurated(schedulesListHandler))).Methods(http.MethodGet)
	api.HandleFunc("/schedules", jwtAuthMiddleware(requireCurated(schedulesSaveHandler))).Methods(http.MethodPost)
	api.HandleFunc("/schedules/{id}", jwtAuthMiddleware(requireCurated(schedulesDeleteHandler))).Methods(http.MethodDelete)
	api.HandleFunc("/schedules/{id}/toggle", jwtAuthMiddleware(requireCurated(schedulesToggleHandler))).Methods(http.MethodPost)
	api.HandleFunc("/schedules/{id}/run", jwtAuthMiddleware(requireCurated(schedulesRunHandler))).Methods(http.MethodPost)

	api.HandleFunc("/exports/task/{taskId}", jwtAuthMiddleware(exportTaskHandler)).Methods(http.MethodGet)
	api.HandleFunc("/exports/reports", jwtAuthMiddleware(exportReportsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/exports/project/{projectId}", jwtAuthMiddleware(exportProjectHandler)).Methods(http.MethodGet)

	api.HandleFunc("/me", jwtAuthMiddleware(meHandler)).Methods(http.MethodGet)
	api.HandleFunc("/nav/badges", jwtAuthMiddleware(navBadgesHandler)).Methods(http.MethodGet)
	api.HandleFunc("/curated/status", jwtAuthMiddleware(curatedStatusHandler)).Methods(http.MethodGet)
	api.HandleFunc("/curated/activate", jwtAuthMiddleware(curatedActivateHandler)).Methods(http.MethodPost)
	api.HandleFunc("/curated/update", jwtAuthMiddleware(requireCurated(curatedUpdateHandler))).Methods(http.MethodPost)
	api.HandleFunc("/curated/config", jwtAuthMiddleware(curatedConfigGetHandler)).Methods(http.MethodGet)
	api.HandleFunc("/curated/config", jwtAuthMiddleware(curatedConfigPutHandler)).Methods(http.MethodPut)
	api.HandleFunc("/ledger", jwtAuthMiddleware(requireCurated(ledgerListHandler))).Methods(http.MethodGet)
	api.HandleFunc("/ledger/status", jwtAuthMiddleware(requireCurated(ledgerUpdateHandler))).Methods(http.MethodPost)
	api.HandleFunc("/projects", jwtAuthMiddleware(projectsListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/projects", jwtAuthMiddleware(projectSaveHandler)).Methods(http.MethodPost)
	api.HandleFunc("/projects/{id}", jwtAuthMiddleware(projectGetHandler)).Methods(http.MethodGet)
	api.HandleFunc("/projects/{id}", jwtAuthMiddleware(projectDeleteHandler)).Methods(http.MethodDelete)
	api.HandleFunc("/notifications", jwtAuthMiddleware(requireCurated(notificationsGetHandler))).Methods(http.MethodGet)
	api.HandleFunc("/notifications", jwtAuthMiddleware(requireCurated(notificationsSaveHandler))).Methods(http.MethodPut)
	api.HandleFunc("/notifications/test", jwtAuthMiddleware(requireCurated(notificationsTestHandler))).Methods(http.MethodPost)
	api.HandleFunc("/notifications/logs", jwtAuthMiddleware(requireCurated(notificationsLogsHandler))).Methods(http.MethodGet)
	api.HandleFunc("/notifications/logs/resend", jwtAuthMiddleware(requireCurated(notificationsResendHandler))).Methods(http.MethodPost)
	// 多实例编排：/cluster/self 供同伴实例互访（走集群共享密钥，不走 JWT），
	// /cluster/instances 是控制台自己的聚合视图，/cluster/config 用来在运行时
	// 增删节点（会员能力，保存后写回 afrog-config.yaml 并立即生效）。
	api.HandleFunc("/cluster/self", clusterSelfHandler).Methods(http.MethodGet)
	// 远程派发（执行节点一侧）：同样只认集群共享密钥，不认 Web 登录态。
	// dispatch 幂等；tasks/{id} 供发起端对账；findings 供发起端只读代理。
	api.HandleFunc("/cluster/inbound/dispatch", clusterInboundDispatchHandler).Methods(http.MethodPost)
	api.HandleFunc("/cluster/inbound/tasks/{taskId}", clusterInboundTaskStatusHandler).Methods(http.MethodGet)
	api.HandleFunc("/cluster/inbound/tasks/{taskId}/stop", clusterInboundTaskStopHandler).Methods(http.MethodPost)
	api.HandleFunc("/cluster/inbound/tasks/{taskId}/findings", clusterInboundTaskFindingsHandler).Methods(http.MethodGet)
	api.HandleFunc("/cluster/inbound/tasks/{taskId}/results", clusterInboundTaskResultsHandler).Methods(http.MethodGet)
	api.HandleFunc("/cluster/instances", jwtAuthMiddleware(clusterInstancesHandler)).Methods(http.MethodGet)
	api.HandleFunc("/cluster/config", jwtAuthMiddleware(requireCurated(clusterConfigGetHandler))).Methods(http.MethodGet)
	api.HandleFunc("/cluster/config", jwtAuthMiddleware(requireCurated(clusterConfigPutHandler))).Methods(http.MethodPut)
	// 远程派发（发起端一侧）：会员能力，派发/查看/停止/只读代理命中。
	api.HandleFunc("/cluster/dispatch", jwtAuthMiddleware(requireCurated(clusterRemoteDispatchHandler))).Methods(http.MethodPost)
	api.HandleFunc("/cluster/remote-tasks", jwtAuthMiddleware(requireCurated(clusterRemoteTaskListHandler))).Methods(http.MethodGet)
	api.HandleFunc("/cluster/remote-tasks/{taskId}", jwtAuthMiddleware(requireCurated(clusterRemoteTaskHandler))).Methods(http.MethodGet)
	api.HandleFunc("/cluster/remote-tasks/{taskId}", jwtAuthMiddleware(requireCurated(clusterRemoteTaskDeleteHandler))).Methods(http.MethodDelete)
	api.HandleFunc("/cluster/remote-tasks/{taskId}/stop", jwtAuthMiddleware(requireCurated(clusterRemoteTaskStopHandler))).Methods(http.MethodPost)
	api.HandleFunc("/cluster/remote-tasks/{taskId}/findings", jwtAuthMiddleware(requireCurated(clusterRemoteTaskFindingsHandler))).Methods(http.MethodGet)

	// AI 辅助（v1：命中研判）：/ai/status 告诉界面能不能用、本月还剩几次试用；
	// /ai/config 读写模型接入配置（写回 afrog-config.yaml，保存即生效）；
	// /ai/verdict 用 SSE 流式返回单条命中的研判结果（额度在服务端校验）。
	api.HandleFunc("/ai/status", jwtAuthMiddleware(aiStatusHandler)).Methods(http.MethodGet)
	api.HandleFunc("/ai/config", jwtAuthMiddleware(aiConfigGetHandler)).Methods(http.MethodGet)
	api.HandleFunc("/ai/config", jwtAuthMiddleware(aiConfigPutHandler)).Methods(http.MethodPut)
	api.HandleFunc("/ai/verdict", jwtAuthMiddleware(aiVerdictHandler)).Methods(http.MethodGet)
	api.HandleFunc("/ai/summary", jwtAuthMiddleware(aiSummaryHandler)).Methods(http.MethodGet)
	// /ai/recommend 依据「目标画像」（规模、类型分布、样例）推荐扫描参数，
	// 流式返回理由，并额外下发一个 params 事件供界面一键应用。
	api.HandleFunc("/ai/recommend", jwtAuthMiddleware(aiRecommendHandler)).Methods(http.MethodGet)

	// OOB（带外检测）凭据：读写 afrog-config.yaml 的 reverse 段。
	// 保存后写回配置文件，Web 执行器下次起扫描子进程时生效。
	api.HandleFunc("/oob/config", jwtAuthMiddleware(oobConfigGetHandler)).Methods(http.MethodGet)
	api.HandleFunc("/oob/config", jwtAuthMiddleware(oobConfigPutHandler)).Methods(http.MethodPut)

	api.HandleFunc("/server/info", jwtAuthMiddleware(serverInfoHandler)).Methods(http.MethodGet)
	api.HandleFunc("/instances", jwtAuthMiddleware(instancesListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/instances/{instanceId}/force-stop", jwtAuthMiddleware(instanceForceStopHandler)).Methods(http.MethodPost)

	api.HandleFunc("/assets", jwtAuthMiddleware(assetsListHandler)).Methods(http.MethodGet)
	api.HandleFunc("/assets", jwtAuthMiddleware(assetsCreateHandler)).Methods(http.MethodPost)
	api.HandleFunc("/assets/facets", jwtAuthMiddleware(assetsFacetsHandler)).Methods(http.MethodGet)
	api.HandleFunc("/assets/update", jwtAuthMiddleware(assetsUpdateHandler)).Methods(http.MethodPost)
	api.HandleFunc("/assets/delete", jwtAuthMiddleware(assetsDeleteHandler)).Methods(http.MethodPost)
}

// API 未匹配路由 -> JSON 404
func apiNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"message": "API endpoint not found",
		"path":    r.URL.Path,
		"method":  r.Method,
	})
}

// 健康检查（API）
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"afrog-web"}`))
}

// -----------------------
// 静态网站（SvelteKit）
// -----------------------

type spaHandler struct {
	staticFS  fs.FS
	indexPath string
}

func newSPAHandler(staticFS fs.FS, indexPath string) http.Handler {
	return &spaHandler{staticFS: staticFS, indexPath: indexPath}
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 安全兜底：若误落入静态处理但路径是 /api/*，仍返回 JSON 404，避免混淆
	if strings.HasPrefix(r.URL.Path, "/api/") {
		apiNotFoundHandler(w, r)
		return
	}

	// 去除前导斜线
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	// 调整：SvelteKit __data.json 专用处理
	// 存在文件 -> 按 JSON 返回；不存在 -> 返回 200 空数据 JSON，避免触发页面 404
	if strings.Contains(path, "__data.json") {
		if file, err := h.staticFS.Open(path); err == nil {
			defer file.Close()
			if stat, err2 := file.Stat(); err2 == nil && !stat.IsDir() {
				if rs, ok := file.(io.ReadSeeker); ok {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					http.ServeContent(w, r, path, stat.ModTime(), rs)
					return
				}
			}
		}
		// 返回最小合法数据，保证客户端路由/无效化流程正常
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "data",
			"nodes": []any{}, // 空节点，表示无可更新数据
		})
		return
	}

	// 尝试真实文件
	if file, err := h.staticFS.Open(path); err == nil {
		defer file.Close()

		if stat, err := file.Stat(); err == nil && !stat.IsDir() {
			if rs, ok := file.(io.ReadSeeker); ok {
				// 差异化缓存策略
				setStaticCacheHeaders(w, path)
				http.ServeContent(w, r, path, stat.ModTime(), rs)
				return
			}
		}
	}

	// 未找到文件或为目录 -> 对于 .js 请求返回 404，而不是 fallback 到 index.html
	if strings.HasSuffix(path, ".js") {
		http.NotFound(w, r)
		return
	}
	// 其他情况 fallback 到 index.html（支持前端路由）
	h.serveIndex(w, r)
}

func (h *spaHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	indexFile, err := h.staticFS.Open(h.indexPath)
	if err != nil {
		http.Error(w, "Index file not found", http.StatusNotFound)
		return
	}
	defer indexFile.Close()

	stat, err := indexFile.Stat()
	if err != nil {
		http.Error(w, "Unable to stat index file", http.StatusInternalServerError)
		return
	}
	rs, ok := indexFile.(io.ReadSeeker)
	if !ok {
		http.Error(w, "Index file does not support seeking", http.StatusInternalServerError)
		return
	}

	// HTML 不缓存，确保前端路由更新
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	http.ServeContent(w, r, h.indexPath, stat.ModTime(), rs)
}

// 按后缀设置缓存策略（SvelteKit 打包文件名带 hash，可使用 immutable）
func setStaticCacheHeaders(w http.ResponseWriter, path string) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".html":
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	case ".js", ".css":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case ".woff", ".woff2", ".ttf", ".eot":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
}

// serveStaticFile 直接按文件名服务静态文件（用于 favicon/robots 等）
// 自动带上缓存策略
func serveStaticFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, filename string) {
	f, err := fsys.Open(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Unable to stat file", http.StatusInternalServerError)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "File does not support seeking", http.StatusInternalServerError)
		return
	}

	setStaticCacheHeaders(w, filename)
	http.ServeContent(w, r, filename, stat.ModTime(), rs)
}

// -----------------------
// 通用中间件
// -----------------------

// 访问日志（与 API/静态无关，单独保留）
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("Request: %s %s - Duration: %v", r.Method, r.URL.Path, time.Since(start))
	})
}
