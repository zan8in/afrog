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
	// 静态网站（SvelteKit 打包内容）
	// -----------------------
	buildRoot, err := fs.Sub(GetWebpathFS(), "webpath")
	if err != nil {
		return nil, fmt.Errorf("unable to load embedded web assets: %w", err)
	}

	spa := newSPAHandler(buildRoot, GetWebpathIndexPath())

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
	// 新增：创建 POC
	api.HandleFunc("/pocs/create", jwtAuthMiddleware(pocsCreateHandler)).Methods(http.MethodPost)
	// 新增：更新指定 POC 的 YAML 内容（当前使用 POST）
	api.HandleFunc("/pocs/update/{id}", jwtAuthMiddleware(pocsUpdateHandler)).Methods(http.MethodPost)
	// 新增：删除指定 POC（仅允许删除 my 源）
	api.HandleFunc("/pocs/{id}", jwtAuthMiddleware(pocsDeleteHandler)).Methods(http.MethodDelete)
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

	// 未找到文件或为目录 -> 返回 index.html（支持前端路由）
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
