package web

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

func setupHandler() (http.Handler, error) {
	mux := http.NewServeMux()

	// API 路由组 - 使用子路由器确保精确匹配
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/login", loginRateLimitMiddleware(loginHandler))
	apiMux.HandleFunc("/logout", jwtAuthMiddleware(logoutHandler))
	apiMux.HandleFunc("/vulns", jwtAuthMiddleware(vulnsHandler))
	apiMux.HandleFunc("/reports", jwtAuthMiddleware(reportsHandler))
	apiMux.HandleFunc("/reports/detail/", jwtAuthMiddleware(reportsDetailHandler)) // 修改路径避免冲突
	apiMux.HandleFunc("/reports/poc/", jwtAuthMiddleware(pocDetailHandler))
	apiMux.HandleFunc("/pocs/stats", jwtAuthMiddleware(pocsStatsHandler))
	apiMux.HandleFunc("/health", healthCheckHandler)

	// 将 API 路由挂载到 /api/ 下，并应用 API 专用中间件
	mux.Handle("/api/", http.StripPrefix("/api", apiMiddleware(apiMux)))

	// 静态文件和 SPA 处理
	buildRoot, err := fs.Sub(buildFS, "build")
	if err != nil {
		return nil, fmt.Errorf("无法加载静态文件: %v", err)
	}

	// 使用优化的 SPA Handler
	spaHandler := &spaHandler{
		staticFS:  buildRoot,
		indexPath: "index.html",
	}
	mux.Handle("/", spaHandler)

	return secureHeadersMiddleware(mux), nil
	// return secureHeadersMiddleware(loggingMiddleware(mux)), nil
}

// API 专用中间件
func apiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 确保 API 响应始终为 JSON
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}

// 健康检查处理器
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"afrog-web"}`))
}

// 优化的 SPA Handler
type spaHandler struct {
	staticFS  fs.FS
	indexPath string
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 如果是 API 请求，直接返回 404（不应该到达这里）
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	// 临时解决方案：根路径重定向到 reports.html
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/reports.html", http.StatusTemporaryRedirect)
		return
	}

	// 清理路径
	path := filepath.Clean(r.URL.Path)
	if path == "/" {
		path = "index.html"
	} else {
		path = strings.TrimPrefix(path, "/")
	}

	// 尝试打开文件
	file, err := h.staticFS.Open(path)
	if err != nil {
		// 文件不存在，检查是否为前端路由
		if h.isFrontendRoute(r.URL.Path) {
			h.serveIndex(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	// 检查是否为目录
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Unable to stat file", http.StatusInternalServerError)
		return
	}

	// 如果是目录，返回 index.html 让前端路由处理
	if stat.IsDir() {
		h.serveIndex(w, r)
		return
	}

	// 设置缓存策略
	h.setCacheHeaders(w, path)

	// 确保文件实现了 io.ReadSeeker 接口
	readSeeker, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(w, "File does not support seeking", http.StatusInternalServerError)
		return
	}

	// 使用标准的文件服务器处理
	http.ServeContent(w, r, path, stat.ModTime(), readSeeker)
}

// 判断是否为前端路由
func (h *spaHandler) isFrontendRoute(path string) bool {
	// SvelteKit 的前端路由路径
	frontendRoutes := []string{"/login", "/reports", "/pocs", "/docs"}
	for _, route := range frontendRoutes {
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

// 设置差异化缓存策略
func (h *spaHandler) setCacheHeaders(w http.ResponseWriter, path string) {
	ext := filepath.Ext(path)
	switch ext {
	case ".html":
		// HTML 文件不缓存，确保路由更新
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	case ".js", ".css":
		// JS/CSS 文件长期缓存（SvelteKit 会生成带 hash 的文件名）
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
		// 图片资源长期缓存
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case ".woff", ".woff2", ".ttf", ".eot":
		// 字体文件长期缓存
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	default:
		// 其他文件短期缓存
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
}

// serveIndex 提供 index.html 文件
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

	readSeeker, ok := indexFile.(io.ReadSeeker)
	if !ok {
		http.Error(w, "Index file does not support seeking", http.StatusInternalServerError)
		return
	}

	// HTML 不缓存
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeContent(w, r, h.indexPath, stat.ModTime(), readSeeker)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
