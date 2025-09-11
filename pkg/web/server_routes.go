package web

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
)

func setupHandler() (http.Handler, error) {

	mux := http.NewServeMux()

	// API 路由（全部返回JSON）- 确保这些路由优先匹配
	mux.HandleFunc("/api/login", loginRateLimitMiddleware(loginHandler))
	mux.HandleFunc("/api/logout", jwtAuthMiddleware(logoutHandler))
	mux.HandleFunc("/api/vulns", jwtAuthMiddleware(vulnsHandler))
	mux.HandleFunc("/api/reports", jwtAuthMiddleware(reportsHandler))
	// 报告详情接口
	mux.HandleFunc("/api/reports/", jwtAuthMiddleware(reportsDetailHandler))

	// 新增：POC YAML源码接口
	mux.HandleFunc("/api/reports/poc/", jwtAuthMiddleware(pocDetailHandler))
	mux.HandleFunc("/api/pocs/stats", jwtAuthMiddleware(pocsStatsHandler))

	// 从 embed.go 中的 buildFS 截取到 build 目录作为根
	buildRoot, err := fs.Sub(buildFS, "build")
	if err != nil {
		return nil, fmt.Errorf("无法加载静态文件: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(buildRoot)))

	// 为所有路由增加全局安全响应头
	return secureHeadersMiddleware(loggingMiddleware(mux)), nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// spaHandler 处理SPA路由，对于不存在的路径返回index.html
// type spaHandler struct {
// 	staticFS  fs.FS
// 	indexPath string
// }

// func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	// 清理路径
// 	path := filepath.Clean(r.URL.Path)
// 	if path == "/" {
// 		path = "index.html"
// 	} else {
// 		path = strings.TrimPrefix(path, "/")
// 	}

// 	// 尝试打开文件
// 	file, err := h.staticFS.Open(path)
// 	if err != nil {
// 		// 如果文件不存在且不是API路径，返回index.html让前端路由处理
// 		if !strings.HasPrefix(r.URL.Path, "/api/") {
// 			h.serveIndex(w, r)
// 			return
// 		}
// 		http.NotFound(w, r)
// 		return
// 	}
// 	defer file.Close()

// 	// 检查是否为目录
// 	stat, err := file.Stat()
// 	if err != nil {
// 		http.Error(w, "Unable to stat file", http.StatusInternalServerError)
// 		return
// 	}

// 	// 如果是目录，返回index.html让前端路由处理
// 	if stat.IsDir() {
// 		h.serveIndex(w, r)
// 		return
// 	}

// 	// 确保文件实现了io.ReadSeeker接口
// 	readSeeker, ok := file.(io.ReadSeeker)
// 	if !ok {
// 		http.Error(w, "File does not support seeking", http.StatusInternalServerError)
// 		return
// 	}

// 	// 使用标准的文件服务器处理
// 	http.ServeContent(w, r, path, stat.ModTime(), readSeeker)
// }

// // serveIndex 提供index.html文件
// func (h *spaHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
// 	indexFile, err := h.staticFS.Open(h.indexPath)
// 	if err != nil {
// 		http.Error(w, "Index file not found", http.StatusNotFound)
// 		return
// 	}
// 	defer indexFile.Close()

// 	stat, err := indexFile.Stat()
// 	if err != nil {
// 		http.Error(w, "Unable to stat index file", http.StatusInternalServerError)
// 		return
// 	}

// 	readSeeker, ok := indexFile.(io.ReadSeeker)
// 	if !ok {
// 		http.Error(w, "Index file does not support seeking", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	http.ServeContent(w, r, h.indexPath, stat.ModTime(), readSeeker)
// }
