package web

import (
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func setupHandler() (http.Handler, error) {
	// 从 embed.go 中的 buildFS 截取到 build 目录作为根
	buildRoot, err := fs.Sub(buildFS, "build")
	if err != nil {
		return nil, fmt.Errorf("无法加载静态文件: %v", err)
	}

	mux := http.NewServeMux()

	// API 路由（全部返回JSON）
	mux.HandleFunc("/api/login", loginRateLimitMiddleware(loginHandler))
	mux.HandleFunc("/api/logout", jwtAuthMiddleware(logoutHandler))
	mux.HandleFunc("/api/vulns", jwtAuthMiddleware(vulnsHandler))
	mux.HandleFunc("/api/reports", jwtAuthMiddleware(reportsHandler))
	// 报告详情接口
	mux.HandleFunc("/api/reports/", jwtAuthMiddleware(reportsDetailHandler))

	// 新增：POC YAML源码接口
	mux.HandleFunc("/api/reports/poc/", jwtAuthMiddleware(pocDetailHandler))
	mux.HandleFunc("/api/pocs/stats", jwtAuthMiddleware(pocsStatsHandler))

	staticHandler := http.FileServer(http.FS(buildRoot))
	// 定义需要重定向的路径集合
	var spaPaths = map[string]bool{
		"/login":   true,
		"/reports": true,
		"/docs":    true,
		"/pocs":    true,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 动态路径匹配
		if spaPaths[r.URL.Path] {
			http.Redirect(w, r, "/", http.StatusPermanentRedirect)
			return
		}

		// 原有静态资源处理逻辑
		cleanPath := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if _, err := buildRoot.Open(cleanPath); err == nil {
			staticHandler.ServeHTTP(w, r)
			return
		}

		// SPA回退逻辑
		fileContent, _ := fs.ReadFile(buildRoot, "index.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(fileContent)
	})
	// 为所有路由增加全局安全响应头
	return secureHeadersMiddleware(mux), nil
}
