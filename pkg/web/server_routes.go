package web

import (
	"fmt"
	"io/fs"
	"net/http"
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
	mux.HandleFunc("/api/pocs/stats", jwtAuthMiddleware(pocsStatsHandler))

	// 静态文件服务（包含 _app 目录、index.html 等）
	staticFileServer := http.FileServer(http.FS(buildRoot))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		staticFileServer.ServeHTTP(w, r)
	})

	// 为所有路由增加全局安全响应头
	return secureHeadersMiddleware(mux), nil
}