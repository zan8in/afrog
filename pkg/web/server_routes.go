package web

import (
	"fmt"
	"io/fs"
	"net/http"
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

	// 静态文件服务（包含 _app 目录、index.html 等）
	// 创建带MIME类型检测的文件服务器
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置MIME类型
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "text/javascript")
		} else if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}
		http.FileServer(http.FS(buildRoot)).ServeHTTP(w, r)
	})

	// 通配符路由（最后声明）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 尝试访问嵌入式文件
		if _, err := buildRoot.Open(strings.TrimPrefix(r.URL.Path, "/")); err == nil {
			staticHandler.ServeHTTP(w, r)
			return
		}
		// 返回嵌入式index.html
		fileContent, _ := fs.ReadFile(buildRoot, "index.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(fileContent)
	})

	// 为所有路由增加全局安全响应头
	return secureHeadersMiddleware(mux), nil
}
