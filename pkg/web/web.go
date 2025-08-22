package web

import (
	"embed"
	"net/http"
	"text/template"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

//go:embed template/*.html static/*
var temp embed.FS

// 全局变量存储生成的密码和会话
var (
	generatedPassword string
	loggedInSessions  = make(map[string]time.Time)
)

// 生成32位随机密码
func generateRandomPassword() string {
	return utils.CreateRandomString(32)
}

// 验证会话是否有效
func isValidSession(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	expireTime, exists := loggedInSessions[sessionID]
	if !exists {
		return false
	}
	// 会话24小时后过期
	return time.Now().Before(expireTime)
}

// 生成会话ID
func generateSessionID() string {
	return utils.CreateRandomString(16)
}

// 权限验证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 检查会话cookie
		cookie, err := r.Cookie("afrog_session")
		if err != nil || !isValidSession(cookie.Value) {
			// 未登录，重定向到登录页面
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// 已登录，继续处理请求
		next(w, r)
	}
}

func StartServer(addr string) error {
	// 生成随机密码
	generatedPassword = generateRandomPassword()
	gologger.Info().Msgf("Web UI Password: %s", generatedPassword)
	gologger.Info().Msg("Please save this password, it will be required for login.")

	err := sqlite.InitX()
	if err != nil {
		return err
	}

	// 注册路由
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	// 使用认证中间件保护敏感页面
	http.HandleFunc("/vulns", authMiddleware(listHandler))
	http.HandleFunc("/", authMiddleware(indexHandler))

	// 处理静态资源
	http.Handle("/static/", http.FileServer(http.FS(temp)))

	// 启动HTTP服务器并监听端口
	gologger.Info().Msg("Serving HTTP on :: port " + addr[1:] + " (http://[::]" + addr + "/) ...")
	return http.ListenAndServe(addr, nil)
}

// 首页处理器
func indexHandler(w http.ResponseWriter, r *http.Request) {
	// 重定向到漏洞列表页面
	http.Redirect(w, r, "/vulns", http.StatusFound)
}

// 登录处理器
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// 显示登录页面
		tmpl, err := template.ParseFS(temp, "template/Login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == "POST" {
		// 处理登录请求
		password := r.FormValue("password")
		if password == generatedPassword {
			// 密码正确，创建会话
			sessionID := generateSessionID()
			loggedInSessions[sessionID] = time.Now().Add(30 * 24 * time.Hour)

			// 设置会话cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "afrog_session",
				Value:    sessionID,
				Path:     "/",
				MaxAge:   86400 * 30, // 30天
				HttpOnly: true,
			})

			// 重定向到漏洞列表页面
			http.Redirect(w, r, "/vulns", http.StatusFound)
			return
		} else {
			// 密码错误，重新显示登录页面并显示错误信息
			tmpl, err := template.ParseFS(temp, "template/Login.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = tmpl.Execute(w, map[string]string{"Error": "密码错误，请重试"})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
	}
}

// 登出处理器
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 删除会话
	cookie, err := r.Cookie("afrog_session")
	if err == nil {
		delete(loggedInSessions, cookie.Value)
	}

	// 清除cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "afrog_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// 重定向到登录页面
	http.Redirect(w, r, "/login", http.StatusFound)
}

type User struct {
	Password string
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	keyword := r.URL.Query().Get("keyword")
	severity := r.URL.Query().Get("severity")
	page := r.URL.Query().Get("page")

	data, err := sqlite.SelectX(severity, keyword, page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	count := sqlite.Count()

	// 解析模板文件
	tmpl, err := template.ParseFS(temp, "template/List.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respData := struct {
		DataList         []db.ResultData
		CurrentDataCount int
		TotalDataCount   int64
	}{
		DataList:         data,
		CurrentDataCount: len(data),
		TotalDataCount:   count,
	}

	// 渲染模板并将结果写入响应
	err = tmpl.Execute(w, respData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
