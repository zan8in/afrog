package web

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// JWT配置
var (
	jwtSecret         []byte
	generatedPassword string
)

// JWT Claims结构
type Claims struct {
	UserID    string `json:"user_id"`
	LoginTime int64  `json:"login_time"`
	jwt.RegisteredClaims
}

// 登录请求结构
type LoginRequest struct {
	Password string `json:"password"`
}

// 登录响应结构
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// 通用API响应
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 初始化JWT密钥
func initJWTSecret() {
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)
	gologger.Info().Msg("JWT密钥已生成")
}

// 生成JWT Token
func generateJWTToken(userID string) (string, int64, error) {
	expires := time.Now().Add(1 * time.Minute)
	// expires := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:    userID,
		LoginTime: time.Now().Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "afrog-security-scanner",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	return tokenString, expires.Unix(), err
}

// 验证JWT Token
func validateJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("无效的token")
}

// 登录处理器
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "仅支持POST方法",
		})
		return
	}

	// 验证Content-Type
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Content-Type必须为application/json",
		})
		return
	}

	// 解析请求
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "无效的JSON格式",
		})
		return
	}

	// 验证密码
	if loginReq.Password != generatedPassword {
		// 记录失败尝试
		gologger.Warning().Str("ip", getClientIP(r)).Msg("登录失败尝试")

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "密码错误",
		})
		return
	}

	// 生成JWT Token
	userID := "admin" // 固定用户ID
	token, expires, err := generateJWTToken(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "生成token失败",
		})
		return
	}

	// 记录成功登录
	gologger.Info().Str("ip", getClientIP(r)).Msg("用户登录成功")

	// 返回成功响应
	json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "登录成功",
		Token:   token,
		Expires: expires,
	})
}

// JWT认证中间件
func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// 从Authorization header获取token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Message: "缺少Authorization header",
			})
			return
		}

		// 验证Bearer格式
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Message: "无效的Authorization格式，应为: Bearer <token>",
			})
			return
		}

		// 验证JWT Token
		claims, err := validateJWTToken(tokenParts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Message: "无效或过期的token",
			})
			return
		}

		// 将用户信息添加到请求上下文
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-Login-Time", fmt.Sprintf("%d", claims.LoginTime))

		// 继续处理请求
		next.ServeHTTP(w, r)
	}
}

// 退出处理器
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "仅支持POST方法",
		})
		return
	}

	// JWT是无状态的，客户端删除token即可
	// 这里可以记录退出日志
	userID := r.Header.Get("X-User-ID")
	if userID != "" {
		gologger.Info().Str("user_id", userID).Str("ip", getClientIP(r)).Msg("用户退出")
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "退出成功",
	})
}

// 漏洞列表处理器（受JWT保护）
func vulnsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 获取用户信息（由中间件设置）
	userID := r.Header.Get("X-User-ID")
	gologger.Info().Str("user_id", userID).Msg("访问漏洞列表")

	// 这里实现原有的listHandler逻辑
	// 返回漏洞数据的JSON格式
	vulnData := map[string]interface{}{
		"total": 0,
		"vulns": []interface{}{},
		"page":  1,
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "获取成功",
		Data:    vulnData,
	})
}

func StartServer(addr string) error {
	// 初始化
	generatedPassword = generateRandomPassword()
	initJWTSecret()
	gologger.Info().Str("password", generatedPassword).Msg("Web访问密码")

	// 创建文件系统
	buildRoot, err := fs.Sub(buildFS, "build")
	if err != nil {
		return fmt.Errorf("无法加载静态文件: %v", err)
	}

	// 创建路由复用器
	mux := http.NewServeMux()

	// API 路由
	mux.HandleFunc("/api/login", withCORS(loginHandler))
	mux.HandleFunc("/api/logout", withCORS(jwtAuthMiddleware(logoutHandler)))
	mux.HandleFunc("/api/vulns", withCORS(jwtAuthMiddleware(vulnsHandler)))

	// 静态文件服务
	// staticFileServer := http.FileServer(http.FS(buildRoot))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reqPath := strings.TrimPrefix(r.URL.Path, "/")
		if reqPath == "" {
			reqPath = "index.html"
		}
		f, err := buildRoot.Open(reqPath)
		if err == nil {
			defer f.Close()
			data, _ := io.ReadAll(f)
			// 自动识别Content-Type
			http.ServeContent(w, r, reqPath, time.Now(), bytes.NewReader(data))
			return
		}
		// SPA路由兼容，找不到文件时返回index.html
		indexFile, err := buildRoot.Open("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer indexFile.Close()
		data, _ := io.ReadAll(indexFile)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// 启动服务器
	gologger.Info().Msgf("Web服务器启动于: http://%s", addr)
	return http.ListenAndServe(addr, mux)
}

// 获取客户端IP
func getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	// 检查X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// 使用RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// 生成随机密码
func generateRandomPassword() string {
	return utils.CreateRandomString(32)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
