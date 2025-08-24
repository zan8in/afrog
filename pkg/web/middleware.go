package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 全局安全头（覆盖静态资源与API）
func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 仅设置安全相关头，不修改Content-Type（静态资源需要各自类型）
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		// 基础CSP，按需微调
		// w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// 简单登录限速（滑动窗口）
var (
	loginMu       sync.Mutex
	loginAttempts = make(map[string][]time.Time)
)

func loginRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	const (
		window   = 30 * time.Minute
		maxTries = 10 // 30分钟最多10次
	)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		now := time.Now()
		loginMu.Lock()
		history := loginAttempts[ip]
		// 清理窗口外
		var recent []time.Time
		for _, t := range history {
			if now.Sub(t) < window {
				recent = append(recent, t)
			}
		}
		if len(recent) >= maxTries {
			loginMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "尝试次数过多，请稍后再试"})
			return
		}
		recent = append(recent, now)
		loginAttempts[ip] = recent
		loginMu.Unlock()

		next.ServeHTTP(w, r)
	}
}

func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// API统一为JSON
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

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

		// 使用context传递认证信息（替代通过请求头透传）
		ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
		ctx = context.WithValue(ctx, ctxLoginTime, claims.LoginTime)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}
