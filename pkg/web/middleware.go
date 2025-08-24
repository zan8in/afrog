package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 所有API返回JSON
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

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

		// 将用户信息添加到请求头，后续处理器可读取
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-Login-Time", string(rune(claims.LoginTime)))

		next.ServeHTTP(w, r)
	}
}