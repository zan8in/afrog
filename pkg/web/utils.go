package web

import (
	"net/http"
	"os"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// context keys
type ctxKey string

const (
	ctxUserID   ctxKey = "user_id"
	ctxLoginTime ctxKey = "login_time"
)

func GetUserIDFromContext(r *http.Request) string {
	if v := r.Context().Value(ctxUserID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getClientIP(r *http.Request) string {
	// 仅在受信任反代环境下使用XFF/X-Real-IP（通过环境变量控制）
	if os.Getenv("AFROG_TRUST_PROXY") == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.Split(xff, ",")[0]
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	// 默认使用RemoteAddr，防止XFF伪造
	return strings.Split(r.RemoteAddr, ":")[0]
}

func generateRandomPassword() string {
	return utils.CreateRandomString(32)
}
