package web

import (
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func generateRandomPassword() string {
	return utils.CreateRandomString(32)
}
