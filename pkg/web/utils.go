package web

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// context keys
type ctxKey string

const (
	ctxUserID    ctxKey = "user_id"
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

func isValidAddress(line string) bool {
	s := strings.TrimSpace(line)
	if s == "" {
		return false
	}
	schemeRe := regexp.MustCompile(`^(?i)[a-z][a-z0-9+.-]*://\S+$`)
	httpRe := regexp.MustCompile(`^(?i)https?://\S+$`)
	hostPortRe := regexp.MustCompile(`^[A-Za-z0-9.-]+:\d+$`)
	// IPv6 主机:端口，形如 [2001:db8::1]:80（net.JoinHostPort 的产物）
	ipv6HostPortRe := regexp.MustCompile(`^\[[0-9A-Fa-f:]+\]:\d+$`)
	tcpRe := regexp.MustCompile(`^(?i)tcp://[A-Za-z0-9.-]+:\d+$`)
	domainRe := regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	hostPathRe := regexp.MustCompile(`^(?i)[A-Za-z0-9.-]+(?::\d+)?(?:/\S*)?$`)
	if httpRe.MatchString(s) || hostPortRe.MatchString(s) || ipv6HostPortRe.MatchString(s) || tcpRe.MatchString(s) {
		return true
	}
	if schemeRe.MatchString(s) { // 允许任意合法 scheme（如 ftp, udp 等）
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if domainRe.MatchString(s) {
		return true
	}
	if hostPathRe.MatchString(s) { // 允许 host[/path] 或 host:port[/path]
		return true
	}
	return false
}

func normalizeAddress(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "`\"")
	if s == "" {
		return s
	}
	if strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://") {
		if u, err := url.Parse(s); err == nil {
			host := strings.ToLower(u.Host)
			if strings.Contains(host, ":") {
				h := strings.Split(host, ":")
				host = strings.ToLower(h[0]) + ":" + h[1]
			}
			u.Host = host
			if u.Scheme == "http" && strings.HasSuffix(u.Path, "/") {
				u.Path = strings.TrimRight(u.Path, "/")
			}
			if u.Scheme == "https" && strings.HasSuffix(u.Path, "/") {
				u.Path = strings.TrimRight(u.Path, "/")
			}
			if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) || (u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
				u.Host = strings.Split(u.Host, ":")[0]
			}
			return u.String()
		}
	}
	s = strings.TrimRight(s, "/")
	return strings.ToLower(s)
}
