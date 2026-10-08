package web

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	curatedservice "github.com/zan8in/afrog/v3/pkg/curated/service"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/gologger"
)

// CuratedStatus 是会员身份的聚合状态，供 /api/me 与 Curated 中心使用。
type CuratedStatus struct {
	// Enabled 表示本进程是否具备 curated 能力（已注入配置且未被禁用）。
	Enabled bool `json:"enabled"`
	// Active 表示存在有效且未过期的授权。
	Active bool `json:"active"`
	// Expired 表示授权存在但已过期。
	Expired bool `json:"expired"`
	// License 是脱敏后的 license。
	License string `json:"license,omitempty"`
	// ExpiresAt 与 RemainingDays 描述授权到期时间，取自 license 的真实到期日。
	// 不限期或服务端尚未告知时 ExpiresAt 为空。
	ExpiresAt     string `json:"expires_at,omitempty"`
	RemainingDays int    `json:"remaining_days"`
	// LicensePermanent 表示该授权不限期（服务端 expires_at <= 0）。
	LicensePermanent bool `json:"license_permanent"`
	// Channel / ManifestID / LastUpdateAt / LastError 来自 curated 运行时状态。
	Channel      string `json:"channel,omitempty"`
	ManifestID   string `json:"manifest_id,omitempty"`
	LastUpdateAt string `json:"last_update_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	// PocCount 是本地 curated PoC 数量（带短 TTL 缓存）。
	PocCount int `json:"poc_count"`
}

var (
	curatedSvcMu sync.RWMutex
	curatedSvc   *curatedservice.Service
)

// SetCuratedService 由 cmd/afrog 在挂载 curated 后注入。未注入即表示本进程未启用 curated。
// 注入的实例带有 endpoint / channel / license，才能支撑 Web 侧激活与更新。
func SetCuratedService(svc *curatedservice.Service) {
	curatedSvcMu.Lock()
	curatedSvc = svc
	curatedSvcMu.Unlock()
}

func getCuratedService() *curatedservice.Service {
	curatedSvcMu.RLock()
	defer curatedSvcMu.RUnlock()
	return curatedSvc
}

// curatedFeatureEnabled 表示本进程是否具备 curated 能力。
func curatedFeatureEnabled() bool {
	return getCuratedService() != nil &&
		strings.TrimSpace(os.Getenv("AFROG_CURATED_DISABLED")) != "1"
}

// currentCuratedStatus 汇总 curated 授权与本地 PoC 状态。
func currentCuratedStatus() CuratedStatus {
	out := CuratedStatus{Enabled: curatedFeatureEnabled()}

	svc := getCuratedService()
	if svc == nil {
		return out
	}

	st, err := svc.Status(context.Background())
	if err != nil {
		return out
	}

	if st.Auth != nil {
		license := strings.TrimSpace(st.Auth.LicenseKey)
		out.License = maskLicense(license)

		// 到期时间只认服务端下发的 license 真实到期日（licenses.expires_at）。
		// 绝不拿 refresh/access token 的 TTL 冒充：那是"token 还能用多久"，
		// 与"授权到哪天"无关，用它会让界面显示一个凭空的期限。
		// LicenseExpiresAt 为 nil 表示服务端尚未告知（老版本服务端 / 升级前的旧文件）。
		if exp := st.Auth.LicenseExpiresAt; exp != nil {
			out.LicensePermanent = *exp <= 0
			if !out.LicensePermanent {
				expires := time.Unix(*exp, 0)
				out.ExpiresAt = expires.Format(time.RFC3339)
				out.RemainingDays = remainingDays(expires, time.Now())
				out.Expired = expires.Before(time.Now())
			}
		}
		// 未启用 curated 时，即使本地残留授权文件也不视为会员。
		out.Active = out.Enabled && license != "" && !out.Expired
	}

	if st.State != nil {
		out.Channel = strings.TrimSpace(st.State.CuratedChannel)
		out.ManifestID = strings.TrimSpace(st.State.ManifestID)
		if !st.State.LastUpdateAt.IsZero() {
			out.LastUpdateAt = st.State.LastUpdateAt.Format(time.RFC3339)
		}
		out.LastError = strings.TrimSpace(st.State.LastError)
	}

	out.PocCount = curatedPocCount()
	return out
}

// curatedRole 返回当前会员角色。始终以真实授权状态为准，不信任 token 中的旧值。
func curatedRole() string {
	if currentCuratedStatus().Active {
		return "curated"
	}
	return "free"
}

// remainingDays 把到期时间换算成「还剩几天」，**向上取整**。
//
// 向下截断会让"刚激活 30 天"显示成 29 天（还剩 29 天 23 小时），用户会以为授权少了 1 天；
// 向上取整后不足一天也算 1 天，与"还剩 N 天"的直觉一致。
func remainingDays(exp, now time.Time) int {
	days := int(math.Ceil(exp.Sub(now).Hours() / 24))
	if days < 0 {
		return 0
	}
	return days
}

// maskLicense 只保留 license 首尾各 4 位，避免接口把完整凭据吐给前端。
func maskLicense(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= 8 {
		return "****"
	}
	return string(r[:4]) + "****" + string(r[len(r)-4:])
}

var curatedPocCache struct {
	mu sync.Mutex
	n  int
	at time.Time
}

// curatedPocCount 统计本地 curated PoC 数量。目录遍历成本较高，加 30s 缓存。
func curatedPocCount() int {
	curatedPocCache.mu.Lock()
	defer curatedPocCache.mu.Unlock()

	if !curatedPocCache.at.IsZero() && time.Since(curatedPocCache.at) < 30*time.Second {
		return curatedPocCache.n
	}

	n := 0
	if items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "curated"}); err == nil {
		n = len(items)
	}
	curatedPocCache.n = n
	curatedPocCache.at = time.Now()
	return n
}

func invalidateCuratedPocCache() {
	curatedPocCache.mu.Lock()
	curatedPocCache.at = time.Time{}
	curatedPocCache.mu.Unlock()

	// curated PoC 数量也会出现在左侧菜单角标上，一并失效。
	invalidateNavBadgeCache()
}

// defaultCuratedDir 与 curated service 的默认目录保持一致（~/.config/afrog/pocs-curated）。
func defaultCuratedDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "afrog", "pocs-curated")
}

// meHandler 返回当前登录身份与会员状态，是前端渲染会员徽章/锁定态的唯一来源。
func meHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cs := currentCuratedStatus()
	role := "free"
	if cs.Active {
		role = "curated"
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data: map[string]any{
			"authenticated": true,
			"user_id":       GetUserIDFromContext(r),
			"role":          role,
			"curated":       cs,
		},
	})
}

// requireCurated 保护会员专属接口：非会员一律 403。以实时授权状态判断，
// 不用 token 里的旧 role，避免授权到期后仍可访问。
func requireCurated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if curatedRole() != "curated" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "该功能为 Curated 会员专属"})
			return
		}
		next(w, r)
	}
}

// curatedRemoteTimeout 约束远端交互（登录/拉取 manifest）的最长等待。
const curatedRemoteTimeout = 90 * time.Second

func writeCuratedJSON(w http.ResponseWriter, status int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// curatedStatusHandler 返回 curated 状态快照。
func curatedStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeCuratedJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: currentCuratedStatus()})
}

type curatedActivateRequest struct {
	License string `json:"license"`
}

// curatedActivateHandler 让 Web 成为激活渠道：粘贴 license 即完成登录并拉取 PoC。
func curatedActivateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writeCuratedJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	svc := getCuratedService()
	if svc == nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Curated 未启用，请先在 afrog-config.yaml 中配置 curated.endpoint",
		})
		return
	}

	var req curatedActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	license := strings.TrimSpace(req.License)
	if license == "" {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "license 不能为空"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), curatedRemoteTimeout)
	defer cancel()

	if err := svc.Login(ctx, license); err != nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "激活失败：" + err.Error()})
		return
	}

	// 激活本身已成功；拉取 PoC 失败不否定激活，前端据 poc_count/last_error 判断。
	if dir, mErr := svc.Mount(ctx); mErr != nil {
		gologger.Warning().Msgf("curated mount after activate failed: %s", mErr.Error())
	} else if strings.TrimSpace(dir) != "" {
		_ = os.Setenv("AFROG_POCS_CURATED_DIR", dir)
	}

	invalidateCuratedPocCache()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已激活", Data: currentCuratedStatus()})
}

// curatedUpdateHandler 强制检查并拉取最新 curated PoC。会员专属。
func curatedUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writeCuratedJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	svc := getCuratedService()
	if svc == nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Curated 未启用"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), curatedRemoteTimeout)
	defer cancel()

	if err := svc.Update(ctx, curatedservice.UpdateOptions{Force: true}); err != nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "更新失败：" + err.Error()})
		return
	}
	if dir := defaultCuratedDir(); dir != "" {
		_ = os.Setenv("AFROG_POCS_CURATED_DIR", dir)
	}

	invalidateCuratedPocCache()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已更新", Data: currentCuratedStatus()})
}
