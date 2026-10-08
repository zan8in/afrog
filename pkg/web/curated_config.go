package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	curatedservice "github.com/zan8in/afrog/v3/pkg/curated/service"
)

// curated（会员）段配置的读写与运行时装配。
//
// 与 OOB / 集群一样，会员配置只存在于 afrog-config.yaml 的 curated 段，界面把它暴露成一张
// 设置卡、保存即写回文件。区别在于：curated 的能力在启动时就被装配进一个 service
// （endpoint / license 全部烘焙在里面，且没有 setter），所以**光改文件对当前进程无效**，
// 保存后必须按新配置重新装配一次。
var (
	curatedCfgMu   sync.RWMutex
	curatedSection config.Curated
	curatedCfgPath string
)

const (
	defaultCuratedTimeoutSec = 10
	defaultCuratedChannel    = "stable"
)

func setCuratedSection(cur config.Curated, configPath string) {
	curatedCfgMu.Lock()
	defer curatedCfgMu.Unlock()
	curatedSection = cur
	curatedCfgPath = resolveClusterConfigPath(configPath)
}

// currentCuratedSection 返回当前 curated 段与它所在的文件路径（路径总是具体的，便于界面展示）。
func currentCuratedSection() (config.Curated, string) {
	curatedCfgMu.RLock()
	cur := curatedSection
	path := curatedCfgPath
	curatedCfgMu.RUnlock()
	return cur, resolveClusterConfigPath(path)
}

// AssembleCurated 按 curated 段装配运行态，并把结果注入本进程。
//
// 启动（cmd/afrog）与界面保存配置共用这一份口径，避免"启动会清理残留、保存却不会"这类漂移：
//   - 禁用（enabled=off/false/0，或 endpoint 为空）：卸下能力、清掉本地残留 PoC；
//   - 启用：构建 service、挂载 PoC，并导出 AFROG_POCS_CURATED_DIR（Web 执行器拉起的子进程要读）。
//
// 返回的 err 只表示"挂载失败"：装配本身已经完成——拿不到 PoC 不等于未激活，
// 界面据 last_error 展示，而不是把配置回滚。
func AssembleCurated(cur config.Curated, configPath string, forceUpdate bool) error {
	setCuratedSection(cur, configPath)

	enabled := strings.ToLower(strings.TrimSpace(cur.Enabled))
	if enabled == "off" || enabled == "false" || enabled == "0" || strings.TrimSpace(cur.Endpoint) == "" {
		_ = os.Setenv("AFROG_CURATED_DISABLED", "1")
		_ = os.Unsetenv("AFROG_POCS_CURATED_DIR")
		SetCuratedService(nil)
		if dir := defaultCuratedDir(); dir != "" {
			_ = os.RemoveAll(dir)
		}
		invalidateCuratedPocCache()
		return nil
	}

	_ = os.Unsetenv("AFROG_CURATED_DISABLED")
	svc := curatedservice.New(curatedservice.Config{
		Endpoint:      strings.TrimSpace(cur.Endpoint),
		Channel:       strings.TrimSpace(cur.Channel),
		LicenseKey:    strings.TrimSpace(cur.LicenseKey),
		NoUpdate:      cur.AutoUpdate != nil && !*cur.AutoUpdate && !forceUpdate,
		ForceUpdate:   forceUpdate,
		ClientVersion: config.Version,
	})
	SetCuratedService(svc)

	timeout := time.Duration(cur.TimeoutSec) * time.Second
	// 显式更新不该被配置里很小的 timeout_sec 掐断：那个值默认只有 10s，原本是给启动时
	// "顺手检查一下"用的，而点保存/带 -curated-force-update 时要真的把 PoC 拉下来。
	if forceUpdate && timeout < curatedRemoteTimeout {
		timeout = curatedRemoteTimeout
	}
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	dir, err := svc.Mount(ctx)
	invalidateCuratedPocCache()
	if err != nil {
		return err
	}
	if strings.TrimSpace(dir) != "" {
		_ = os.Setenv("AFROG_POCS_CURATED_DIR", dir)
	}
	return nil
}

// curatedConfigPayload 是界面编辑 curated 段用的扁平结构。
type curatedConfigPayload struct {
	// Enabled 是会员能力的开关，沿用配置文件的字符串语义：auto / on / off。
	Enabled    string `json:"enabled"`
	Endpoint   string `json:"endpoint"`
	Channel    string `json:"channel"`
	LicenseKey string `json:"license_key"`
	AutoUpdate bool   `json:"auto_update"`
	TimeoutSec int    `json:"timeout_sec"`
	// ConfigPath 告诉界面改的到底是哪个文件。
	ConfigPath string `json:"config_path,omitempty"`
}

func curatedPayloadFrom(cur config.Curated, configPath string) curatedConfigPayload {
	autoUpdate := true
	if cur.AutoUpdate != nil {
		autoUpdate = *cur.AutoUpdate
	}
	timeout := cur.TimeoutSec
	if timeout <= 0 {
		timeout = defaultCuratedTimeoutSec
	}
	return curatedConfigPayload{
		Enabled:    normalizedCuratedEnabled(cur.Enabled),
		Endpoint:   strings.TrimSpace(cur.Endpoint),
		Channel:    normalizedCuratedChannel(cur.Channel),
		LicenseKey: strings.TrimSpace(cur.LicenseKey),
		AutoUpdate: autoUpdate,
		TimeoutSec: timeout,
		ConfigPath: configPath,
	}
}

// normalizedCuratedEnabled 把开关归一成 auto/on/off，非法值回落 auto（与 config 段同口径）。
func normalizedCuratedEnabled(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "off", "false", "0":
		return "off"
	case "on", "true", "1":
		return "on"
	default:
		return "auto"
	}
}

func normalizedCuratedChannel(raw string) string {
	if v := strings.TrimSpace(raw); v != "" {
		return v
	}
	return defaultCuratedChannel
}

// curatedConfigFromPayload 校验并归一化界面提交的 curated 段。
func curatedConfigFromPayload(p curatedConfigPayload) (config.Curated, error) {
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint != "" &&
		!strings.HasPrefix(endpoint, "http://") &&
		!strings.HasPrefix(endpoint, "https://") {
		return config.Curated{}, errors.New("服务地址需以 http:// 或 https:// 开头")
	}
	timeout := p.TimeoutSec
	if timeout <= 0 {
		timeout = defaultCuratedTimeoutSec
	}
	autoUpdate := p.AutoUpdate
	return config.Curated{
		Enabled:    normalizedCuratedEnabled(p.Enabled),
		AutoUpdate: &autoUpdate,
		Endpoint:   endpoint,
		TimeoutSec: timeout,
		Channel:    normalizedCuratedChannel(p.Channel),
		LicenseKey: strings.TrimSpace(p.LicenseKey),
	}, nil
}

// curatedConfigGetHandler 返回当前 curated 段，供会员中心编辑。
func curatedConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeCuratedJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cur, path := currentCuratedSection()
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    curatedPayloadFrom(cur, path),
	})
}

// curatedConfigPutHandler 保存 curated 段：先写回 afrog-config.yaml，再按新配置重新装配。
//
// 重新装配会顺带完成登录并拉取 PoC，一次点击即等价于原来的"激活会员"。
// 拉取失败只提示、不回滚配置——与既有"拿不到 PoC 不等于未激活"的语义一致。
func curatedConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		writeCuratedJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持PUT方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req curatedConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	next, err := curatedConfigFromPayload(req)
	if err != nil {
		writeCuratedJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	_, path := currentCuratedSection()
	if err := config.UpdateCuratedSection(path, next); err != nil {
		writeCuratedJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "写入配置文件失败：" + err.Error(),
		})
		return
	}

	message := "已保存并生效"
	if err := AssembleCurated(next, path, true); err != nil {
		message = "配置已保存，但拉取 PoC 失败：" + strings.TrimSpace(err.Error())
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
		Data: map[string]any{
			"config": curatedPayloadFrom(next, path),
			"status": currentCuratedStatus(),
		},
	})
}
