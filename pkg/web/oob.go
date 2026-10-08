package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/config"
)

// OOB（带外检测）适配器凭据的读写。
//
// 这些凭据（ceyeio 的 api-key、alphalog 的 api_url…）只存在于 afrog-config.yaml
// 的 reverse 段。Web 端此前只能选适配器名、无法录入凭据，选错或未配置会静默失效。
// 这里把 reverse 段暴露成一张设置卡片：保存即写回 afrog-config.yaml；Web 执行器
// 每次扫描新起子进程，子进程启动时读取该文件，因此保存后下一次扫描即生效。
var (
	oobMu   sync.RWMutex
	oobCfg  config.Reverse
	oobPath string
)

// SetOOBConfig 注入 OOB 配置及其所在文件路径，由 cmd 层在启动 Web 服务前调用。
func SetOOBConfig(reverse config.Reverse, configPath string) {
	oobMu.Lock()
	defer oobMu.Unlock()
	oobCfg = reverse
	oobPath = configPath
}

func currentOOBConfig() (config.Reverse, string) {
	oobMu.RLock()
	defer oobMu.RUnlock()
	return oobCfg, oobPath
}

// oobConfigPayload 是界面编辑用的扁平结构，只含常见适配器的凭据字段。
// eye/jndi 不在界面暴露，保存时从当前配置原样带回，避免被覆盖。
type oobConfigPayload struct {
	CeyeApiKey       string `json:"ceye_api_key"`
	CeyeDomain       string `json:"ceye_domain"`
	DnslogcnDomain   string `json:"dnslogcn_domain"`
	AlphalogDomain   string `json:"alphalog_domain"`
	AlphalogAPIURL   string `json:"alphalog_api_url"`
	XrayToken        string `json:"xray_token"`
	XrayDomain       string `json:"xray_domain"`
	XrayAPIURL       string `json:"xray_api_url"`
	RevsuitToken     string `json:"revsuit_token"`
	RevsuitDNSDomain string `json:"revsuit_dns_domain"`
	RevsuitHTTPURL   string `json:"revsuit_http_url"`
	RevsuitAPIURL    string `json:"revsuit_api_url"`
	InteractshServer string `json:"interactsh_server"`
	InteractshToken  string `json:"interactsh_token"`
	ConfigPath       string `json:"config_path,omitempty"`
}

func oobPayloadFrom(r config.Reverse, configPath string) oobConfigPayload {
	return oobConfigPayload{
		CeyeApiKey:       r.Ceye.ApiKey,
		CeyeDomain:       r.Ceye.Domain,
		DnslogcnDomain:   r.Dnslogcn.Domain,
		AlphalogDomain:   r.Alphalog.Domain,
		AlphalogAPIURL:   r.Alphalog.ApiUrl,
		XrayToken:        r.Xray.XToken,
		XrayDomain:       r.Xray.Domain,
		XrayAPIURL:       r.Xray.ApiUrl,
		RevsuitToken:     r.Revsuit.Token,
		RevsuitDNSDomain: r.Revsuit.DnsDomain,
		RevsuitHTTPURL:   r.Revsuit.HttpUrl,
		RevsuitAPIURL:    r.Revsuit.ApiUrl,
		InteractshServer: r.Interactsh.Server,
		InteractshToken:  r.Interactsh.Token,
		ConfigPath:       configPath,
	}
}

// oobConfigGetHandler 返回当前生效的 OOB 凭据，供设置页编辑。
func oobConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cfg, path := currentOOBConfig()
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    oobPayloadFrom(cfg, resolveClusterConfigPath(path)),
	})
}

// oobConfigPutHandler 保存 OOB 凭据：先写回 afrog-config.yaml，再更新内存态。
func oobConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持PUT方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req oobConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	trim := strings.TrimSpace
	cur, path := currentOOBConfig()
	next := config.Reverse{
		Alphalog: config.Alphalog{
			Domain: trim(req.AlphalogDomain),
			ApiUrl: trim(req.AlphalogAPIURL),
		},
		Ceye: config.Ceye{
			ApiKey: trim(req.CeyeApiKey),
			Domain: trim(req.CeyeDomain),
		},
		Dnslogcn: config.Dnslogcn{Domain: trim(req.DnslogcnDomain)},
		Interactsh: config.Interactsh{
			Server: trim(req.InteractshServer),
			Token:  trim(req.InteractshToken),
		},
		Xray: config.Xray{
			XToken: trim(req.XrayToken),
			Domain: trim(req.XrayDomain),
			ApiUrl: trim(req.XrayAPIURL),
		},
		Revsuit: config.Revsuit{
			Token:     trim(req.RevsuitToken),
			DnsDomain: trim(req.RevsuitDNSDomain),
			HttpUrl:   trim(req.RevsuitHTTPURL),
			ApiUrl:    trim(req.RevsuitAPIURL),
		},
		// 界面未暴露，原样保留，避免写回时丢配置。
		Eye:  cur.Eye,
		Jndi: cur.Jndi,
	}

	path = resolveClusterConfigPath(path)
	if err := config.UpdateReverseSection(path, next); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入配置文件失败：" + err.Error()})
		return
	}

	oobMu.Lock()
	oobCfg = next
	oobPath = path
	oobMu.Unlock()

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "已保存，下次扫描生效",
		Data:    oobPayloadFrom(next, path),
	})
}
