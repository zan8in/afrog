package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/sqli"
	"github.com/zan8in/afrog/v3/pkg/passive/proxy"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/gologger"
)

// passiveRuntime 是被动扫描的进程内单例。
//
// 生命周期与 Web 服务解耦：默认不启动，由前端显式开关。这样即使代理端口被占用
// 或 CA 目录不可写，也不会影响 afrogweb 的其它功能。
type passiveRuntime struct {
	mu        sync.Mutex
	server    *proxy.Server
	engine    *passive.Engine
	cfg       config.Passive
	cfgPath   string
	caDir     string
	startedAt time.Time
	lastErr   string

	// listenOverride 仅供测试注入监听地址（如 127.0.0.1:0 随机端口），
	// 避免单元测试占用真实端口。生产路径始终使用配置里的地址。
	listenOverride string

	reported int64
}

// 调度层的并发参数不再硬编码：门控池/检测池的 worker 数与队列容量都由 passive
// 配置段决定（见 config.Passive.Workers / DetectWorkers / QueueSize），
// 未配置时由各自的默认值兜底。

var passiveRT = &passiveRuntime{
	cfg: config.Passive{
		Host:            config.DefaultPassiveHost,
		Port:            config.DefaultPassivePort,
		Detectors:       []string{config.DefaultPassiveDetector},
		MaxRPS:          config.DefaultPassiveMaxRPS,
		HostConcurrency: config.DefaultPassiveHostConcurrency,
		Workers:         config.DefaultPassiveWorkers,
		DetectWorkers:   config.DefaultPassiveDetectWorkers,
		QueueSize:       config.DefaultPassiveQueueSize,
	},
	caDir: proxy.DefaultCADir(),
}

// SetPassiveConfig 注入 passive 配置段及其所在文件路径，由 cmd 层在启动 Web 服务前调用。
func SetPassiveConfig(cfg config.Passive, configPath string) {
	passiveRT.mu.Lock()
	defer passiveRT.mu.Unlock()
	passiveRT.cfg = cfg
	passiveRT.cfgPath = configPath
}

// StartPassive 启动被动扫描（幂等）。
func StartPassive() error {
	return passiveRT.start()
}

// StopPassive 停止被动扫描（幂等），Web 服务退出时调用。
func StopPassive() {
	passiveRT.stop()
}

// AutoStartPassive 在配置要求时自动开启，失败只记日志、不影响 Web 服务。
func AutoStartPassive() {
	passiveRT.mu.Lock()
	auto := passiveRT.cfg.AutoStart
	passiveRT.mu.Unlock()
	if !auto {
		return
	}
	if err := StartPassive(); err != nil {
		gologger.Error().Msgf("被动扫描自动启动失败: %v", err)
	}
}

// buildDetectors 按配置装配检测器。
//
// 未识别的名字被忽略而不是报错：配置文件可能被新版本写入、又被旧版本读取，
// 让旧版本因为一个不认识的检测器名而整体启动失败，体验很差。
func buildDetectors(names []string) []passive.Detector {
	out := make([]passive.Detector, 0, len(names))
	for _, name := range names {
		switch name {
		case sqli.DetectorName:
			out = append(out, sqli.New(sqli.DefaultOptions()))
		default:
			gologger.Debug().Msgf("忽略未识别的被动检测器: %s", name)
		}
	}
	if len(out) == 0 {
		out = append(out, sqli.New(sqli.DefaultOptions()))
	}
	return out
}

func (rt *passiveRuntime) listenAddr(cfg config.Passive) string {
	if rt.listenOverride != "" {
		return rt.listenOverride
	}
	return cfg.Addr()
}

func (rt *passiveRuntime) start() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.server != nil {
		return nil
	}

	cfg := rt.cfg

	// 每次启动都清空历史观测数据，避免上一次运行的结论误导本次排查。
	passiveTraffic.reset()

	var upstream *url.URL
	if strings.TrimSpace(cfg.Upstream) != "" {
		u, err := url.Parse(cfg.Upstream)
		if err != nil {
			rt.lastErr = "上游代理地址无效: " + err.Error()
			passiveTraffic.recordError("server", errors.New(rt.lastErr))
			return errors.New(rt.lastErr)
		}
		upstream = u
	}

	proberOpts := passive.DefaultProberOptions()
	if cfg.MaxRPS > 0 {
		proberOpts.GlobalRPS = cfg.MaxRPS
	}
	if cfg.HostConcurrency > 0 {
		proberOpts.HostConcurrency = cfg.HostConcurrency
	}
	proberOpts.Upstream = upstream

	// 归属项目在启动这一瞬固定下来：之后所有命中都记到这个项目名下。为空即「未归属」，
	// 仍按无项目归档——不因为没选项目就丢弃命中。
	projectID := cfg.ProjectID

	engine := passive.NewEngine(passive.EngineOptions{
		Detectors: buildDetectors(cfg.EnabledDetectors()),
		Prober:    passive.NewHTTPProber(proberOpts),
		OnFinding: func(f passive.Finding) { rt.onFinding(projectID, f) },
		OnTraffic: passiveTraffic.add,
		OnError: func(detector string, err error) {
			passiveTraffic.recordError("detector:"+detector, err)
			gologger.Debug().Msgf("被动检测异常: detector=%s err=%v", detector, err)
		},
		Workers:       cfg.WorkersOrDefault(),
		DetectWorkers: cfg.DetectWorkersOrDefault(),
		QueueSize:     cfg.QueueSizeOrDefault(),
	})
	engine.Start(context.Background())

	srv, err := proxy.New(proxy.Options{
		Addr:     rt.listenAddr(cfg),
		CADir:    rt.caDir,
		Upstream: upstream,
		// 范围裁剪在代理层生效：范围外的流量连队列都不占用。
		// 这是使用者唯一能「从源头省流量」的旋钮。
		Scope:              cfg.Scope(),
		AllowUnsafeMethods: cfg.ScanUnsafeMethods,
		OnTransaction: func(tx *passive.CapturedTransaction) {
			engine.Submit(tx)
		},
		OnTraffic: passiveTraffic.add,
		OnError: func(scope string, err error) {
			passiveTraffic.recordError(scope, err)
		},
	})
	if err != nil {
		engine.Close()
		rt.lastErr = err.Error()
		passiveTraffic.recordError("server", err)
		return err
	}
	if err := srv.Start(); err != nil {
		engine.Close()
		rt.lastErr = err.Error()
		passiveTraffic.recordError("server", err)
		return err
	}

	rt.server = srv
	rt.engine = engine
	rt.startedAt = time.Now()
	rt.lastErr = ""
	gologger.Info().Msgf("被动扫描代理已启动: http://%s", srv.Addr())
	return nil
}

func (rt *passiveRuntime) stop() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.server == nil && rt.engine == nil {
		return
	}
	if rt.server != nil {
		_ = rt.server.Stop()
		rt.server = nil
	}
	if rt.engine != nil {
		rt.engine.Close()
		rt.engine = nil
	}
	rt.startedAt = time.Time{}
	gologger.Info().Msg("被动扫描代理已停止")
}

// onFinding 是被动发现的落库入口。
//
// 只有 ConfidenceCertain 的结论能走到这里（调度层保证），因此无需再判置信度。
// 落库走 upsert：同一 (project_id, fingerprint) 反复命中会归到同一条、累加次数并
// 刷新 last_seen——这正是「今天扫到、下次复测又扫到」需要被记录的事实，而不是
// 被当成重复丢掉。单条写入失败只记日志：被动链路不能因为数据库问题而中断。
func (rt *passiveRuntime) onFinding(projectID string, f passive.Finding) {
	extra := "{}"
	if len(f.Extra) > 0 {
		if b, err := json.Marshal(f.Extra); err == nil {
			extra = string(b)
		}
	}

	traces := "[]"
	if len(f.Traces) > 0 {
		if b, err := json.Marshal(f.Traces); err == nil {
			traces = string(b)
		}
	}

	id, state, hitCount, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		ProjectID:   projectID,
		Fingerprint: passiveFingerprint(f),
		Detector:    f.Detector,
		VulnType:    f.VulnType,
		Severity:    f.Severity,
		Confidence:  f.Confidence.String(),
		Title:       f.Title,
		Target:      f.Target,
		Location:    f.Location,
		Payload:     f.Payload,
		Evidence:    f.Evidence,
		LatencyMs:   f.LatencyMs,
		TracesRaw:   traces,
		Request:     string(f.Request),
		Response:    string(f.Response),
		Extra:       extra,
	})
	if err != nil {
		passiveTraffic.recordError("storage", errors.New("被动发现落库失败: "+err.Error()))
		gologger.Debug().Msgf("被动发现落库失败: %v", err)
		return
	}
	if id <= 0 {
		return
	}
	if state != sqlite.PassiveStateNew {
		gologger.Debug().Msgf("被动命中已存在，累计第 %d 次: state=%s target=%s", hitCount, state, f.Target)
	}
	atomic.AddInt64(&rt.reported, 1)
}

func passiveFingerprint(f passive.Finding) string {
	return f.Detector + "|" + f.VulnType + "|" + f.Target + "|" + f.Location
}

// -----------------------
// HTTP 接口
// -----------------------

type passiveStatus struct {
	Running    bool     `json:"running"`
	Addr       string   `json:"addr"`
	CADir      string   `json:"ca_dir"`
	CADownload string   `json:"ca_download"`
	StartedAt  string   `json:"started_at,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	Detectors  []string `json:"detectors"`
	// ProjectID 是本次运行绑定的归属项目：启动那一刻固定，改配置重启后才改变。
	ProjectID string        `json:"project_id"`
	Stats     passive.Stats `json:"stats"`
	// Drained 表示「进入调度的事务是否已全部处理完」：积压与在途都为 0 时才算跑完。
	// 判断「这一轮流量检测完了吗」要看它，不能用 stats.inspected——后者只统计
	// 真正跑过检测器的事务，未通过门控的不计入，会永远比 submitted 少。
	Drained     bool                 `json:"drained"`
	Traffic     passiveTrafficCounts `json:"traffic"`
	Reported    int64                `json:"reported"`
	TotalStored int64                `json:"total_stored"`
	ProxyHint   string               `json:"proxy_hint"`
	Config      passiveConfigView    `json:"config"`
	// AvailableDetectors 供设置面板渲染可选项，避免前端硬编码。
	AvailableDetectors []string `json:"available_detectors"`
}

// passiveConfigView 是配置对外的形态，字段名与前端保持一致。
type passiveConfigView struct {
	AutoStart       bool     `json:"auto_start"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Upstream        string   `json:"upstream"`
	Detectors       []string `json:"detectors"`
	MaxRPS          int      `json:"max_rps"`
	HostConcurrency int      `json:"host_concurrency"`
	// Workers 是门控池 worker 数，只负责「要不要检测」的筛选。
	Workers int `json:"workers"`
	// DetectWorkers 是检测池 worker 数，等于实际重放并发度。
	DetectWorkers int `json:"detect_workers"`
	// QueueSize 是门控入口队列容量，队列满即丢弃。
	QueueSize int `json:"queue_size"`
	// ProjectID 是被动命中的归属渗透项目；空表示「未归属」。
	ProjectID string `json:"project_id"`
	// ScopeHostAllow / ScopeHostDeny / ScopePathDeny 是代理层的范围裁剪规则。
	ScopeHostAllow []string `json:"scope_host_allow"`
	ScopeHostDeny  []string `json:"scope_host_deny"`
	ScopePathDeny  []string `json:"scope_path_deny"`
	// ScanUnsafeMethods 表示是否重放 PUT / PATCH / DELETE；默认关闭以防破坏数据。
	ScanUnsafeMethods bool `json:"scan_unsafe_methods"`
	// ConfigPath 回显配置实际写入的文件，便于使用者直接去编辑。
	ConfigPath string `json:"config_path,omitempty"`
}

func passiveConfigViewFrom(cfg config.Passive, path string) passiveConfigView {
	return passiveConfigView{
		AutoStart:         cfg.AutoStart,
		Host:              cfg.Host,
		Port:              cfg.Port,
		Upstream:          cfg.Upstream,
		Detectors:         cfg.EnabledDetectors(),
		MaxRPS:            cfg.MaxRPS,
		HostConcurrency:   cfg.HostConcurrency,
		Workers:           cfg.WorkersOrDefault(),
		DetectWorkers:     cfg.DetectWorkersOrDefault(),
		QueueSize:         cfg.QueueSizeOrDefault(),
		ProjectID:         cfg.ProjectID,
		ScopeHostAllow:    cfg.ScopeHostAllow,
		ScopeHostDeny:     cfg.ScopeHostDeny,
		ScopePathDeny:     cfg.ScopePathDeny,
		ScanUnsafeMethods: cfg.ScanUnsafeMethods,
		ConfigPath:        path,
	}
}

// passiveProxyHint 按监听位置给出可执行的接入提示。
//
// 绑定回环地址时只说 127.0.0.1；绑定所有网卡时必须提醒「用本机局域网 IP」，
// 否则使用者会拿着 0.0.0.0 去填代理，那不是一个可连接的目标地址。
func passiveProxyHint(cfg config.Passive) string {
	addr := cfg.Addr()
	_, port, _ := net.SplitHostPort(addr)
	switch cfg.Host {
	case "", "127.0.0.1", "localhost":
		return "把 Burp / 浏览器的上游代理指向 127.0.0.1:" + port + "，并信任 /api/passive/ca 下载的根证书"
	case "0.0.0.0", "::":
		return "已监听所有网卡：本机填 127.0.0.1:" + port + "；手机或其他设备填「本机局域网 IP:" + port + "」，并在设备上信任根证书"
	default:
		return "把 Burp / 浏览器的上游代理指向 " + addr + "，并信任 /api/passive/ca 下载的根证书"
	}
}

func passiveStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	passiveRT.mu.Lock()
	running := passiveRT.server != nil
	cfg := passiveRT.cfg
	cfgPath := passiveRT.cfgPath
	caDir := passiveRT.caDir
	startedAt := passiveRT.startedAt
	lastErr := passiveRT.lastErr
	engine := passiveRT.engine
	passiveRT.mu.Unlock()

	st := passiveStatus{
		Running:            running,
		Addr:               cfg.Addr(),
		CADir:              caDir,
		CADownload:         "/api/passive/ca",
		Detectors:          cfg.EnabledDetectors(),
		ProjectID:          cfg.ProjectID,
		Reported:           atomic.LoadInt64(&passiveRT.reported),
		ProxyHint:          passiveProxyHint(cfg),
		Config:             passiveConfigViewFrom(cfg, cfgPath),
		AvailableDetectors: []string{sqli.DetectorName},
	}
	if running {
		st.StartedAt = startedAt.Format(time.RFC3339)
	}
	st.LastError = lastErr
	if engine != nil {
		st.Stats = engine.Stats()
		st.Drained = engine.Drained()
	}
	_, st.Traffic = passiveTraffic.snapshot(1, "")
	// 「已入库」与运行绑定的项目同口径：被动扫描是绑定到渗透项目运行的，
	// 若仍报全局计数，会把其它项目的历史命中混进来，与当前任务无关。
	// 未绑定项目时退回全局计数。
	if projectID := strings.TrimSpace(cfg.ProjectID); projectID != "" {
		if n, err := sqlite.CountPassiveFindingsByProject(projectID); err == nil {
			st.TotalStored = n
		}
	} else if n, err := sqlite.CountPassiveFindings(); err == nil {
		st.TotalStored = n
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: st})
}

func passiveStartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := StartPassive(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "被动扫描启动失败: " + err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已启动"})
}

func passiveStopHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	StopPassive()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已停止"})
}

// -----------------------
// 配置读写
// -----------------------

type passiveConfigPayload struct {
	AutoStart         bool     `json:"auto_start"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Upstream          string   `json:"upstream"`
	Detectors         []string `json:"detectors"`
	MaxRPS            int      `json:"max_rps"`
	HostConcurrency   int      `json:"host_concurrency"`
	Workers           int      `json:"workers"`
	DetectWorkers     int      `json:"detect_workers"`
	QueueSize         int      `json:"queue_size"`
	ProjectID         string   `json:"project_id"`
	ScopeHostAllow    []string `json:"scope_host_allow"`
	ScopeHostDeny     []string `json:"scope_host_deny"`
	ScopePathDeny     []string `json:"scope_path_deny"`
	ScanUnsafeMethods bool     `json:"scan_unsafe_methods"`
}

func passiveConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	passiveRT.mu.Lock()
	cfg := passiveRT.cfg
	path := passiveRT.cfgPath
	passiveRT.mu.Unlock()

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"config":              passiveConfigViewFrom(cfg, path),
		"available_detectors": []string{sqli.DetectorName},
	}})
}

// passiveConfigPutHandler 保存配置。
//
// 运行中保存会按新配置自动重启代理：改端口、改监听地址、改上游代理都必须重建
// 监听才能生效，要求使用者「保存后再手动重启一次」是没有必要的负担。
func passiveConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req passiveConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	next, err := normalizePassivePayload(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	passiveRT.mu.Lock()
	path := passiveRT.cfgPath
	running := passiveRT.server != nil
	passiveRT.mu.Unlock()

	if err := config.UpdatePassiveSection(path, next); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入配置文件失败：" + err.Error()})
		return
	}

	passiveRT.mu.Lock()
	passiveRT.cfg = next
	passiveRT.mu.Unlock()

	message := "配置已保存，下次启动被动扫描时生效"
	if running {
		StopPassive()
		if err := StartPassive(); err != nil {
			message = "配置已保存，但按新配置重启失败：" + err.Error()
		} else {
			message = "配置已保存，被动扫描已按新配置重启"
		}
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: message, Data: map[string]any{
		"config": passiveConfigViewFrom(next, path),
	}})
}

// normalizePassivePayload 校验并补齐配置。
//
// 校验只做「一定会导致启动失败」的项：端口越界、上游代理格式非法。
// 其余（限速、并发）做温和兜底，避免把一个可用的配置拦在门外。
func normalizePassivePayload(req passiveConfigPayload) (config.Passive, error) {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = config.DefaultPassiveHost
	}
	if req.Port <= 0 || req.Port > 65535 {
		return config.Passive{}, errors.New("端口必须在 1-65535 之间")
	}

	upstream := strings.TrimRight(strings.TrimSpace(req.Upstream), "/")
	if upstream != "" {
		u, err := url.Parse(upstream)
		if err != nil || u.Host == "" {
			return config.Passive{}, errors.New("上游代理地址无效，应形如 http://127.0.0.1:8080")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return config.Passive{}, errors.New("上游代理仅支持 http 或 https")
		}
	}

	valid := map[string]bool{sqli.DetectorName: true}
	detectors := make([]string, 0, len(req.Detectors))
	for _, d := range req.Detectors {
		name := strings.ToLower(strings.TrimSpace(d))
		if valid[name] {
			detectors = append(detectors, name)
		}
	}
	if len(detectors) == 0 {
		detectors = []string{config.DefaultPassiveDetector}
	}

	maxRPS := req.MaxRPS
	if maxRPS <= 0 {
		maxRPS = config.DefaultPassiveMaxRPS
	}
	conc := req.HostConcurrency
	if conc <= 0 {
		conc = config.DefaultPassiveHostConcurrency
	}
	workers := req.Workers
	if workers <= 0 {
		workers = config.DefaultPassiveWorkers
	}
	detectWorkers := req.DetectWorkers
	if detectWorkers <= 0 {
		detectWorkers = config.DefaultPassiveDetectWorkers
	}
	queueSize := req.QueueSize
	if queueSize <= 0 {
		queueSize = config.DefaultPassiveQueueSize
	}

	// 归属项目：允许为空（未归属）。非空时必须真实存在，否则命中会挂到一个
	// 查不到名字的裸 ID 上，界面只能显示 ID、按项目筛选也永远命中不了。
	projectID := strings.TrimSpace(req.ProjectID)
	if projectID != "" {
		if _, ok := findProject(projectID); !ok {
			return config.Passive{}, errors.New("归属项目不存在或已被删除")
		}
	}

	return config.Passive{
		AutoStart:         req.AutoStart,
		Host:              host,
		Port:              req.Port,
		Upstream:          upstream,
		Detectors:         detectors,
		MaxRPS:            maxRPS,
		HostConcurrency:   conc,
		Workers:           workers,
		DetectWorkers:     detectWorkers,
		QueueSize:         queueSize,
		ProjectID:         projectID,
		ScopeHostAllow:    cleanScopeList(req.ScopeHostAllow),
		ScopeHostDeny:     cleanScopeList(req.ScopeHostDeny),
		ScopePathDeny:     cleanScopeList(req.ScopePathDeny),
		ScanUnsafeMethods: req.ScanUnsafeMethods,
	}, nil
}

// cleanScopeList 去掉范围规则里的空白项，避免界面上的空行变成一条规则。
func cleanScopeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// passiveCAHandler 下发根证书。
//
// 未启动时也允许下载：使用者通常需要先信任证书、再配置代理，顺序不该被强绑。
func passiveCAHandler(w http.ResponseWriter, r *http.Request) {
	var pemData []byte

	passiveRT.mu.Lock()
	srv := passiveRT.server
	caDir := passiveRT.caDir
	passiveRT.mu.Unlock()

	if srv != nil {
		pemData = srv.CACertPEM()
	}
	if len(pemData) == 0 {
		ca, err := proxy.LoadOrCreateCA(caDir)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取根证书失败: " + err.Error()})
			return
		}
		pemData = ca.CertPEM()
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="afrog-ca.crt"`)
	_, _ = w.Write(pemData)
}

func passiveFindingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	q := r.URL.Query()
	page := atoiParam(q.Get("page"), 1)
	if page <= 0 {
		page = 1
	}
	pageSize := atoiParam(q.Get("page_size"), 50)
	if pageSize <= 0 {
		pageSize = 50
	}
	flt := sqlite.PassiveFindingFilter{
		Detector: strings.TrimSpace(q.Get("detector")),
		VulnType: strings.TrimSpace(q.Get("vuln_type")),
		Severity: strings.TrimSpace(q.Get("severity")),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     page,
		PageSize: pageSize,
	}
	if v := strings.TrimSpace(q.Get("project_id")); v != "" {
		flt.ProjectID = v
	}
	if v := strings.TrimSpace(q.Get("state")); v != "" {
		flt.State = strings.Split(v, ",")
	}
	if v := strings.TrimSpace(q.Get("promoted")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			flt.Promoted = &n
		}
	}

	items, total, err := sqlite.SelectPassiveFindings(flt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "被动发现查询失败"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items":     items,
		"total":     total,
		"page":      flt.Page,
		"page_size": flt.PageSize,
	}})
}

// passiveFindingDetailView 是详情接口的对外形态：把库里的证据链 JSON 解析成数组，
// 前端直接渲染，不必再解析一次。
type passiveFindingDetailView struct {
	*sqlite.PassiveFindingDetail
	Traces []passive.Trace `json:"traces"`
}

func newPassiveFindingDetailView(d *sqlite.PassiveFindingDetail) passiveFindingDetailView {
	traces := parsePassiveTraces(d)
	// 兼容早期只存单条请求/响应的记录：界面上永远有东西可看。
	if len(traces) == 0 && (d.Request != "" || d.Response != "") {
		traces = []passive.Trace{{
			Label:     "命中请求",
			Payload:   d.Payload,
			LatencyMs: d.LatencyMs,
			Request:   d.Request,
			Response:  d.Response,
		}}
	}
	return passiveFindingDetailView{PassiveFindingDetail: d, Traces: traces}
}

// parsePassiveTraces 解析证据链；老记录或坏数据返回空切片。
func parsePassiveTraces(d *sqlite.PassiveFindingDetail) []passive.Trace {
	if d == nil || strings.TrimSpace(d.TracesRaw) == "" {
		return nil
	}
	var traces []passive.Trace
	if err := json.Unmarshal([]byte(d.TracesRaw), &traces); err != nil {
		return nil
	}
	return traces
}

func passiveFindingDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的 id"})
		return
	}

	detail, err := sqlite.GetPassiveFinding(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "被动发现不存在"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: newPassiveFindingDetailView(detail)})
}

// passiveFindingStateHandler 人工流转一条命中的观察状态。
//
// 目前只支持把命中标记为「已修复」（fixed），或把误标的改回「仍存在」（present）：
// 这是「人工确认修复」的唯一入口——系统只会据观察自动转 new / present / regression，
// 绝不会自己把一条漏洞判成已修复。标记 fixed 后若再次被命中，upsert 会自动转为
// regression，从而在时间线上暴露「修复被回退」这一事实。
func passiveFindingStateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的 id"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	if err := sqlite.SetPassiveFindingState(id, req.State); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已更新"})
}

// passivePromoteHandler 把一条被动发现提升为正式台账记录。
//
// 复用 result 表而不是另建台账：这样「主动扫描命中」与「被动检测命中」在报告、
// 台账、导出里天然合并，使用者不需要在两套列表之间来回对照。
func passivePromoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的 id"})
		return
	}

	detail, err := sqlite.GetPassiveFinding(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "被动发现不存在"})
		return
	}
	if detail.Promoted == 1 {
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已提升过", Data: map[string]string{"result_id": detail.ResultID}})
		return
	}

	resultID, err := sqlite.InsertResultAndReturnID(buildPassiveResult(detail))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入台账失败: " + err.Error()})
		return
	}

	rid := fmt.Sprintf("%d", resultID)
	if err := sqlite.MarkPassiveFindingPromoted(id, rid); err != nil {
		gologger.Debug().Msgf("标记被动发现已提升失败: %v", err)
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已加入台账", Data: map[string]string{"result_id": rid}})
}

// buildPassiveResult 把被动发现转换成一条标准的 result 记录。
//
// 刻意复用 result 的既有结构（PocInfo + AllPocResult），而不是新增台账表：
// 这样「主动扫描命中」与「被动检测命中」在报告、台账、导出里天然合并，
// 使用者不需要在两套列表之间来回对照。
func buildPassiveResult(detail *sqlite.PassiveFindingDetail) *result.Result {
	pocInfo := &poc.Poc{
		Id: "passive-" + detail.VulnType,
		Info: poc.Info{
			Name:        detail.Title,
			Author:      "afrog-passive",
			Severity:    detail.Severity,
			Description: detail.Evidence,
			Tags:        "passive," + detail.VulnType,
		},
	}

	// 证据链整体搬进报告的 result 列表：每一条请求/响应各占一张卡片，
	// 报告详情的编号 + 耗时徽标正好逐条对应，人工复核时不必在两个界面之间对照。
	pocResults := make([]*result.PocResult, 0, 4)
	for _, tr := range parsePassiveTraces(detail) {
		pocResults = append(pocResults, &result.PocResult{
			FullTarget:    detail.Target + " [" + tr.Label + "]",
			ResultRequest: &proto.Request{Raw: []byte(tr.Request)},
			// Latency 由 proto.Response 携带：台账落库时正是从 Response.GetLatency()
			// 读出 other.latency，这样被动提升的记录在报告详情里也能显示响应时间，
			// 时间盲注的耗时证据才不会被丢掉。
			ResultResponse: &proto.Response{
				Raw:     []byte(tr.Response),
				Latency: tr.LatencyMs,
			},
		})
	}
	// 老记录没有证据链，退化为单条，行为与升级前一致。
	if len(pocResults) == 0 {
		pocResults = append(pocResults, &result.PocResult{
			FullTarget:    detail.Target,
			ResultRequest: &proto.Request{Raw: []byte(detail.Request)},
			ResultResponse: &proto.Response{
				Raw:     []byte(detail.Response),
				Latency: detail.LatencyMs,
			},
		})
	}

	return &result.Result{
		IsVul:        true,
		Target:       detail.Target,
		FullTarget:   detail.Target + " [" + detail.Location + "]",
		PocInfo:      pocInfo,
		AllPocResult: pocResults,
	}
}
