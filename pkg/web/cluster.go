package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/gologger"
)

// 多实例编排（v1：只读聚合）。
//
// 一个控制台可以同时盯住多个 afrog 实例：在 afrog-config.yaml 的 cluster 段登记
// 同伴（name + url）并设置同一个 token，本实例会周期性地拉取同伴的自身状态
// （/api/cluster/self），在「概览」页聚合成一张实例表。
//
// v1 刻意只读，不做远程起扫/远程终止：派发要先解决「任务归属谁、断连后怎么办、
// 同一目标被两个实例同时扫怎么办」这些一致性问题，属于下一阶段。同伴不可达时
// 如实展示原因，不影响本地扫描。
const (
	// clusterTokenHeader 是实例之间互访的凭证头。Web 登录密码每次启动随机生成，
	// 无法用来互访，因此集群内另设一个共享密钥。
	clusterTokenHeader = "X-Afrog-Cluster-Token"

	// 心跳节奏：单个同伴最多等 5 秒，全部同伴每 30 秒探测一轮。
	clusterProbeTimeout  = 5 * time.Second
	clusterProbeInterval = 30 * time.Second
)

// ClusterSelf 是一个实例对外暴露的自身状态。
type ClusterSelf struct {
	InstanceID  string   `json:"instance_id"`
	Name        string   `json:"name"`
	BaseURL     string   `json:"base_url"`
	Version     string   `json:"version"`
	StartedAt   string   `json:"started_at"`
	PID         int      `json:"pid"`
	ActiveTasks int      `json:"active_task_count"`
	ActiveIDs   []string `json:"active_task_ids"`
	CPUUsage    float64  `json:"cpu_usage"`
	MemoryUsage float64  `json:"memory_usage"`
}

// ClusterInstance 是聚合视图里的一行：本机或某个同伴。
type ClusterInstance struct {
	ClusterSelf
	// Local 标记这一行是否本机。
	Local bool `json:"local"`
	// OK 为最近一次探测是否成功；同伴不通时 Error 说明原因，
	// 尚未探测过的行两者都为空（界面上显示为「探测中」）。
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// clusterRegistry 保存同伴清单与最近一轮心跳结果。
type clusterRegistry struct {
	name  string
	token string
	peers []config.ClusterPeer

	mu     sync.Mutex
	state  map[string]ClusterInstance
	client *http.Client

	stop chan struct{}
	once sync.Once
}

var (
	// clusterMu 保护下面三项：集群配置可以在 Web 端运行时改写（增删节点），
	// 而心跳协程与 HTTP 处理器会并发读取它们。
	clusterMu     sync.RWMutex
	clusterCfg    config.Cluster
	clusterPath   string
	globalCluster *clusterRegistry
)

// SetClusterConfig 注入集群配置及它所在的文件路径。由 cmd 层在启动 Web 服务前调用；
// 不调用（或 cluster 段留空）即单实例运行。configPath 为空表示用默认的
// ~/.config/afrog/afrog-config.yaml。
func SetClusterConfig(cfg config.Cluster, configPath string) {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	clusterCfg = cfg
	clusterPath = configPath
}

func currentClusterConfig() (config.Cluster, string) {
	clusterMu.RLock()
	defer clusterMu.RUnlock()
	return clusterCfg, clusterPath
}

// StartCluster 启动同伴心跳。没有配置同伴时不起后台协程，只保留本机视图。
func StartCluster() {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	if globalCluster != nil {
		return
	}
	reg := newClusterRegistry(clusterCfg)
	globalCluster = reg
	reg.start()
}

// StopCluster 停止心跳，可重复调用。
func StopCluster() {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	stopClusterLocked()
}

func stopClusterLocked() {
	reg := globalCluster
	if reg == nil {
		return
	}
	reg.stopNow()
	globalCluster = nil
}

// RebuildCluster 用新配置替换正在运行的心跳，立即生效，不需要重启进程。
//
// 只动内存不动磁盘：落盘由调用方先完成，写文件失败就不该走到这里，
// 否则会出现「界面显示已生效、进程重启后又变回去」的错位。
func RebuildCluster(cfg config.Cluster) {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	stopClusterLocked()
	clusterCfg = cfg
	reg := newClusterRegistry(cfg)
	globalCluster = reg
	reg.start()
}

// activeClusterRegistry 返回当前注册表（可能为 nil：服务未启动或未初始化）。
func activeClusterRegistry() *clusterRegistry {
	clusterMu.RLock()
	defer clusterMu.RUnlock()
	return globalCluster
}

func newClusterRegistry(cfg config.Cluster) *clusterRegistry {
	peers := make([]config.ClusterPeer, 0, len(cfg.Peers))
	seen := make(map[string]bool, len(cfg.Peers))
	for _, p := range cfg.Peers {
		url := normalizePeerURL(p.URL)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = url
		}
		peers = append(peers, config.ClusterPeer{Name: name, URL: url})
	}
	return &clusterRegistry{
		name:   strings.TrimSpace(cfg.Name),
		token:  strings.TrimSpace(cfg.Token),
		peers:  peers,
		state:  make(map[string]ClusterInstance, len(peers)),
		client: &http.Client{Timeout: clusterProbeTimeout},
		stop:   make(chan struct{}),
	}
}

// normalizePeerURL 归一化同伴地址：补默认协议、去掉结尾斜杠，非 http(s) 一律丢弃。
func normalizePeerURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return ""
	}
	return strings.TrimRight(v, "/")
}

// start 启动心跳循环。首轮探测在协程里跑：同伴不可达时不该拖慢服务启动或保存请求。
func (c *clusterRegistry) start() {
	if len(c.peers) == 0 {
		gologger.Debug().Msg("多实例编排：未配置同伴实例，仅展示本机")
		return
	}
	gologger.Info().Msgf("多实例编排已启动：%d 个同伴实例", len(c.peers))
	go c.loop()
}

// stopNow 关闭心跳循环，可重复调用。
func (c *clusterRegistry) stopNow() {
	c.once.Do(func() { close(c.stop) })
}

func (c *clusterRegistry) loop() {
	ticker := time.NewTicker(clusterProbeInterval)
	defer ticker.Stop()

	c.refresh()
	for {
		select {
		case <-c.stop:
			gologger.Info().Msg("多实例编排已停止")
			return
		case <-ticker.C:
			c.refresh()
		}
	}
}

// refresh 并发探测全部同伴。单个同伴失败只影响自己那一行。
func (c *clusterRegistry) refresh() {
	results := make([]ClusterInstance, len(c.peers))
	var wg sync.WaitGroup
	for i, p := range c.peers {
		wg.Add(1)
		go func(i int, p config.ClusterPeer) {
			defer wg.Done()
			results[i] = c.probe(p)
		}(i, p)
	}
	wg.Wait()

	c.mu.Lock()
	for _, item := range results {
		c.state[item.BaseURL] = item
	}
	c.mu.Unlock()
}

// probe 拉取一个同伴的自身状态。
//
// 失败同样返回一行（而不是把节点从列表里抹掉）：控制台要能看出「谁掉线了、
// 为什么掉线」，悄然消失的节点比报错的节点更难排查。
func (c *clusterRegistry) probe(p config.ClusterPeer) ClusterInstance {
	item := ClusterInstance{
		ClusterSelf: ClusterSelf{Name: p.Name, BaseURL: p.URL},
	}

	req, err := http.NewRequest(http.MethodGet, p.URL+"/api/cluster/self", nil)
	if err != nil {
		item.Error = "实例地址无效：" + err.Error()
		return item
	}
	if c.token != "" {
		req.Header.Set(clusterTokenHeader, c.token)
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		item.Error = "无法连接：" + err.Error()
		return item
	}
	defer resp.Body.Close()
	item.LatencyMs = time.Since(start).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		item.Error = clusterProbeError(resp.StatusCode)
		return item
	}

	var out struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Data    ClusterSelf `json:"data"`
	}
	// 同伴是别的进程，响应体不可信：限长解码，避免一个异常实例把控制台内存吃满。
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		item.Error = "返回内容无法解析"
		return item
	}
	if !out.Success {
		item.Error = strings.TrimSpace(out.Message)
		return item
	}

	self := out.Data
	if strings.TrimSpace(self.Name) == "" {
		self.Name = p.Name
	}
	// 地址以本地配置为准：同伴自报的 base_url 可能是它自己视角的地址（例如 0.0.0.0），
	// 直接展示会让人分不清该连哪里。
	self.BaseURL = p.URL
	if self.ActiveIDs == nil {
		self.ActiveIDs = []string{}
	}

	item.ClusterSelf = self
	item.OK = true
	item.LastSeen = time.Now().Format(scheduleTimeLayout)
	return item
}

// clusterProbeError 把 HTTP 状态码翻译成可执行的原因，而不是干巴巴的 401。
func clusterProbeError(status int) string {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "集群令牌不匹配（检查两端的 cluster.token）"
	}
	if status == http.StatusNotFound {
		return "目标地址上没有 /api/cluster/self（对方版本过旧或地址指向了别的服务）"
	}
	return fmt.Sprintf("对方返回 HTTP %d", status)
}

// instances 返回聚合视图：本机在前，同伴按配置顺序。
func (c *clusterRegistry) instances() []ClusterInstance {
	out := make([]ClusterInstance, 0, len(c.peers)+1)
	out = append(out, localClusterInstance())

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.peers {
		if item, ok := c.state[p.URL]; ok {
			out = append(out, item)
			continue
		}
		// 刚启动还没探测过：如实给出「探测中」，不假装在线也不假装掉线。
		out = append(out, ClusterInstance{ClusterSelf: ClusterSelf{Name: p.Name, BaseURL: p.URL}})
	}
	return out
}

// localClusterSelf 组装本机状态。字段与同伴接口返回的完全一致，
// 界面上「本机」与「同伴」两行才能并排比较。
//
// Name 取 cluster.name，允许为空：同伴拉取时用它自己配置的名字兜底，
// 本机展示时由界面兜底，两边都不必猜。
func localClusterSelf() ClusterSelf {
	cpu, mem := GetMonitorStats()
	cfg, _ := currentClusterConfig()

	m := getTaskManager()
	active := make([]string, 0, 16)
	m.mu.Lock()
	for id, t := range m.tasks {
		if isActive(t.Status()) {
			active = append(active, id)
		}
	}
	m.mu.Unlock()
	sort.Strings(active)

	return ClusterSelf{
		InstanceID:  serverInstanceID,
		Name:        strings.TrimSpace(cfg.Name),
		BaseURL:     serverBaseURL,
		Version:     fmt.Sprintf("v%s", config.Version),
		StartedAt:   serverStartedAt.Format(time.RFC3339),
		PID:         serverPID,
		ActiveTasks: len(active),
		ActiveIDs:   active,
		CPUUsage:    cpu,
		MemoryUsage: mem,
	}
}

func localClusterInstance() ClusterInstance {
	return ClusterInstance{ClusterSelf: localClusterSelf(), Local: true, OK: true}
}

// -----------------------
// HTTP API
// -----------------------

// clusterSelfHandler 供同伴实例读取本机状态，鉴权走集群共享密钥。
//
// 未配置 cluster.token 的实例不对外暴露自身状态：默认关闭，要用才开，
// 避免把「实例清单 + 活跃任务」这种内部信息顺手挂到公网上。
func clusterSelfHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cfg, _ := currentClusterConfig()
	expected := strings.TrimSpace(cfg.Token)
	if expected == "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "本实例未配置 cluster.token，不对外提供实例信息"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get(clusterTokenHeader))), []byte(expected)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "集群令牌不匹配"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: localClusterSelf()})
}

// clusterView 计算聚合视图与会员边界（纯函数，便于单独验证两种角色的差异）。
//
// 会员边界（PRD 8.2「多实例编排：普通用户受限 / 会员不限」）：普通用户只看得到
// 本机一行，同伴数量如实告知但不给内容；Curated 用户看到全部实例。
func clusterView(reg *clusterRegistry, role string) (items []ClusterInstance, peerCount int, locked bool) {
	items = []ClusterInstance{localClusterInstance()}
	if reg == nil || len(reg.peers) == 0 {
		return items, 0, false
	}

	peerCount = len(reg.peers)
	if role == "curated" {
		return reg.instances(), peerCount, false
	}
	return items, peerCount, true
}

// clusterInstancesHandler 返回聚合后的实例列表。
func clusterInstancesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	items, peerCount, locked := clusterView(activeClusterRegistry(), curatedRole())

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items":      items,
		"total":      len(items),
		"peer_count": peerCount,
		"locked":     locked,
	}})
}

// -----------------------
// 集群配置读写（运行时增删节点）
// -----------------------

// clusterPeerPayload / clusterConfigPayload 是 Web 端读写集群配置的传输结构。
// 直接序列化 config.Cluster 会输出 Go 字段名——那两个类型只带了 yaml tag。
type clusterPeerPayload struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type clusterConfigPayload struct {
	Name       string               `json:"name"`
	Token      string               `json:"token"`
	Peers      []clusterPeerPayload `json:"peers"`
	ConfigPath string               `json:"config_path"`
}

// maxClusterPeers 是同伴数量的上限：心跳是并发轮询，节点越多单轮耗时越长，
// 而控制台只是看板，没必要无限扩张。
const maxClusterPeers = 64

// parseClusterConfigPayload 校验并归一化提交上来的集群配置。
//
// 前端可以随便传，进入运行态之前必须收敛成「地址合法、去重、有上限」的清单：
// 免得一个手抖的地址把每 30 秒的心跳变成对错误目标的持续骚扰。
func parseClusterConfigPayload(p clusterConfigPayload) (config.Cluster, error) {
	out := config.Cluster{
		Name:  strings.TrimSpace(p.Name),
		Token: strings.TrimSpace(p.Token),
	}
	if len(p.Peers) > maxClusterPeers {
		return out, fmt.Errorf("同伴实例最多 %d 个", maxClusterPeers)
	}

	seen := make(map[string]bool, len(p.Peers))
	for _, peer := range p.Peers {
		raw := strings.TrimSpace(peer.URL)
		if raw == "" {
			continue
		}
		url := normalizePeerURL(raw)
		if url == "" {
			return out, fmt.Errorf("实例地址无效：%s（只支持 http/https）", raw)
		}
		if seen[url] {
			continue
		}
		seen[url] = true

		name := strings.TrimSpace(peer.Name)
		if name == "" {
			name = url
		}
		out.Peers = append(out.Peers, config.ClusterPeer{Name: name, URL: url})
	}

	// 没有令牌的实例不对外提供自身状态（见 clusterSelfHandler），配上同伴也拉不到
	// 数据。与其让它静默地全红，不如在保存时就说清楚。
	if len(out.Peers) > 0 && out.Token == "" {
		return out, fmt.Errorf("配置了同伴实例时必须设置集群令牌（cluster.token）")
	}
	return out, nil
}

func clusterPayloadFrom(cfg config.Cluster, configPath string) clusterConfigPayload {
	peers := make([]clusterPeerPayload, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers = append(peers, clusterPeerPayload{Name: p.Name, URL: p.URL})
	}
	return clusterConfigPayload{
		Name:       cfg.Name,
		Token:      cfg.Token,
		Peers:      peers,
		ConfigPath: configPath,
	}
}

// clusterConfigGetHandler 返回当前生效的集群配置，供概览页编辑。
//
// 令牌按原值返回：能过 JWT + Curated 两层校验的已经是这台机器的管理员，
// 而且他必须靠这个值去别的节点上填同样的 token。
func clusterConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cfg, path := currentClusterConfig()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: clusterPayloadFrom(cfg, resolveClusterConfigPath(path))})
}

// clusterConfigPutHandler 保存集群配置：先落盘，再重建心跳，保存即生效。
func clusterConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持PUT方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req clusterConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	cfg, err := parseClusterConfigPayload(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	_, path := currentClusterConfig()
	path = resolveClusterConfigPath(path)
	if err := config.UpdateClusterSection(path, cfg); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入配置文件失败：" + err.Error()})
		return
	}

	RebuildCluster(cfg)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已保存，心跳立即生效", Data: clusterPayloadFrom(cfg, path)})
}

// resolveClusterConfigPath 把「没传 -config」归一化成实际要写的默认路径，
// 让界面能如实告诉用户改的是哪个文件。
func resolveClusterConfigPath(path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	return config.DefaultConfigPath()
}
