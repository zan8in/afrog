package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
)

// withCluster 注入集群配置与注册表，测试结束后还原，避免用例之间互相影响。
func withCluster(t *testing.T, cfg config.Cluster) *clusterRegistry {
	t.Helper()
	return withClusterPath(t, cfg, "")
}

func withClusterPath(t *testing.T, cfg config.Cluster, configPath string) *clusterRegistry {
	t.Helper()

	clusterMu.Lock()
	prevCfg, prevPath, prevReg := clusterCfg, clusterPath, globalCluster
	clusterMu.Unlock()

	SetClusterConfig(cfg, configPath)
	reg := newClusterRegistry(cfg)
	clusterMu.Lock()
	globalCluster = reg
	clusterMu.Unlock()

	t.Cleanup(func() {
		clusterMu.Lock()
		clusterCfg, clusterPath, globalCluster = prevCfg, prevPath, prevReg
		clusterMu.Unlock()
	})
	return reg
}

// stopClusterOnCleanup 用例里如果调过 RebuildCluster，会留下一个仍在跑的心跳协程，
// 注册到 Cleanup 里收掉它。
func stopClusterOnCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(StopCluster)
}

func TestNormalizePeerURL(t *testing.T) {
	cases := map[string]string{
		"http://10.0.0.11:16868":  "http://10.0.0.11:16868",
		"10.0.0.12:16868":         "http://10.0.0.12:16868",
		"https://afrog.example/":  "https://afrog.example",
		"  http://a.example//  ":  "http://a.example",
		"":                        "",
		"ftp://a.example":         "",
		"redis://10.0.0.13:6379":  "",
		"http://127.0.0.1:16868/": "http://127.0.0.1:16868",
	}
	for in, want := range cases {
		if got := normalizePeerURL(in); got != want {
			t.Errorf("normalizePeerURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// 同伴清单要能容忍手写配置的重复与缺名：重复地址只留一条，没写名字就用地址兜底。
func TestNewClusterRegistry_DedupesAndNamesPeers(t *testing.T) {
	reg := newClusterRegistry(config.Cluster{
		Name:  " 总部 ",
		Token: " s3cret ",
		Peers: []config.ClusterPeer{
			{Name: "节点A", URL: "10.0.0.11:16868"},
			{Name: "重复", URL: "http://10.0.0.11:16868"},
			{Name: "", URL: "http://10.0.0.12:16868"},
			{Name: "无效", URL: "ftp://10.0.0.13"},
		},
	})

	if reg.name != "总部" || reg.token != "s3cret" {
		t.Fatalf("config not trimmed: name=%q token=%q", reg.name, reg.token)
	}
	if len(reg.peers) != 2 {
		t.Fatalf("peers = %+v, want the two valid unique entries", reg.peers)
	}
	if reg.peers[0].URL != "http://10.0.0.11:16868" || reg.peers[1].Name != "http://10.0.0.12:16868" {
		t.Fatalf("peer normalization mismatch: %+v", reg.peers)
	}
}

// 探测成功要把同伴自报的状态带回来，但地址以本地配置为准（同伴可能报 0.0.0.0）。
func TestClusterProbe_Success(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/self" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotToken = r.Header.Get(clusterTokenHeader)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: ClusterSelf{
			InstanceID:  "abc",
			Name:        "节点A",
			BaseURL:     "http://0.0.0.0:16868",
			Version:     "v3.5.7",
			ActiveTasks: 2,
			ActiveIDs:   []string{"t-1", "t-2"},
			CPUUsage:    1.5,
		}})
	}))
	defer srv.Close()

	reg := newClusterRegistry(config.Cluster{Token: "shared"})
	item := reg.probe(config.ClusterPeer{Name: "备用名", URL: srv.URL})

	if gotToken != "shared" {
		t.Fatalf("token header = %q, want the configured cluster token", gotToken)
	}
	if !item.OK || item.Error != "" {
		t.Fatalf("probe failed: %+v", item)
	}
	if item.InstanceID != "abc" || item.Version != "v3.5.7" || item.ActiveTasks != 2 {
		t.Fatalf("self fields mismatch: %+v", item)
	}
	if item.BaseURL != srv.URL {
		t.Fatalf("BaseURL = %q, want the locally configured %q", item.BaseURL, srv.URL)
	}
	if item.LastSeen == "" {
		t.Fatal("LastSeen should record the probe time")
	}
}

// 同伴没写名字时用本地配置的名字兜底，避免列表里出现一行空的实例名。
func TestClusterProbe_FallsBackToConfiguredName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Data: ClusterSelf{InstanceID: "abc"}})
	}))
	defer srv.Close()

	reg := newClusterRegistry(config.Cluster{})
	item := reg.probe(config.ClusterPeer{Name: "节点B", URL: srv.URL})
	if item.Name != "节点B" {
		t.Fatalf("Name = %q, want the configured fallback", item.Name)
	}
	if item.ActiveIDs == nil {
		t.Fatal("ActiveIDs must not be nil so the UI can iterate it")
	}
}

// 同伴不可达/令牌不对时，探测结果要给出可执行的原因，而不是变成一个空格子。
func TestClusterProbe_ReportsActionableErrors(t *testing.T) {
	t.Run("token rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		item := newClusterRegistry(config.Cluster{}).probe(config.ClusterPeer{Name: "n", URL: srv.URL})
		if item.OK || !strings.Contains(item.Error, "cluster.token") {
			t.Fatalf("error = %q, want a hint about cluster.token", item.Error)
		}
	})

	t.Run("no cluster endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		item := newClusterRegistry(config.Cluster{}).probe(config.ClusterPeer{Name: "n", URL: srv.URL})
		if item.OK || !strings.Contains(item.Error, "版本过旧") {
			t.Fatalf("error = %q, want a version hint", item.Error)
		}
	})

	t.Run("not json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html>hello</html>"))
		}))
		defer srv.Close()

		item := newClusterRegistry(config.Cluster{}).probe(config.ClusterPeer{Name: "n", URL: srv.URL})
		if item.OK || !strings.Contains(item.Error, "无法解析") {
			t.Fatalf("error = %q, want a parse hint", item.Error)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // 立刻关掉，模拟节点掉线

		item := newClusterRegistry(config.Cluster{}).probe(config.ClusterPeer{Name: "n", URL: url})
		if item.OK || !strings.Contains(item.Error, "无法连接") {
			t.Fatalf("error = %q, want a connection hint", item.Error)
		}
	})
}

// 聚合视图永远以本机开头；还没探测过的同伴如实显示为「探测中」而不是消失。
func TestClusterRegistry_InstancesPutsLocalFirst(t *testing.T) {
	reg := withCluster(t, config.Cluster{
		Peers: []config.ClusterPeer{{Name: "节点A", URL: "http://10.0.0.11:16868"}},
	})

	items := reg.instances()
	if len(items) != 2 {
		t.Fatalf("items = %d, want local + 1 peer", len(items))
	}
	if !items[0].Local || items[0].Name != "" {
		t.Fatalf("first row should be the raw local self: %+v", items[0])
	}
	if items[1].Local || items[1].OK || items[1].Error != "" {
		t.Fatalf("unprobed peer should be neutral: %+v", items[1])
	}
}

// /api/cluster/self 默认关闭：没配 token 就不对外暴露实例信息。
func TestClusterSelfHandler_RequiresClusterToken(t *testing.T) {
	withCluster(t, config.Cluster{})

	rec := httptest.NewRecorder()
	clusterSelfHandler(rec, httptest.NewRequest(http.MethodGet, "/api/cluster/self", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when no token is configured", rec.Code)
	}

	withCluster(t, config.Cluster{Token: "shared"})

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/self", nil)
	req.Header.Set(clusterTokenHeader, "wrong")
	clusterSelfHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a wrong token", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/cluster/self", nil)
	req.Header.Set(clusterTokenHeader, "shared")
	clusterSelfHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with the right token", rec.Code)
	}
	var resp struct {
		Success bool        `json:"success"`
		Data    ClusterSelf `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not json: %s", rec.Body.String())
	}
	if !resp.Success || resp.Data.InstanceID != serverInstanceID {
		t.Fatalf("payload mismatch: %+v", resp)
	}
}

// 会员边界：普通用户看得到「有几个同伴」，但看不到同伴的内容。
func TestClusterInstancesHandler_LocksPeersForFreeUsers(t *testing.T) {
	if curatedRole() != "free" {
		t.Skip("curated 服务已注入，跳过免费用户场景")
	}
	withCluster(t, config.Cluster{
		Peers: []config.ClusterPeer{{Name: "节点A", URL: "http://10.0.0.11:16868"}},
	})

	rec := httptest.NewRecorder()
	clusterInstancesHandler(rec, httptest.NewRequest(http.MethodGet, "/api/cluster/instances", nil))

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Items     []ClusterInstance `json:"items"`
			Total     int               `json:"total"`
			PeerCount int               `json:"peer_count"`
			Locked    bool              `json:"locked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not json: %s", rec.Body.String())
	}
	if !resp.Data.Locked {
		t.Fatal("peers must be locked for free users")
	}
	if resp.Data.PeerCount != 1 || resp.Data.Total != 1 || len(resp.Data.Items) != 1 {
		t.Fatalf("free users should only see the local row: %+v", resp.Data)
	}
	if !resp.Data.Items[0].Local {
		t.Fatalf("the single visible row must be the local instance: %+v", resp.Data.Items[0])
	}
}

// 同一个注册表，两种角色看到的东西不同：Curated 展开全部节点，普通用户只看本机。
func TestClusterView_RoleDecidesVisibility(t *testing.T) {
	reg := newClusterRegistry(config.Cluster{
		Name:  "总部",
		Peers: []config.ClusterPeer{{Name: "节点A", URL: "http://10.0.0.11:16868"}},
	})

	items, peerCount, locked := clusterView(reg, "curated")
	if locked || peerCount != 1 || len(items) != 2 {
		t.Fatalf("curated view = %d items, peerCount=%d locked=%v", len(items), peerCount, locked)
	}
	if !items[0].Local || items[1].Local {
		t.Fatalf("local row must stay first: %+v", items)
	}

	items, peerCount, locked = clusterView(reg, "free")
	if !locked || peerCount != 1 || len(items) != 1 || !items[0].Local {
		t.Fatalf("free view mismatch: items=%d peerCount=%d locked=%v", len(items), peerCount, locked)
	}

	// 未启动（注册表为空）时既不报错也不上锁：单实例就是完整视图。
	items, peerCount, locked = clusterView(nil, "free")
	if locked || peerCount != 0 || len(items) != 1 {
		t.Fatalf("nil registry mismatch: items=%d peerCount=%d locked=%v", len(items), peerCount, locked)
	}
}

// 没有配置同伴时不进入上锁态：单实例用户看到的就是完整的真实情况。
func TestClusterInstancesHandler_NoPeersIsNotLocked(t *testing.T) {
	withCluster(t, config.Cluster{})

	rec := httptest.NewRecorder()
	clusterInstancesHandler(rec, httptest.NewRequest(http.MethodGet, "/api/cluster/instances", nil))

	var resp struct {
		Data struct {
			Total     int  `json:"total"`
			PeerCount int  `json:"peer_count"`
			Locked    bool `json:"locked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not json: %s", rec.Body.String())
	}
	if resp.Data.Locked || resp.Data.PeerCount != 0 || resp.Data.Total != 1 {
		t.Fatalf("single-instance view mismatch: %+v", resp.Data)
	}
}

// 提交上来的配置要收敛成「地址合法、去重、有上限」的清单才允许进入运行态。
func TestParseClusterConfigPayload(t *testing.T) {
	t.Run("normalizes and dedupes", func(t *testing.T) {
		cfg, err := parseClusterConfigPayload(clusterConfigPayload{
			Name:  " 总部 ",
			Token: " shared ",
			Peers: []clusterPeerPayload{
				{Name: "节点B", URL: "192.168.1.111:16869"},
				{Name: "重复", URL: "http://192.168.1.111:16869/"},
				{Name: "", URL: " http://a.example:16868 "},
				{Name: "空地址", URL: "   "},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Name != "总部" || cfg.Token != "shared" {
			t.Fatalf("未清理首尾空格: %+v", cfg)
		}
		if len(cfg.Peers) != 2 {
			t.Fatalf("peers = %+v, want 2 unique entries", cfg.Peers)
		}
		if cfg.Peers[0].URL != "http://192.168.1.111:16869" {
			t.Fatalf("地址未补全协议或未去重: %+v", cfg.Peers[0])
		}
		if cfg.Peers[1].Name != "http://a.example:16868" {
			t.Fatalf("没写名字时应以地址兜底: %+v", cfg.Peers[1])
		}
	})

	t.Run("rejects invalid url", func(t *testing.T) {
		_, err := parseClusterConfigPayload(clusterConfigPayload{
			Token: "shared",
			Peers: []clusterPeerPayload{{Name: "坏地址", URL: "ftp://10.0.0.9"}},
		})
		if err == nil || !strings.Contains(err.Error(), "地址无效") {
			t.Fatalf("err = %v, want an invalid-address error", err)
		}
	})

	t.Run("requires token when peers exist", func(t *testing.T) {
		_, err := parseClusterConfigPayload(clusterConfigPayload{
			Peers: []clusterPeerPayload{{Name: "节点B", URL: "http://192.168.1.111:16869"}},
		})
		if err == nil || !strings.Contains(err.Error(), "cluster.token") {
			t.Fatalf("err = %v, want a token hint", err)
		}
		if _, err := parseClusterConfigPayload(clusterConfigPayload{Name: "总部"}); err != nil {
			t.Fatalf("单实例（没有同伴）不该要求令牌: %v", err)
		}
	})

	t.Run("caps peer count", func(t *testing.T) {
		peers := make([]clusterPeerPayload, 0, maxClusterPeers+1)
		for i := 0; i <= maxClusterPeers; i++ {
			peers = append(peers, clusterPeerPayload{URL: fmt.Sprintf("http://10.0.0.%d:16868", i+1)})
		}
		if _, err := parseClusterConfigPayload(clusterConfigPayload{Token: "shared", Peers: peers}); err == nil {
			t.Fatalf("超过 %d 个同伴应被拒绝", maxClusterPeers)
		}
	})
}

// 保存节点列表：先落盘再重建心跳，之后连 /api/cluster/self 的令牌也换成新的。
func TestClusterConfigPutHandler_WritesAndRebuilds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(clusterTokenHeader) != "new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: ClusterSelf{
			InstanceID: "peer-1",
			Name:       "阿里云",
		}})
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "afrog-config.yaml")
	if err := os.WriteFile(path, []byte("server: :16868\n\ncluster:\n  name: \"旧\"\n  token: \"old\"\n"), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	withClusterPath(t, config.Cluster{Name: "旧", Token: "old"}, path)
	stopClusterOnCleanup(t)

	body := fmt.Sprintf(`{"name":"总部","token":"new-token","peers":[{"name":"阿里云","url":%q}]}`, srv.URL)
	rec := httptest.NewRecorder()
	clusterConfigPutHandler(rec, httptest.NewRequest(http.MethodPut, "/api/cluster/config", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back config: %v", err)
	}
	if !strings.Contains(string(written), srv.URL) || !strings.Contains(string(written), `token: "new-token"`) {
		t.Fatalf("配置未写入文件：\n%s", written)
	}
	if !strings.Contains(string(written), "server: :16868") {
		t.Fatalf("其它段落被破坏：\n%s", written)
	}

	// 保存即生效：注册表换成新的同伴，共享密钥也立刻跟着换。
	reg := activeClusterRegistry()
	if reg == nil || len(reg.peers) != 1 || reg.peers[0].URL != srv.URL {
		t.Fatalf("心跳未按新配置重建: %+v", reg)
	}
	cfg, gotPath := currentClusterConfig()
	if cfg.Token != "new-token" || gotPath != path {
		t.Fatalf("内存态未更新: cfg=%+v path=%q", cfg, gotPath)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/self", nil)
	req.Header.Set(clusterTokenHeader, "new-token")
	clusterSelfHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("新令牌应立即生效, status = %d", rec.Code)
	}
}

// 校验失败时不能改内存，也不能碰配置文件。
func TestClusterConfigPutHandler_RejectsInvalidPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "afrog-config.yaml")
	original := "cluster:\n  name: \"总部\"\n  token: \"shared\"\n  peers: []\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	withClusterPath(t, config.Cluster{Name: "总部", Token: "shared"}, path)

	rec := httptest.NewRecorder()
	body := `{"name":"总部","token":"shared","peers":[{"name":"坏","url":"ftp://10.0.0.9"}]}`
	clusterConfigPutHandler(rec, httptest.NewRequest(http.MethodPut, "/api/cluster/config", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back config: %v", err)
	}
	if string(written) != original {
		t.Fatalf("校验失败不应写文件：\n%s", written)
	}
}

// 概览页编辑需要回读当前生效的配置（含要写回的文件路径）。
func TestClusterConfigGetHandler_ReturnsCurrentConfig(t *testing.T) {
	withClusterPath(t, config.Cluster{
		Name:  "总部",
		Token: "shared",
		Peers: []config.ClusterPeer{{Name: "阿里云", URL: "http://101.201.70.97:16868"}},
	}, "/tmp/afrog-config.yaml")

	rec := httptest.NewRecorder()
	clusterConfigGetHandler(rec, httptest.NewRequest(http.MethodGet, "/api/cluster/config", nil))

	var resp struct {
		Success bool                 `json:"success"`
		Data    clusterConfigPayload `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not json: %s", rec.Body.String())
	}
	if !resp.Success {
		t.Fatalf("unexpected payload: %s", rec.Body.String())
	}
	if resp.Data.Name != "总部" || resp.Data.Token != "shared" || resp.Data.ConfigPath != "/tmp/afrog-config.yaml" {
		t.Fatalf("顶层字段不对: %+v", resp.Data)
	}
	if len(resp.Data.Peers) != 1 || resp.Data.Peers[0].URL != "http://101.201.70.97:16868" {
		t.Fatalf("peers 不对: %+v", resp.Data.Peers)
	}
}
