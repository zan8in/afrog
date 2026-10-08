package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), afrogConfigFilename)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back config: %v", err)
	}
	return string(b)
}

// 写回只该动 cluster 块：同文件里的其它段落、以及紧随其后的顶级键都不能被吃掉。
func TestUpdateClusterSection_ReplacesOnlyClusterBlock(t *testing.T) {
	path := writeTempConfig(t, `server: :16868
curated:
  enabled: "auto"
  license_key: "LIC_1"

cluster:
  name: "旧名字" # 本节点显示名
  token: "old-token"
  peers:
    - name: "老节点"
      url: "http://10.0.0.9:16868"

webhook:
  dingtalk:
    tokens:
      - ""
`)

	err := UpdateClusterSection(path, Cluster{
		Name:  "总部",
		Token: "shared",
		Peers: []ClusterPeer{
			{Name: "节点B", URL: "http://192.168.1.111:16869"},
			{Name: "阿里云", URL: "http://101.201.70.97:16868"},
		},
	})
	if err != nil {
		t.Fatalf("UpdateClusterSection: %v", err)
	}

	got := readFile(t, path)
	if strings.Contains(got, "10.0.0.9") || strings.Contains(got, "old-token") {
		t.Fatalf("旧节点未被替换：\n%s", got)
	}
	if !strings.Contains(got, "curated:") || !strings.Contains(got, `license_key: "LIC_1"`) {
		t.Fatalf("其它段落被破坏：\n%s", got)
	}
	if !strings.Contains(got, "webhook:") || !strings.Contains(got, "server: :16868") {
		t.Fatalf("cluster 之后的顶级键被破坏：\n%s", got)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(got), &cfg); err != nil {
		t.Fatalf("写回的内容不是合法 yaml: %v\n%s", err, got)
	}
	if cfg.Cluster.Name != "总部" || cfg.Cluster.Token != "shared" {
		t.Fatalf("cluster 段解析结果不对: %+v", cfg.Cluster)
	}
	if len(cfg.Cluster.Peers) != 2 ||
		cfg.Cluster.Peers[1].Name != "阿里云" ||
		cfg.Cluster.Peers[1].URL != "http://101.201.70.97:16868" {
		t.Fatalf("peers 解析结果不对: %+v", cfg.Cluster.Peers)
	}
	if cfg.Curated.LicenseKey != "LIC_1" {
		t.Fatalf("curated 段解析结果不对: %+v", cfg.Curated)
	}
}

// 原本没有 cluster 段时要能追加，且追加后仍是合法 yaml。
func TestUpdateClusterSection_AppendsWhenMissing(t *testing.T) {
	path := writeTempConfig(t, `server: :16868
curated:
  enabled: "auto"
`)

	if err := UpdateClusterSection(path, Cluster{
		Name:  "总部",
		Token: "shared",
		Peers: []ClusterPeer{{Name: "节点B", URL: "http://192.168.1.111:16869"}},
	}); err != nil {
		t.Fatalf("UpdateClusterSection: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(readFile(t, path)), &cfg); err != nil {
		t.Fatalf("写回的内容不是合法 yaml: %v", err)
	}
	if cfg.ServerAddress != ":16868" || cfg.Curated.Enabled != "auto" {
		t.Fatalf("原有段落被破坏: %+v", cfg)
	}
	if len(cfg.Cluster.Peers) != 1 || cfg.Cluster.Peers[0].URL != "http://192.168.1.111:16869" {
		t.Fatalf("cluster 段未写入: %+v", cfg.Cluster)
	}
}

// 删光同伴时要写回 peers: []，而不是留下一个空键（读回来是 nil，界面会当成没配置过）。
func TestUpdateClusterSection_EmptyPeersAsInlineList(t *testing.T) {
	path := writeTempConfig(t, `cluster:
  name: "总部"
  token: "shared"
  peers:
    - name: "节点B"
      url: "http://192.168.1.111:16869"
`)

	if err := UpdateClusterSection(path, Cluster{Name: "总部", Token: "shared"}); err != nil {
		t.Fatalf("UpdateClusterSection: %v", err)
	}

	got := readFile(t, path)
	if !strings.Contains(got, "peers: []") {
		t.Fatalf("空同伴应写成 peers: []：\n%s", got)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(got), &cfg); err != nil {
		t.Fatalf("写回的内容不是合法 yaml: %v", err)
	}
	if len(cfg.Cluster.Peers) != 0 {
		t.Fatalf("peers 应为空: %+v", cfg.Cluster.Peers)
	}
}

// ai 段与 cluster 段共用同一套「整块替换」逻辑：写 ai 不能动 cluster，反之亦然。
func TestUpdateAISection_ReplacesOnlyAIBlock(t *testing.T) {
	path := writeTempConfig(t, `server: :16868
ai:
  base_url: "http://old.example/v1"
  model: "old-model"
  api_key: "old-key"
  timeout_sec: 10
  max_tokens: 100

cluster:
  name: "总部"
  token: "shared"
  peers:
    - name: "阿里云"
      url: "http://101.201.70.97:16868"
`)

	err := UpdateAISection(path, AI{
		BaseURL:    "https://api.deepseek.com/v1/",
		Model:      "deepseek-chat",
		APIKey:     "sk-new",
		TimeoutSec: 90,
		MaxTokens:  2000,
	})
	if err != nil {
		t.Fatalf("UpdateAISection: %v", err)
	}

	got := readFile(t, path)
	if strings.Contains(got, "old-key") || strings.Contains(got, "old-model") {
		t.Fatalf("旧配置未被替换：\n%s", got)
	}
	if !strings.Contains(got, `base_url: "https://api.deepseek.com/v1"`) {
		t.Fatalf("地址应去掉结尾斜杠：\n%s", got)
	}
	if !strings.Contains(got, "cluster:") || !strings.Contains(got, "101.201.70.97") {
		t.Fatalf("cluster 段被破坏：\n%s", got)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(got), &cfg); err != nil {
		t.Fatalf("写回的内容不是合法 yaml: %v\n%s", err, got)
	}
	if cfg.AI.Model != "deepseek-chat" || cfg.AI.APIKey != "sk-new" || cfg.AI.TimeoutSec != 90 || cfg.AI.MaxTokens != 2000 {
		t.Fatalf("ai 段解析结果不对: %+v", cfg.AI)
	}
	if cfg.Cluster.Name != "总部" || len(cfg.Cluster.Peers) != 1 {
		t.Fatalf("cluster 段解析结果不对: %+v", cfg.Cluster)
	}
}

// curated 段同样整块替换：写会员配置不能动同文件里的其它段。
func TestUpdateCuratedSection_ReplacesOnlyCuratedBlock(t *testing.T) {
	path := writeTempConfig(t, `server: :16868
curated:
  enabled: "auto"
  endpoint: "http://old.example:8787/"
  timeout_sec: 10

cluster:
  name: "总部"
  token: "shared"
`)

	autoUpdate := false
	err := UpdateCuratedSection(path, Curated{
		Enabled:    "on",
		AutoUpdate: &autoUpdate,
		Endpoint:   "http://afrogx.com:8787/",
		TimeoutSec: 60,
		Channel:    "stable",
		LicenseKey: "LIC_12bee5652f92c526a9abcacc_63e4e54ffb18",
	})
	if err != nil {
		t.Fatalf("UpdateCuratedSection: %v", err)
	}

	got := readFile(t, path)
	if strings.Contains(got, "old.example") {
		t.Fatalf("旧配置未被替换：\n%s", got)
	}
	if !strings.Contains(got, `license_key: "LIC_12bee5652f92c526a9abcacc_63e4e54ffb18"`) {
		t.Fatalf("license 未写入：\n%s", got)
	}
	if !strings.Contains(got, "auto_update: false") || !strings.Contains(got, "timeout_sec: 60") {
		t.Fatalf("开关 / 超时未写入：\n%s", got)
	}
	if !strings.Contains(got, "cluster:") || !strings.Contains(got, "shared") {
		t.Fatalf("cluster 段被破坏：\n%s", got)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(got), &cfg); err != nil {
		t.Fatalf("写回的内容不是合法 yaml: %v\n%s", err, got)
	}
	if cfg.Curated.Enabled != "on" || cfg.Curated.TimeoutSec != 60 ||
		cfg.Curated.LicenseKey != "LIC_12bee5652f92c526a9abcacc_63e4e54ffb18" {
		t.Fatalf("curated 段解析结果不对: %+v", cfg.Curated)
	}
	if cfg.Curated.AutoUpdate == nil || *cfg.Curated.AutoUpdate {
		t.Fatalf("auto_update 应为 false: %+v", cfg.Curated.AutoUpdate)
	}
}
