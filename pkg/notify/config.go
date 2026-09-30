// Package notify 提供 Web 端的扫描通知集成：渠道配置、消息组装与分发。
//
// 与 pkg/webhook 下的 CLI 逐条推送不同，这里的粒度是「扫描任务」：
// 一个任务结束时推汇总，运行中按阈值推高危命中，异常结束时推提醒。
package notify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// ChannelType 是通知渠道类型。
type ChannelType string

const (
	ChannelWebhook    ChannelType = "webhook"
	ChannelFeishu     ChannelType = "feishu"
	ChannelDingtalk   ChannelType = "dingtalk"
	ChannelWecom      ChannelType = "wecom"
	ChannelServerChan ChannelType = "serverchan"
)

// allChannelTypes 是渠道类型的展示顺序，前端按此渲染选项。
var allChannelTypes = []ChannelType{
	ChannelWebhook, ChannelFeishu, ChannelDingtalk, ChannelWecom, ChannelServerChan,
}

// AllChannelTypes 返回全部渠道类型。
func AllChannelTypes() []ChannelType {
	return append([]ChannelType(nil), allChannelTypes...)
}

func (t ChannelType) valid() bool {
	for _, c := range allChannelTypes {
		if c == t {
			return true
		}
	}
	return false
}

// defaultMaxPerTask 是单任务实时推送的默认上限。
const defaultMaxPerTask = 20

// maxMaxPerTask 防止把上限配得过大导致刷屏。
const maxMaxPerTask = 200

// Channel 是一个通知渠道的配置。
type Channel struct {
	ID      string      `json:"id"`
	Type    ChannelType `json:"type"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	// Target 是渠道凭据，按类型含义不同：
	//   webhook    完整 URL
	//   feishu     机器人 webhook 完整 URL
	//   dingtalk   机器人 access_token
	//   wecom      机器人 key
	//   serverchan SendKey
	Target string `json:"target"`
	// AtMobiles / AtAll 仅钉钉、企微生效。
	AtMobiles []string `json:"at_mobiles,omitempty"`
	AtAll     bool     `json:"at_all,omitempty"`
}

// Events 是事件开关。
type Events struct {
	TaskCompleted bool `json:"task_completed"`
	VulnFound     bool `json:"vuln_found"`
	TaskFailed    bool `json:"task_failed"`
}

// Config 是通知集成的完整配置。
type Config struct {
	// Enabled 是总开关；关闭时不发送任何消息。
	Enabled bool   `json:"enabled"`
	Events  Events `json:"events"`
	// Severity 是「实时逐条」的严重级别阈值。
	Severity []string `json:"severity"`
	// MaxPerTask 限制单个任务实时推送条数，避免刷屏。
	MaxPerTask int       `json:"max_per_task"`
	Channels   []Channel `json:"channels"`
	// ProjectIDs 是「按项目订阅」白名单：留空表示所有任务都推；
	// 一旦配置，只有归属这些项目的任务才会推送，不属于任何项目的任务不推。
	ProjectIDs []string `json:"project_ids"`
}

// DefaultConfig 返回默认配置：事件全开、阈值 high/critical、单任务最多 20 条、
// 不限项目，但不含任何渠道（因此实际不会发送，避免用户没配就被推送）。
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Events: Events{
			TaskCompleted: true,
			VulnFound:     true,
			TaskFailed:    true,
		},
		Severity:   []string{"critical", "high"},
		MaxPerTask: defaultMaxPerTask,
		Channels:   []Channel{},
		ProjectIDs: []string{},
	}
}

var configMu sync.Mutex

func configFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	return filepath.Join(dir, "notifications.json"), nil
}

// Load 读取配置；文件不存在时返回默认配置。
func Load() (Config, error) {
	configMu.Lock()
	defer configMu.Unlock()
	return loadLocked()
}

func loadLocked() (Config, error) {
	path, err := configFilePath()
	if err != nil {
		return DefaultConfig(), err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return DefaultConfig(), err
	}

	cfg := DefaultConfig()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return DefaultConfig(), fmt.Errorf("parse notifications config: %w", err)
		}
	}
	normalize(&cfg)
	return cfg, nil
}

// Save 校验并原子写入配置。
func Save(cfg Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	normalize(&cfg)

	path, err := configFilePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// normalize 清洗配置：补齐缺失字段、丢弃无效渠道、收敛数值范围。
func normalize(cfg *Config) {
	cfg.Severity = normalizeSeverities(cfg.Severity)
	if len(cfg.Severity) == 0 {
		cfg.Severity = append([]string(nil), DefaultConfig().Severity...)
	}

	if cfg.MaxPerTask <= 0 {
		cfg.MaxPerTask = defaultMaxPerTask
	}
	if cfg.MaxPerTask > maxMaxPerTask {
		cfg.MaxPerTask = maxMaxPerTask
	}

	// 项目白名单清洗后保证是「非 nil 的空切片」：nil 会被序列化成 null，
	// 前端按数组遍历会直接崩掉渲染。
	cfg.ProjectIDs = normalizeIDList(cfg.ProjectIDs)

	channels := make([]Channel, 0, len(cfg.Channels))
	seen := make(map[string]struct{}, len(cfg.Channels))
	for _, ch := range cfg.Channels {
		ch.Type = ChannelType(strings.ToLower(strings.TrimSpace(string(ch.Type))))
		ch.Target = strings.TrimSpace(ch.Target)
		ch.Name = strings.TrimSpace(ch.Name)
		// 没有类型或没有凭据的渠道无法发送，直接丢弃而不是留个坏配置。
		if !ch.Type.valid() || ch.Target == "" {
			continue
		}
		ch.ID = strings.TrimSpace(ch.ID)
		if ch.ID == "" {
			ch.ID = "n_" + utils.CreateRandomString(12)
		}
		if _, dup := seen[ch.ID]; dup {
			ch.ID = "n_" + utils.CreateRandomString(12)
		}
		seen[ch.ID] = struct{}{}
		if ch.Name == "" {
			ch.Name = string(ch.Type)
		}
		ch.AtMobiles = normalizeStringList(ch.AtMobiles)
		channels = append(channels, ch)
	}
	cfg.Channels = channels
}

// severityRank 定义已知严重级别，未知值一律丢弃。
var severityRank = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

func normalizeSeverities(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" || !severityRank[v] {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeStringList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// normalizeIDList 清洗 ID 列表：去空白、丢空项、去重。
func normalizeIDList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		t := strings.TrimSpace(v)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
