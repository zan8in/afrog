package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

// errOOBUnavailable 是「工具面没有可用的反连后端」时的统一错误。
//
// fail-closed：没配置 OOB 就不铸地址、不等待，直接告诉调用方缺什么，而不是静默等一个
// 永远不会来的回连。
var errOOBUnavailable = errors.New("oob not configured: set agent.oob and the reverse credentials in afrog-config.yaml")

// OOBSource 是工具面需要的带外（反连）能力：铸一组反连地址、等待回连、取证据。
//
// 定义成窄接口而不是直接暴露 runner.OOBManager：工具面只依赖这三件事，单测因此可以
// 用假实现，不必起真的反连平台。
type OOBSource interface {
	// Payload 铸一组新的反连地址，并开始监听回连。
	Payload() (OOBPayload, error)
	// Wait 在 timeout 内等待该 filter 的回连；true 表示命中。
	Wait(filter, filterType string, timeout time.Duration) bool
	// Hit 取一次已确认回连的细节（无命中返回 false）。
	Hit(filter, filterType string) (OOBHit, bool)
	// Close 停止后台轮询。
	Close()
}

// OOBPayload 是一组反连地址：把 dns / http 注进目标请求，再用 filter + filter_type 等待。
type OOBPayload struct {
	Filter string `json:"filter"`
	DNS    string `json:"dns"`
	HTTP   string `json:"http"`
	JNDI   string `json:"jndi,omitempty"`
	RMI    string `json:"rmi,omitempty"`
	LDAP   string `json:"ldap,omitempty"`
}

// OOBHit 是一次已确认的回连及其证据。
type OOBHit struct {
	Filter     string `json:"filter"`
	FilterType string `json:"filter_type"`
	Count      uint64 `json:"count"`
	LastAt     string `json:"last_at,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// payloadWatches 是铸载荷时预先监听的 filter 类型。
//
// DNS 与 HTTP 是绝大多数回连的落点；先登记好，目标在 Agent 调用 act.oob_wait 之前
// 就回连也不会漏——命中会先被轮询循环记下来，Wait 再查时立刻返回。
var payloadWatches = []string{oobadapter.OOBDNS, oobadapter.OOBHTTP}

// DefaultOOBPollInterval / DefaultOOBHitRetention 与引擎侧的口径保持一致。
const (
	DefaultOOBPollInterval = time.Second
	DefaultOOBHitRetention = 10 * time.Minute
)

// NewOOBSource 按适配器名与 reverse 凭据构造常驻反连后端。
//
// adapter 为空、取值未识别或凭据未配置时返回 (nil, nil)：工具面据此 fail-closed。
// 直接连不通适配器（凭据格式非法等）时才返回错误，避免「配错了却以为没配」。
func NewOOBSource(adapter string, reverse config.Reverse) (OOBSource, error) {
	p, ok := config.ResolveOOBConnector(adapter, reverse)
	if !ok {
		return nil, nil
	}
	client, err := oobadapter.NewOOBAdapter(p.Adapter, &oobadapter.ConnectorParams{
		Key:     p.Key,
		Domain:  p.Domain,
		HTTPUrl: p.HTTPURL,
		ApiUrl:  p.APIURL,
	})
	if err != nil {
		return nil, fmt.Errorf("init oob adapter %s: %w", p.Adapter, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &oobSource{
		adapter: client,
		mgr:     runner.NewOOBManager(ctx, client, DefaultOOBPollInterval, DefaultOOBHitRetention),
		cancel:  cancel,
	}, nil
}

type oobSource struct {
	adapter *oobadapter.OOBAdapter
	mgr     *runner.OOBManager
	cancel  context.CancelFunc
}

func (s *oobSource) Payload() (OOBPayload, error) {
	if s == nil || s.adapter == nil {
		return OOBPayload{}, errOOBUnavailable
	}
	d := s.adapter.GetValidationDomain()
	if strings.TrimSpace(d.Filter) == "" {
		return OOBPayload{}, errors.New("oob: adapter returned an empty filter")
	}
	for _, ft := range payloadWatches {
		s.mgr.Watch(d.Filter, ft)
	}
	return OOBPayload{
		Filter: d.Filter,
		DNS:    d.DNS,
		HTTP:   d.HTTP,
		JNDI:   d.JNDI,
		RMI:    d.RMI,
		LDAP:   d.LDAP,
	}, nil
}

func (s *oobSource) Wait(filter, filterType string, timeout time.Duration) bool {
	if s == nil || s.mgr == nil {
		return false
	}
	return s.mgr.Wait(filter, filterType, timeout)
}

func (s *oobSource) Hit(filter, filterType string) (OOBHit, bool) {
	if s == nil || s.mgr == nil {
		return OOBHit{}, false
	}
	snap, ok := s.mgr.HitSnapshot(filter, filterType)
	if !ok {
		return OOBHit{}, false
	}
	hit := OOBHit{
		Filter:     snap.Filter,
		FilterType: snap.FilterType,
		Count:      snap.Count,
		Evidence:   s.mgr.Evidence(filter, filterType, 5),
	}
	if !snap.LastAt.IsZero() {
		hit.LastAt = snap.LastAt.UTC().Format(time.RFC3339Nano)
	}
	return hit, true
}

func (s *oobSource) Close() {
	if s == nil || s.mgr == nil {
		return
	}
	s.cancel()
	s.mgr.Stop()
}

// waitOOB 给 Wait 套一层取消：OOBManager.Wait 本身不认 ctx，调用方被取消时不该干等满超时。
//
// 取消后等待协程仍会跑到 timeout 才退出——它有界（最多一个 timeout），不泄漏。
func waitOOB(ctx context.Context, src OOBSource, filter, filterType string, timeout time.Duration) bool {
	done := make(chan bool, 1)
	go func() { done <- src.Wait(filter, filterType, timeout) }()
	select {
	case ok := <-done:
		return ok
	case <-ctx.Done():
		return false
	}
}

// act.oob_wait 的等待上限；默认 30 秒，最长 5 分钟。
const (
	defaultOOBWaitSec = 30
	maxOOBWaitSec     = 300
)

// --- act.oob_payload ---

func (s *Server) actOOBPayloadTool() *Tool {
	return &Tool{
		Name:        "act.oob_payload",
		Description: "【需要 exec 能力】铸一组带外（反连）地址并开始监听回连。把 dns / http 注入目标请求后，用 act.oob_wait 等回连；需要 afrog-config.yaml 配置 agent.oob 与 reverse 凭据。",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
			"required":   []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := s.gate.Take(policy.Action{
				Name:       "act.oob_payload",
				Capability: capability.Exec,
			}, 0); err != nil {
				return nil, err
			}
			if s.oob == nil {
				return nil, errOOBUnavailable
			}
			return s.oob.Payload()
		},
	}
}

// --- act.oob_wait ---

func (s *Server) actOOBWaitTool() *Tool {
	type args struct {
		Filter     string `json:"filter"`
		FilterType string `json:"filter_type"`
		TimeoutSec int    `json:"timeout_sec"`
		Target     string `json:"target"`
		ProjectID  string `json:"project_id"`
	}
	return &Tool{
		Name:        "act.oob_wait",
		Description: "【需要 exec 能力】等待 act.oob_payload 铸出的反连地址回连。命中返回 hit=true 与证据，并把这次回连写进观测流（oob_hit）；超时返回 hit=false。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"filter":      map[string]any{"type": "string", "description": "act.oob_payload 返回的 filter"},
				"filter_type": map[string]any{"type": "string", "enum": []string{oobadapter.OOBDNS, oobadapter.OOBHTTP}, "description": "回连协议，默认 dns"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 1, "maximum": maxOOBWaitSec, "description": fmt.Sprintf("等待上限（秒），默认 %d", defaultOOBWaitSec)},
				"target":      map[string]any{"type": "string", "description": "反连地址被注入到的目标，用于观测流的 subject"},
				"project_id":  map[string]any{"type": "string", "description": "观测流归属的项目 ID；留空表示全局"},
			},
			"required": []string{"filter"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			filter := strings.TrimSpace(a.Filter)
			if filter == "" {
				return nil, fmt.Errorf("filter is required")
			}
			filterType, err := normalizeOOBFilterType(a.FilterType)
			if err != nil {
				return nil, err
			}
			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = defaultOOBWaitSec * time.Second
			}
			if timeout > maxOOBWaitSec*time.Second {
				timeout = maxOOBWaitSec * time.Second
			}
			target := strings.TrimSpace(a.Target)

			if err := s.gate.Take(policy.Action{
				Name:       "act.oob_wait",
				Target:     target,
				Capability: capability.Exec,
			}, 0); err != nil {
				return nil, err
			}
			if s.oob == nil {
				return nil, errOOBUnavailable
			}

			if !waitOOB(ctx, s.oob, filter, filterType, timeout) {
				return map[string]any{"hit": false, "filter": filter, "filter_type": filterType}, nil
			}
			hit, _ := s.oob.Hit(filter, filterType)
			recordOOBObservation(a.ProjectID, target, filterType, filter, hit.Evidence)
			return map[string]any{
				"hit":         true,
				"filter":      filter,
				"filter_type": filterType,
				"count":       hit.Count,
				"last_at":     hit.LastAt,
				"evidence":    hit.Evidence,
			}, nil
		},
	}
}

func normalizeOOBFilterType(raw string) (string, error) {
	ft := strings.ToLower(strings.TrimSpace(raw))
	switch ft {
	case "":
		return oobadapter.OOBDNS, nil
	case oobadapter.OOBDNS, oobadapter.OOBHTTP:
		return ft, nil
	default:
		return "", fmt.Errorf("filter_type must be %q or %q", oobadapter.OOBDNS, oobadapter.OOBHTTP)
	}
}

// recordOOBObservation 把一次带外回连写进观测流。
//
// 与引擎侧同名函数同一口径：回连是「目标确实解析/访问了反连地址」这一事实，不取决于
// 下游是否把它判成漏洞。摘要做截断——观测流不承载完整回连记录。
func recordOOBObservation(projectID, target, filterType, filter, evidence string) {
	subject := observation.EndpointSubject(target)
	if strings.TrimSpace(subject) == "" {
		subject = filter
	}
	obs, err := observation.New(projectID, observation.SourceOOB, observation.KindOOBHit, subject, observation.OOBHit{
		FilterType: filterType,
		Filter:     filter,
		Target:     target,
		Evidence:   observation.Excerpt(evidence, observation.ExcerptLimit()),
	})
	if err != nil {
		return
	}
	sqlite.RecordObservation(obs)
}
