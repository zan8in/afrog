// Package observation 定义 afrog 的观测事件契约：Agent 在扫描过程中「看到了什么」。
//
// 与 evidence 的分工：evidence 回答「某条命中凭什么成立」，observation 回答
// 「这台机器上还出现了什么」。事件只追加、不更新，用 seq 做游标，用内容寻址 id 去重：
// 同一事实在任何节点、任何任务、任何轮次里都得到同一个 obs_ id。
package observation

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/ref"
)

// Source 是观测的来源阶段。
const (
	SourcePortscan = "portscan"
	SourceWebscan  = "webscan"
	SourceHTTP     = "http"
	// SourcePassive 是被动代理看到用户真实流量的阶段。
	SourcePassive = "passive"
	// SourceOOB 是带外回连（反连平台）确认的阶段。
	SourceOOB = "oob"
)

// Kind 是观测的类型判别符。新增 kind 只能追加，不能改变已有 kind 的语义。
const (
	KindPortOpen        = "port_open"
	KindTech            = "tech"
	KindHTTPTransaction = "http_transaction"
	// KindHTTPPassive 是代理被动观察到的一次 HTTP 往返。
	//
	// 与 http_transaction 分开：后者描述 Agent 主动发起的动作（带 poc_id/matched），
	// 前者描述用户流量里出现过什么，只留元数据、不落报文。
	KindHTTPPassive = "http_passive"
	// KindTLS 是 https 目标的证书摘要。
	KindTLS = "tls"
	// KindOOBHit 是一次带外回连命中：目标真的解析/访问了反连地址。
	//
	// 它先于「漏洞命中」存在：回连是事实，是否由此判定漏洞是下游结论。
	KindOOBHit = "oob_hit"
)

const (
	// excerptLimit 是单个请求/响应片段的上限。观测流不存原始报文，
	// 只留足以判断「这是什么」的片段。
	excerptLimit = 2 * 1024
	// payloadLimit 是单条观测 payload 的上限，超出时先压片段再报错。
	payloadLimit = 32 * 1024
)

// Observation 是观测流里的一条事件。
type Observation struct {
	Seq       int64           `json:"seq"`
	ID        string          `json:"id"`
	ProjectID string          `json:"project_id"`
	Source    string          `json:"source"`
	Kind      string          `json:"kind"`
	Subject   string          `json:"subject"`
	Ts        string          `json:"ts"`
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"digest"`
}

// PortOpen 是 portscan 发现的一个开放端口。
type PortOpen struct {
	Port       int    `json:"port"`
	State      string `json:"state"`
	Service    string `json:"service,omitempty"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	Device     string `json:"device,omitempty"`
	OS         string `json:"os,omitempty"`
	CPE        string `json:"cpe,omitempty"`
	TLS        bool   `json:"tls,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Technology 是一条命中的 Web 指纹。
type Technology struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Tech 是一次 Web 指纹识别的结果。
type Tech struct {
	URL          string       `json:"url"`
	Status       int          `json:"status"`
	Title        string       `json:"title,omitempty"`
	Server       string       `json:"server,omitempty"`
	PoweredBy    string       `json:"powered_by,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	WAF          []string     `json:"waf,omitempty"`
	CDN          []string     `json:"cdn,omitempty"`
}

// HTTPTransaction 是一次 Agent 主动发起的 HTTP 往返。
//
// LatencyMs 不参与 id 计算：重放同一次请求得到同一 id，延迟抖动不该产生新事实。
type HTTPTransaction struct {
	Method          string `json:"method"`
	URL             string `json:"url"`
	Status          int    `json:"status"`
	Matched         bool   `json:"matched"`
	LatencyMs       int64  `json:"latency_ms"`
	RequestExcerpt  string `json:"request_excerpt,omitempty"`
	ResponseExcerpt string `json:"response_excerpt,omitempty"`
	PocID           string `json:"poc_id,omitempty"`
	Truncated       bool   `json:"truncated,omitempty"`
}

// New 构造一条观测并算出内容寻址 id 与 digest。
//
// 校验失败（未知 payload 类型、subject 为空、payload 超限）返回错误：
// 观测流宁可少一条，也不要写进无法解释的数据。
func New(projectID, source, kind, subject string, payload any) (*Observation, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("observation: subject is required")
	}
	canonicalBody, err := canonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	canonical := strings.Join([]string{projectID, source, kind, subject, canonicalBody}, "|")

	encoded, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	return &Observation{
		ID:        ref.Make(ref.KindObservation, canonical),
		ProjectID: projectID,
		Source:    source,
		Kind:      kind,
		Subject:   subject,
		Ts:        time.Now().UTC().Format(time.RFC3339),
		Payload:   encoded,
		Digest:    ref.Digest(canonical),
	}, nil
}

// HTTPPassive 是代理层被动看到的一次 HTTP 往返。
//
// 刻意只留元数据：被动流量里可能有登录凭据、业务数据，观测流不保存报文正文。
// 与 HTTPTransaction 的差别在于它没有判定义务（matched / poc_id），只是「看到过」。
type HTTPPassive struct {
	Method        string `json:"method"`
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentType   string `json:"content_type,omitempty"`
	RequestBytes  int    `json:"request_bytes,omitempty"`
	ResponseBytes int    `json:"response_bytes,omitempty"`
	Static        bool   `json:"static,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
}

// TLSCert 是 https 目标的服务端证书摘要。
//
// 只留判断所需的最小字段（谁签的、签给谁、什么时候过期），不落完整证书。
type TLSCert struct {
	URL      string   `json:"url"`
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
}

// OOBHit 是一次带外回连命中。
//
// Evidence 只留反连平台给的摘要，且不参与 id 计算：同一 filter 回连多次（不同源 IP、
// 不同时间）是同一事实，不该反复新增行。
type OOBHit struct {
	FilterType string `json:"filter_type"`
	Filter     string `json:"filter"`
	Token      string `json:"token,omitempty"`
	Target     string `json:"target"`
	PocID      string `json:"poc_id,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// HostPortSubject 把主机与端口拼成观测流的 subject。
func HostPortSubject(host string, port int) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// EndpointSubject 用归一化端点作为 subject；不是绝对 URL 时回退到原值。
func EndpointSubject(raw string) string {
	raw = strings.TrimSpace(raw)
	if normalized, err := ref.NormalizeEndpoint(raw); err == nil {
		return normalized
	}
	return raw
}

// canonicalPayload 返回 payload 里参与内容寻址的那部分。
//
// 显式列一份而不是「序列化整个结构体再删字段」：将来给 payload 加字段时，
// 必须先想清楚它是否稳定，否则 id 会随延迟、时间戳这类噪声漂移。
func canonicalPayload(payload any) (any, error) {
	switch v := payload.(type) {
	case PortOpen:
		return v, nil
	case Tech:
		// 指纹与 WAF/CDN 的命中顺序取决于规则扫描次序，排序后再算 id，
		// 避免同一份事实因为顺序不同而变成两条观测。
		sorted := v
		if len(v.Technologies) > 0 {
			sorted.Technologies = append([]Technology(nil), v.Technologies...)
			sort.Slice(sorted.Technologies, func(i, j int) bool {
				a, b := sorted.Technologies[i], sorted.Technologies[j]
				if a.Name != b.Name {
					return a.Name < b.Name
				}
				return a.Version < b.Version
			})
		}
		sorted.WAF = sortedStrings(v.WAF)
		sorted.CDN = sortedStrings(v.CDN)
		return sorted, nil
	case HTTPTransaction:
		return struct {
			Method  string `json:"method"`
			URL     string `json:"url"`
			Status  int    `json:"status"`
			Matched bool   `json:"matched"`
			PocID   string `json:"poc_id,omitempty"`
		}{v.Method, v.URL, v.Status, v.Matched, v.PocID}, nil
	case HTTPPassive:
		// 身份只看「方法 + 完整 URL + 状态码」：响应大小、耗时、Content-Type 会随
		// 每次请求抖动，把它们算进 id 会让同一事实反复新增行。
		return struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Status int    `json:"status"`
		}{v.Method, v.URL, v.Status}, nil
	case TLSCert:
		// SAN 的顺序取决于证书编码与解析实现，排序后再算 id。
		return struct {
			URL      string   `json:"url"`
			Subject  string   `json:"subject,omitempty"`
			Issuer   string   `json:"issuer,omitempty"`
			NotAfter string   `json:"not_after,omitempty"`
			DNSNames []string `json:"dns_names,omitempty"`
		}{v.URL, v.Subject, v.Issuer, v.NotAfter, sortedStrings(v.DNSNames)}, nil
	case OOBHit:
		// 回连摘要里带时间与来源 IP，每次回连都不同；身份只看到「哪个 filter 被目标
		// 打回来了、属于哪个 PoC」。
		return struct {
			FilterType string `json:"filter_type"`
			Filter     string `json:"filter"`
			Token      string `json:"token,omitempty"`
			Target     string `json:"target"`
			PocID      string `json:"poc_id,omitempty"`
		}{v.FilterType, v.Filter, v.Token, v.Target, v.PocID}, nil
	default:
		return nil, fmt.Errorf("observation: unsupported payload type %T", payload)
	}
}

// sortedStrings 返回排序后的副本，用于让 id 不依赖集合的遍历顺序。
func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func canonicalJSON(payload any) (string, error) {
	view, err := canonicalPayload(payload)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(view)
	if err != nil {
		return "", fmt.Errorf("observation: marshal canonical payload: %w", err)
	}
	return string(b), nil
}

// encodePayload 序列化落库用的 payload；超限时先把 HTTP 片段压到最小再试。
func encodePayload(payload any) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("observation: marshal payload: %w", err)
	}
	if len(b) <= payloadLimit {
		return json.RawMessage(b), nil
	}

	if t, ok := payload.(HTTPTransaction); ok {
		t.RequestExcerpt = Excerpt(t.RequestExcerpt, 256)
		t.ResponseExcerpt = Excerpt(t.ResponseExcerpt, 256)
		t.Truncated = true
		if b, err = json.Marshal(t); err == nil && len(b) <= payloadLimit {
			return json.RawMessage(b), nil
		}
	}
	return nil, fmt.Errorf("observation: payload exceeds %d bytes", payloadLimit)
}

// Excerpt 按 UTF-8 边界截断文本，并在末尾标注截断。
func Excerpt(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…[truncated]"
}

// ExcerptLimit 是对外暴露的片段上限，调用方据此截断请求/响应。
func ExcerptLimit() int { return excerptLimit }
