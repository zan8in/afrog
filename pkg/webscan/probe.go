package webscan

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// Web 探测的默认值，调用方通过 ProbeOptions 覆盖。
const (
	// DefaultProbeTimeout 是单次请求的整体超时。
	DefaultProbeTimeout = 15 * time.Second
	// DefaultProbeMaxRedirects 是最多跟随的跳转次数。
	DefaultProbeMaxRedirects = 10
	// DefaultProbeBodyLimit 是首页正文读取上限（2 MiB）。
	DefaultProbeBodyLimit = 2 << 20
	// DefaultFaviconLimit 是 favicon 读取上限（1 MiB）。
	DefaultFaviconLimit = 1 << 20
)

// TLSInfo 是 https 目标的证书摘要，只保留「这家站是谁签的、什么时候过期」所需的最小字段。
//
// 三端（CLI/Web/MCP）共用这一份，避免各自解析证书得出不同的 subject/issuer 写法。
type TLSInfo struct {
	Subject  string
	Issuer   string
	NotAfter string
	DNSNames []string
}

// ProbeOptions 是一次 Web 探测的抓取参数；零值字段用默认值补齐。
type ProbeOptions struct {
	// Timeout 是单次请求的整体超时。
	Timeout time.Duration
	// MaxRedirects 是最多跟随的跳转次数。
	MaxRedirects int
	// BodyLimit 是首页正文读取上限（字节）。
	BodyLimit int64
	// FaviconLimit 是 favicon 读取上限（字节）。
	FaviconLimit int64
	// UserAgent 为空时随机取一个常见浏览器 UA。
	UserAgent string
	// Headers 是额外的请求头，形如 "Key: Value"，与 CLI -H 同口径。
	Headers []string
	// Proxy 是代理地址，空表示直连；多个代理时取第一个。
	Proxy string
	// InsecureSkipVerify 为真时跳过证书校验——扫描器语义：证书是否可信交给使用者判断。
	InsecureSkipVerify bool
}

// ProbeResult 是一次 Web 探测的素材，可直接转成指纹匹配输入。
type ProbeResult struct {
	// URL 是发起请求的原始 URL。
	URL string
	// FinalURL 是跟随跳转后的最终 URL，无跳转时等于 URL。
	FinalURL string
	// Proto 是响应的 HTTP 协议版本（如 HTTP/1.1）。
	Proto string
	// Status 是最终响应的 HTTP 状态码。
	Status int
	// Headers 是响应头，键名小写；同名多值以 ", " 连接。
	Headers map[string]string
	// Body 是响应正文（受 BodyLimit 限制）。
	Body []byte
	// Cookies 是原始 Set-Cookie 行。
	Cookies []string
	// Redirects 是初始 URL 之后每一次跳转的落点，无跳转时为空。
	Redirects []string
	// Title 是页面标题（已解码 HTML 实体、归一化空白）。
	Title string
	// TLS 是 https 目标的证书摘要；非 https 或握手失败时为空。
	TLS *TLSInfo
}

// Response 把探测素材转成指纹匹配输入。
//
// 不含 favicon：favicon 需调用方按自己的策略（开关或兜底）另抓后填入。
func (r *ProbeResult) Response() Response {
	if r == nil {
		return Response{}
	}
	return Response{
		StatusCode: r.Status,
		Headers:    r.Headers,
		Body:       r.Body,
		Cookies:    r.Cookies,
		RequestURL: r.FinalURL,
	}
}

// Prober 是可复用的 Web 探测器。
//
// 内部持有一个 HTTP 客户端（连接可复用），承载一次探测的超时、跳转上限、UA/自定义头、
// 代理与 TLS 策略。它是「抓首页 → 组装指纹素材 → 抓 favicon」这条链路的唯一实现：
// CLI 与 MCP 各自构造一个 Prober 再调用 Probe / FetchFavicon，不再各写一份抓取逻辑。
//
// 并发安全：CheckRedirect 是客户端级回调，跳转落点通过 context 携带，因此同一个
// Prober 可被多个 worker 并发使用而互不串扰。
type Prober struct {
	client *http.Client
	opts   ProbeOptions
}

// NewProber 按选项构造探测器，零值字段用默认值补齐。
func NewProber(opts ProbeOptions) *Prober {
	opts = withProbeDefaults(opts)
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if p := strings.TrimSpace(strings.Split(opts.Proxy, ",")[0]); p != "" {
		if u, err := url.Parse(p); err == nil && u.Host != "" {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &Prober{
		opts: opts,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if trace, ok := req.Context().Value(redirectTraceKey{}).(*redirectTrace); ok {
					trace.add(req.URL.String())
				}
				if len(via) >= opts.MaxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func withProbeDefaults(o ProbeOptions) ProbeOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultProbeTimeout
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultProbeMaxRedirects
	}
	if o.BodyLimit <= 0 {
		o.BodyLimit = DefaultProbeBodyLimit
	}
	if o.FaviconLimit <= 0 {
		o.FaviconLimit = DefaultFaviconLimit
	}
	return o
}

// Probe 对 rawURL 做一次 GET：跟随跳转、收集跳转链与证书，读回正文与 Cookie。
//
// 返回的 error 表示「没有拿到响应」（连接失败、超时等），此时 result 为 nil。
func (p *Prober) Probe(ctx context.Context, rawURL string) (*ProbeResult, error) {
	if p == nil {
		return nil, errors.New("webscan: nil prober")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	trace := &redirectTrace{}
	req = req.WithContext(context.WithValue(req.Context(), redirectTraceKey{}, trace))
	p.applyHeaders(req)

	resp, err := p.client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.opts.BodyLimit))

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &ProbeResult{
		URL:       rawURL,
		FinalURL:  finalURL,
		Proto:     resp.Proto,
		Status:    resp.StatusCode,
		Headers:   headers,
		Body:      body,
		Cookies:   resp.Header.Values("Set-Cookie"),
		Redirects: trace.result(),
		Title:     Title(body),
		TLS:       tlsInfoFromState(resp.TLS),
	}, nil
}

// FetchFavicon 抓一次 /favicon.ico。
//
// 非 200、为空或超过 FaviconLimit 都返回 nil——失败只影响 favicon 规则，不影响主结果。
func (p *Prober) FetchFavicon(ctx context.Context, rawURL string) []byte {
	if p == nil {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil
	}
	u.Path = "/favicon.ico"
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}
	p.applyHeaders(req)
	resp, err := p.client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.opts.FaviconLimit+1))
	if len(body) == 0 || int64(len(body)) > p.opts.FaviconLimit {
		return nil
	}
	return body
}

// applyHeaders 把自定义头与 UA 加到请求上。
//
// UA 缺省随机取一个常见浏览器 UA，使探测请求的外发特征与 PoC 请求一致
// （否则 WAF 按 UA 就把探测挡了）。
func (p *Prober) applyHeaders(req *http.Request) {
	if req == nil {
		return
	}
	for _, line := range p.opts.Headers {
		key, val, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		if strings.EqualFold(key, "Host") {
			req.Host = strings.TrimSpace(val)
			continue
		}
		req.Header.Set(key, strings.TrimSpace(val))
	}
	if req.Header.Get("User-Agent") == "" {
		ua := strings.TrimSpace(p.opts.UserAgent)
		if ua == "" {
			ua = utils.RandomUA()
		}
		req.Header.Set("User-Agent", ua)
	}
}

// redirectTraceKey 用于把跳转落点收集器塞进探测请求的 context。
//
// http.Client 的 CheckRedirect 是「客户端级」回调，一次探测要拿到自己的跳转链，
// 只能靠 context 把收集器带进去，否则并发探测下几个目标的链会搅在一起。
type redirectTraceKey struct{}

// redirectTrace 收集一次探测里每一次跳转的落点（不含初始 URL）。
type redirectTrace struct {
	mu   sync.Mutex
	urls []string
}

func (t *redirectTrace) add(u string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.urls = append(t.urls, u)
	t.mu.Unlock()
}

func (t *redirectTrace) result() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.urls) == 0 {
		return nil
	}
	return append([]string(nil), t.urls...)
}

// tlsInfoFromState 从一次 TLS 握手结果里提取证书摘要，没有证书时返回 nil。
func tlsInfoFromState(state *tls.ConnectionState) *TLSInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	subject := strings.TrimSpace(leaf.Subject.CommonName)
	if subject == "" {
		subject = leaf.Subject.String()
	}
	// 签发者取组织名（Let's Encrypt、DigiCert Inc…）比取 CN 更贴近「谁签的」这个问题。
	issuer := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(leaf.Issuer.Organization[0])
	}
	if issuer == "" {
		issuer = strings.TrimSpace(leaf.Issuer.CommonName)
	}
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}
	return &TLSInfo{
		Subject:  subject,
		Issuer:   issuer,
		NotAfter: leaf.NotAfter.Format("2006-01-02"),
		DNSNames: append([]string(nil), leaf.DNSNames...),
	}
}
