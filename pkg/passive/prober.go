package passive

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// ProberOptions 控制重放行为。
//
// 默认值刻意保守：被动扫描的重放流量全部叠加在用户真实业务流量之上，
// 参数过于激进会直接影响用户网络（NAT 会话表、带宽），因此宁可慢一点。
type ProberOptions struct {
	// Timeout 是单次重放的超时。
	Timeout time.Duration
	// MaxBodyBytes 是单个响应体的读取上限，超出部分丢弃。
	MaxBodyBytes int64
	// HostConcurrency 是单目标的并发上限。
	HostConcurrency int
	// GlobalRPS 是全局重放速率上限（每秒请求数），<=0 表示不限。
	GlobalRPS int
	// Upstream 是上游代理；为空表示直连。
	Upstream *url.URL
}

// DefaultProberOptions 返回保守的默认配置。
func DefaultProberOptions() ProberOptions {
	return ProberOptions{
		Timeout:         15 * time.Second,
		MaxBodyBytes:    2 << 20, // 2MB
		HostConcurrency: 4,
		GlobalRPS:       100,
	}
}

// HTTPProber 是 Prober 的默认实现。
//
// 它刻意不暴露底层 http.Client：检测器只能通过 Replay/Mutate 发请求，
// 从而无法绕过并发与速率治理。
type HTTPProber struct {
	opts   ProberOptions
	client *http.Client
	gates  *hostGate
	lim    *rateLimiter
}

// NewHTTPProber 创建一个受控重放器。
func NewHTTPProber(opts ProberOptions) *HTTPProber {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 2 << 20
	}
	if opts.HostConcurrency <= 0 {
		opts.HostConcurrency = 4
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: opts.HostConcurrency,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if opts.Upstream != nil {
		u := opts.Upstream
		transport.Proxy = http.ProxyURL(u)
	}

	return &HTTPProber{
		opts: opts,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			// 重定向必须关闭：布尔差分依赖对同一次请求的直接响应，
			// 跟随跳转会把不同语义的页面混为一谈。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		gates: newHostGate(opts.HostConcurrency),
		lim:   newRateLimiter(opts.GlobalRPS),
	}
}

// Replay 原样重放事务。
func (p *HTTPProber) Replay(ctx context.Context, tx *CapturedTransaction) (*CapturedResponse, error) {
	return p.do(ctx, tx, nil)
}

// Mutate 替换指定注入点后重放。
func (p *HTTPProber) Mutate(ctx context.Context, tx *CapturedTransaction, m Mutation) (*CapturedResponse, error) {
	return p.do(ctx, tx, &m)
}

func (p *HTTPProber) do(ctx context.Context, tx *CapturedTransaction, m *Mutation) (*CapturedResponse, error) {
	if tx == nil || tx.Request == nil || tx.Request.URL == nil {
		return nil, errors.New("passive: empty transaction")
	}

	req := tx.Request.Clone()
	if m != nil {
		if err := ApplyMutation(req, *m); err != nil {
			return nil, err
		}
	}

	httpReq, err := buildHTTPRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	host := req.URL.Host
	release, err := p.gates.acquire(ctx, host)
	if err != nil {
		return nil, err
	}
	defer release()

	if err := p.lim.wait(ctx); err != nil {
		return nil, err
	}

	start := time.Now()
	res, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, p.opts.MaxBodyBytes))
	duration := time.Since(start)
	if err != nil && len(body) == 0 {
		return nil, err
	}

	return &CapturedResponse{
		Status:   res.StatusCode,
		Headers:  res.Header.Clone(),
		Body:     body,
		Duration: duration,
	}, nil
}

// hopByHopHeaders 是重放时需要剔除的连接级头部。
// 原样转发会导致请求语义被上一跳的连接状态污染。
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func buildHTTPRequest(ctx context.Context, cr *CapturedRequest) (*http.Request, error) {
	if cr.URL == nil {
		return nil, errors.New("passive: request url is nil")
	}

	var body io.Reader
	if len(cr.Body) > 0 {
		body = bytes.NewReader(cr.Body)
	}

	req, err := http.NewRequestWithContext(ctx, cr.Method, cr.URL.String(), body)
	if err != nil {
		return nil, err
	}

	for k, vs := range cr.Headers {
		canonical := http.CanonicalHeaderKey(k)
		if isHopByHop(canonical) {
			continue
		}
		// Accept-Encoding 交给 Transport 处理，才能获得自动解压。
		if canonical == "Accept-Encoding" {
			continue
		}
		// Content-Length 由 Go 按实际 body 重算，保留原值会与变异后的 body 冲突。
		if canonical == "Content-Length" {
			continue
		}
		for _, v := range vs {
			req.Header.Add(canonical, v)
		}
	}

	// Host 头决定虚拟主机路由，必须显式还原。
	if h := cr.Headers.Get("Host"); h != "" {
		req.Host = h
	}
	if len(cr.Body) > 0 {
		req.ContentLength = int64(len(cr.Body))
		req.Header.Set("Content-Length", strconv.Itoa(len(cr.Body)))
	}

	return req, nil
}

func isHopByHop(h string) bool {
	for _, v := range hopByHopHeaders {
		if h == v {
			return true
		}
	}
	return false
}

// hostGate 限制单目标并发，避免对同一站点瞬间打出过多连接。
type hostGate struct {
	size int
	mu   sync.Mutex
	m    map[string]chan struct{}
}

func newHostGate(size int) *hostGate {
	return &hostGate{size: size, m: make(map[string]chan struct{})}
}

func (g *hostGate) acquire(ctx context.Context, host string) (func(), error) {
	g.mu.Lock()
	ch, ok := g.m[host]
	if !ok {
		ch = make(chan struct{}, g.size)
		g.m[host] = ch
	}
	g.mu.Unlock()

	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// rateLimiter 是全局固定间隔限速器。
//
// 用固定间隔而非令牌桶，是因为被动检测的请求量本身不可预测，固定间隔能给出
// 明确的上界（1/interval 每秒），更容易向用户解释与配置。
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	if rps <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Second / time.Duration(rps)}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r.interval <= 0 {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	d := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()

	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RawHTTPDump 把事务还原成可读的 HTTP 原文，用于证据留档。
func RawHTTPDump(req *CapturedRequest, res *CapturedResponse) ([]byte, []byte) {
	var reqBuf bytes.Buffer
	if req != nil && req.URL != nil {
		fmt.Fprintf(&reqBuf, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
		fmt.Fprintf(&reqBuf, "Host: %s\r\n", req.URL.Host)
		for k, vs := range req.Headers {
			if http.CanonicalHeaderKey(k) == "Host" {
				continue
			}
			for _, v := range vs {
				fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
			}
		}
		reqBuf.WriteString("\r\n")
		reqBuf.Write(req.Body)
	}

	var resBuf bytes.Buffer
	if res != nil {
		fmt.Fprintf(&resBuf, "HTTP/1.1 %d\r\n", res.Status)
		for k, vs := range res.Headers {
			for _, v := range vs {
				fmt.Fprintf(&resBuf, "%s: %s\r\n", k, v)
			}
		}
		resBuf.WriteString("\r\n")
		resBuf.Write(res.Body)
	}

	return reqBuf.Bytes(), resBuf.Bytes()
}
