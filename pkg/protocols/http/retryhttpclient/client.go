package retryhttpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/retryablehttp"
	retryablehttpurlutil "github.com/zan8in/retryablehttp/pkg/utils/urlutil"
)

var (
	RtryRedirect   *retryablehttp.Client
	RtryNoRedirect *retryablehttp.Client

	defaultTimeout = 50 * time.Second

	maxDefaultBody int64

	defaultAccept bool

	reqLimiter *hostPortLimiter

	httpInflight      int64
	rawInflight       int64
	netInflight       int64
	reqLimitWaitNs    int64
	reqLimitWaitCount int64
	taskGateWaitNs    int64
	taskGateWaitCount int64
)

type Options struct {
	Proxy             string
	Timeout           int
	Retries           int
	MaxRespBodySize   int
	ReqLimitPerTarget int
	DefaultAccept     bool
}

const ContextVarKey = "__ctx"

func ContextFromVariableMap(variableMap map[string]any) context.Context {
	if variableMap == nil {
		return nil
	}
	if v, ok := variableMap[ContextVarKey]; ok && v != nil {
		if ctx, ok := v.(context.Context); ok {
			return ctx
		}
	}
	return nil
}

func IsCriticalHeader(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "host", "cookie", "authorization", "user-agent", "content-type", "accept":
		return true
	default:
		return false
	}
}

func ApplyHeaderLines(req *retryablehttp.Request, headerLines []string, overwrite bool) {
	if req == nil || len(headerLines) == 0 {
		return
	}
	for _, line := range headerLines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		if strings.EqualFold(key, "Host") {
			req.Request.Host = val
			continue
		}
		if overwrite {
			req.Header.Set(key, val)
			continue
		}
		if IsCriticalHeader(key) || req.Header.Get(key) == "" {
			req.Header.Set(key, val)
		} else {
			req.Header.Add(key, val)
		}
	}
}

func Init(opt *Options) (err error) {
	po := &retryablehttp.DefaultPoolOptions
	// 避免上游 SDK 在处理代理列表时触发并发通道错误，先不让池初始化解析代理
	// 后续我们在拿到客户端后手动设置 http.Transport 的代理
	po.Proxy = ""
	po.Timeout = opt.Timeout
	po.Retries = opt.Retries
	po.DisableRedirects = true

	// -timeout 参数默认是 50s @editor 2024/11/03
	defaultTimeout = time.Duration(opt.Timeout) * time.Second
	defaultAccept = opt.DefaultAccept

	// 保持查询参数顺序，避免因重新排序导致的漏洞触发失败 @editor 2025/11/25
	retryablehttpurlutil.PreserveQueryOrder = true

	retryablehttp.InitClientPool(po)
	if RtryNoRedirect, err = retryablehttp.GetPool(po); err != nil {
		return err
	}

	po.DisableRedirects = false
	po.EnableRedirect(retryablehttp.FollowAllRedirect)
	retryablehttp.InitClientPool(po)
	if RtryRedirect, err = retryablehttp.GetPool(po); err != nil {
		return err
	}

	// 如果设置了代理，手动配置到 http.Transport，支持 http/https
	if len(strings.TrimSpace(opt.Proxy)) > 0 {
		if u, perr := url.Parse(opt.Proxy); perr == nil {
			switch strings.ToLower(u.Scheme) {
			case "http", "https", "socks5":
				if RtryNoRedirect != nil && RtryNoRedirect.HTTPClient != nil {
					if t, ok := RtryNoRedirect.HTTPClient.Transport.(*http.Transport); ok {
						t.Proxy = http.ProxyURL(u)
						if t.TLSClientConfig == nil {
							t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
						} else {
							t.TLSClientConfig.InsecureSkipVerify = true
						}
					}
				}
				if RtryRedirect != nil && RtryRedirect.HTTPClient != nil {
					if t, ok := RtryRedirect.HTTPClient.Transport.(*http.Transport); ok {
						t.Proxy = http.ProxyURL(u)
						if t.TLSClientConfig == nil {
							t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
						} else {
							t.TLSClientConfig.InsecureSkipVerify = true
						}
					}
				}
			}
		}
	}

	maxDefaultBody = int64(opt.MaxRespBodySize * 1024 * 1024)

	if opt.ReqLimitPerTarget > 0 {
		reqLimiter = newHostPortLimiter(opt.ReqLimitPerTarget)
	} else {
		reqLimiter = nil
	}
	applyReqLimitTransport(RtryNoRedirect)
	applyReqLimitTransport(RtryRedirect)

	return nil
}

func GetReqLimitPerTarget() int {
	if reqLimiter == nil {
		return 0
	}
	reqLimiter.mu.Lock()
	r := reqLimiter.rate
	reqLimiter.mu.Unlock()
	return r
}

func SetReqLimitPerTarget(rate int) {
	if reqLimiter == nil {
		return
	}
	reqLimiter.SetRate(rate)
}

func StartAutoReqLimit(stop <-chan struct{}, minRate int, maxRate int) {
	if reqLimiter == nil {
		return
	}
	if minRate <= 0 {
		minRate = 1
	}
	if maxRate < minRate {
		maxRate = minRate
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		prev := GetLiveMetrics()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}

			cur := GetLiveMetrics()
			deltaWaitCount := cur.ReqLimitWaitCount - prev.ReqLimitWaitCount
			deltaWaitNs := cur.ReqLimitWaitNs - prev.ReqLimitWaitNs
			prev = cur

			if deltaWaitCount <= 0 || deltaWaitNs <= 0 {
				continue
			}

			avgWaitMs := (deltaWaitNs / int64(time.Millisecond)) / deltaWaitCount
			if avgWaitMs < 250 {
				continue
			}

			currentRate := GetReqLimitPerTarget()
			if currentRate <= 0 {
				continue
			}
			if currentRate >= maxRate {
				continue
			}

			step := currentRate / 5
			if step < 1 {
				step = 1
			}
			newRate := currentRate + step
			if newRate > maxRate {
				newRate = maxRate
			}
			if newRate < minRate {
				newRate = minRate
			}
			SetReqLimitPerTarget(newRate)
		}
	}()
}

type hostPortLimiter struct {
	rate int

	mu          sync.Mutex
	limiters    map[string]*perKeyLimiter
	lastCleanup time.Time
}

type perKeyLimiter struct {
	interval time.Duration
	next     time.Time
	lastUsed time.Time
	mu       sync.Mutex
}

func newHostPortLimiter(rate int) *hostPortLimiter {
	return &hostPortLimiter{
		rate:        rate,
		limiters:    make(map[string]*perKeyLimiter),
		lastCleanup: time.Now(),
	}
}

func (l *hostPortLimiter) SetRate(rate int) {
	if rate <= 0 {
		return
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Second
	}

	now := time.Now()
	l.mu.Lock()
	l.rate = rate
	for _, pl := range l.limiters {
		pl.mu.Lock()
		pl.interval = interval
		pl.lastUsed = now
		pl.mu.Unlock()
	}
	l.mu.Unlock()
}

func (l *hostPortLimiter) Wait(ctx context.Context, u *url.URL) error {
	key := urlHostPortKey(u)
	if key == "" {
		return nil
	}
	pl := l.get(key)
	return pl.Wait(ctx)
}

func (l *hostPortLimiter) get(key string) *perKeyLimiter {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastCleanup) > 2*time.Minute {
		l.cleanupLocked(now)
		l.lastCleanup = now
	}

	if pl, ok := l.limiters[key]; ok {
		return pl
	}

	interval := time.Second / time.Duration(l.rate)
	if interval <= 0 {
		interval = time.Second
	}
	pl := &perKeyLimiter{interval: interval, lastUsed: now}
	l.limiters[key] = pl
	return pl
}

func (l *hostPortLimiter) cleanupLocked(now time.Time) {
	for k, pl := range l.limiters {
		pl.mu.Lock()
		lastUsed := pl.lastUsed
		pl.mu.Unlock()
		if now.Sub(lastUsed) > 10*time.Minute {
			delete(l.limiters, k)
		}
	}
}

func (l *perKeyLimiter) Wait(ctx context.Context) error {
	for {
		now := time.Now()

		l.mu.Lock()
		l.lastUsed = now
		if l.next.IsZero() {
			l.next = now
		}
		wait := l.next.Sub(now)
		if wait <= 0 {
			l.next = now.Add(l.interval)
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type reqLimitTransport struct {
	base http.RoundTripper
}

func (t *reqLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if reqLimiter != nil && req != nil && req.URL != nil {
		start := time.Now()
		if err := reqLimiter.Wait(req.Context(), req.URL); err != nil {
			return nil, err
		}
		waited := time.Since(start)
		if waited > 0 {
			atomic.AddInt64(&reqLimitWaitNs, waited.Nanoseconds())
			atomic.AddInt64(&reqLimitWaitCount, 1)
		}
	}
	atomic.AddInt64(&httpInflight, 1)
	defer atomic.AddInt64(&httpInflight, -1)
	return t.base.RoundTrip(req)
}

func applyReqLimitTransport(c *retryablehttp.Client) {
	if c == nil || c.HTTPClient == nil {
		return
	}

	rt := c.HTTPClient.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, ok := rt.(*reqLimitTransport); ok {
		return
	}
	c.HTTPClient.Transport = &reqLimitTransport{base: rt}
}

func urlHostPortKey(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	if _, _, err := net.SplitHostPort(net.JoinHostPort(host, port)); err == nil {
		return net.JoinHostPort(host, port)
	}
	return host + ":" + port
}

func WaitHostPort(ctx context.Context, host string, port string) error {
	if reqLimiter == nil {
		return nil
	}
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return nil
	}
	if port == "" {
		port = "80"
	}
	start := time.Now()
	err := reqLimiter.get(net.JoinHostPort(host, port)).Wait(ctx)
	waited := time.Since(start)
	if waited > 0 {
		atomic.AddInt64(&reqLimitWaitNs, waited.Nanoseconds())
		atomic.AddInt64(&reqLimitWaitCount, 1)
	}
	return err
}

type LiveMetrics struct {
	HTTPInflight      int64
	RawInflight       int64
	NetInflight       int64
	ReqLimitWaitNs    int64
	ReqLimitWaitCount int64
	TaskGateWaitNs    int64
	TaskGateWaitCount int64
}

func GetLiveMetrics() LiveMetrics {
	return LiveMetrics{
		HTTPInflight:      atomic.LoadInt64(&httpInflight),
		RawInflight:       atomic.LoadInt64(&rawInflight),
		NetInflight:       atomic.LoadInt64(&netInflight),
		ReqLimitWaitNs:    atomic.LoadInt64(&reqLimitWaitNs),
		ReqLimitWaitCount: atomic.LoadInt64(&reqLimitWaitCount),
		TaskGateWaitNs:    atomic.LoadInt64(&taskGateWaitNs),
		TaskGateWaitCount: atomic.LoadInt64(&taskGateWaitCount),
	}
}

func AddTaskGateWait(d time.Duration) {
	if d <= 0 {
		return
	}
	atomic.AddInt64(&taskGateWaitNs, d.Nanoseconds())
	atomic.AddInt64(&taskGateWaitCount, 1)
}

func AddRawInflight(delta int64) {
	atomic.AddInt64(&rawInflight, delta)
}

func AddNetInflight(delta int64) {
	atomic.AddInt64(&netInflight, delta)
}

func Request(target string, header []string, rule poc.Rule, variableMap map[string]any) error {
	baseCtx := ContextFromVariableMap(variableMap)
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, defaultTimeout)
	defer cancel()

	variableMap["request"] = nil
	variableMap["response"] = nil

	u, err := url.Parse(target)
	if err != nil {
		return err
	}

	// base
	baseHost := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	basePath := u.Path

	// path
	rule.Request.Path = setVariableMap(strings.TrimSpace(rule.Request.Path), variableMap)

	newpath := rule.Request.Path
	isAbs := false
	if strings.HasPrefix(newpath, "^") {
		isAbs = true
		newpath = newpath[1:]
	}
	if !strings.HasPrefix(newpath, "/") {
		newpath = "/" + newpath
	}
	newpath = strings.ReplaceAll(newpath, " ", "%20")
	newpath = strings.ReplaceAll(newpath, "#", "%23")

	if isAbs {
		target = baseHost + newpath
	} else {
		if newpath == "/" {
			if basePath == "" {
				target = baseHost + "/"
			} else {
				target = baseHost + basePath
			}
		} else {
			bp := strings.TrimRight(basePath, "/")
			target = baseHost + bp + newpath
		}
	}

	// body
	if strings.HasPrefix(strings.ToLower(rule.Request.Headers["Content-Type"]), "multipart/") && !strings.Contains(rule.Request.Body, "\r\n") && (strings.Contains(rule.Request.Body, "\n") || strings.Contains(rule.Request.Body, "\n\n")) {
		rule.Request.Body = setVariableMap(strings.TrimSpace(rule.Request.Body), variableMap)
		splitstr := "\n"
		if splitstr == "\n\n" {
			splitstr = "\n\n"
		}
		rule.Request.Body = strings.ReplaceAll(rule.Request.Body, splitstr, "\r\n")
		rule.Request.Body = strings.TrimRight(rule.Request.Body, "\r\n") + "\r\n"
	} else {
		rule.Request.Body = setVariableMap(strings.TrimSpace(rule.Request.Body), variableMap)
	}

	// newhttprequest
	req, err := retryablehttp.NewRequestWithContext(ctx, rule.Request.Method, target, nil)
	if len(rule.Request.Body) > 0 {
		req, err = retryablehttp.NewRequestWithContext(ctx, rule.Request.Method, target, strings.NewReader(rule.Request.Body))
	}
	if err != nil {
		return err
	}

	// headers (delete @2023.1.10)
	// if rule.Request.Method == http.MethodPost && len(rule.Request.Headers["Content-Type"]) == 0 {
	// 	if rule.Request.Headers == nil {
	// 		rule.Request.Headers = map[string]string{}
	// 	}
	// 	rule.Request.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	// }

	// Tips: poc rule.request.host is changed
	// created: 2023/07/25
	if len(rule.Request.Host) > 0 {
		req.Request.Host = setVariableMap(rule.Request.Host, variableMap)
	}

	for k, v := range rule.Request.Headers {
		req.Header.Add(k, setVariableMap(v, variableMap))
	}

	if defaultAccept && len(req.Header.Get("Accept")) == 0 {
		req.Header.Add("Accept", "*/*")
	}

	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Add("User-Agent", utils.RandomUA())
	}

	// default post content-type
	if rule.Request.Method == http.MethodPost && len(req.Header.Get("Content-Type")) == 0 {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	// 自定义 header，2024.04.13
	if len(header) > 0 {
		ApplyHeaderLines(req, header, false)
	}

	// 自定义 cookie 被废弃，2024.04.13
	// ck := convertCookie(req.Header.Get("Cookie"), cookie)
	// if len(ck) > 0 {
	// 	req.Header.Set("Cookie", ck)
	// }

	// latency
	var milliseconds int64
	start := time.Now()
	trace := httptrace.ClientTrace{}
	trace.GotFirstResponseByte = func() {
		milliseconds = time.Since(start).Nanoseconds() / 1e6
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	// http client do request
	resp := &http.Response{}
	if !rule.Request.FollowRedirects {
		resp, err = RtryNoRedirect.Do(req)
	} else {
		resp, err = RtryRedirect.Do(req)
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}

	var buf bytes.Buffer
	lr := io.LimitedReader{R: resp.Body, N: maxDefaultBody}
	_, err = io.Copy(&buf, &lr) // fixed 服务端或代理提前断开连接，HTTP 响应体被截断， io.ReadAll 在读取 io.LimitReader 时会抛出 unexpected EOF 。@eidtor 2025.12.1
	if err != nil {
		if !strings.Contains(err.Error(), "user canceled") && !errors.Is(err, io.ErrUnexpectedEOF) {
			resp.Body.Close()
			return err
		}
	}
	resp.Body.Close()
	respBody := buf.Bytes()

	responseText := ""
	if len(respBody) > 0 {
		responseText = utils.Str2UTF8(string(respBody))
	}

	variableMap["response_text"] = responseText
	writeHTTPResponseToVars(variableMap, resp, respBody, milliseconds)
	writeHTTPRequestToVars(variableMap, req, rule.Request.Body, target, u)

	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		variableMap["fulltarget"] = resp.Request.URL.String()
	} else {
		variableMap["fulltarget"] = target
	}

	return nil
}

func writeHTTPResponseToVars(variableMap map[string]any, resp *http.Response, body []byte, latency int64) {
	protoResp := &proto.Response{}
	protoResp.Status = int32(resp.StatusCode)
	protoResp.Url = url2ProtoUrl(resp.Request.URL)

	newRespHeader := make(map[string]string)
	rawHeaderBuilder := strings.Builder{}
	for k, v := range resp.Header {
		newRespHeader[strings.ToLower(k)] = strings.Join(v, ";")
		rawHeaderBuilder.WriteString(k)
		rawHeaderBuilder.WriteString(": ")
		rawHeaderBuilder.WriteString(strings.Join(v, ";"))
		rawHeaderBuilder.WriteString("\n")
	}
	protoResp.Headers = newRespHeader
	protoResp.ContentType = resp.Header.Get("Content-Type")
	protoResp.Body = body
	rawPrefix := []byte(resp.Proto + " " + resp.Status + "\n" + strings.Trim(rawHeaderBuilder.String(), "\n") + "\n\n")
	protoResp.Raw = append(rawPrefix, body...)
	protoResp.RawHeader = []byte(strings.Trim(rawHeaderBuilder.String(), "\n"))
	protoResp.Latency = latency
	variableMap["response"] = protoResp
}

func WriteHTTPResponseToVars(variableMap map[string]any, resp *http.Response, body []byte, latency int64) {
	writeHTTPResponseToVars(variableMap, resp, body, latency)
}

func writeHTTPRequestToVars(variableMap map[string]any, req *retryablehttp.Request, body string, target string, u *url.URL) {
	protoReq := &proto.Request{}
	protoReq.Method = req.Method
	protoReq.Url = url2ProtoUrl(req.URL.URL)

	newReqHeader := make(map[string]string)
	rawReqHeaderBuilder := strings.Builder{}
	for k := range req.Header {
		newReqHeader[strings.ToLower(k)] = req.Header.Get(k)
		rawReqHeaderBuilder.WriteString(k)
		rawReqHeaderBuilder.WriteString(": ")
		rawReqHeaderBuilder.WriteString(req.Header.Get(k))
		rawReqHeaderBuilder.WriteString("\n")
	}
	protoReq.Headers = newReqHeader
	protoReq.ContentType = req.Header.Get("Content-Type")
	protoReq.Body = []byte(body)

	reqPath := strings.Replace(target, fmt.Sprintf("%s://%s", u.Scheme, u.Host), "", 1)
	rawHost := u.Host
	if req.Request != nil && strings.TrimSpace(req.Request.Host) != "" {
		rawHost = strings.TrimSpace(req.Request.Host)
	}
	protoReq.Raw = []byte(req.Method + " " + reqPath + " " + req.Proto + "\n" + "Host: " + rawHost + "\n" + strings.Trim(rawReqHeaderBuilder.String(), "\n") + "\n\n" + body)
	protoReq.RawHeader = []byte(strings.Trim(rawReqHeaderBuilder.String(), "\n"))
	variableMap["request"] = protoReq
}

func WriteHTTPRequestToVars(variableMap map[string]any, req *retryablehttp.Request, body string, target string, u *url.URL) {
	writeHTTPRequestToVars(variableMap, req, body, target, u)
}

func convertCookie(old, new string) string {

	if len(new) > 0 && len(old) > 0 {
		return strings.TrimSuffix(new, ";") + ";" + old
	}

	if len(new) > 0 && len(old) == 0 {
		return new
	}

	if len(new) == 0 && len(old) > 0 {
		return old
	}

	return ""
}

func url2ProtoUrl(u *url.URL) *proto.UrlType {
	return &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

func setVariableMap(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		_, isMap := v.(map[string]string)
		if isMap {
			continue
		}
		newstr := fmt.Sprintf("%v", v)
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, newstr)
	}
	return find
}

// 处理multipart（已过期）
func dealMultipart(contentType string, ruleBody string) (result string, err error) {
	// 处理multipart的/n
	re := regexp.MustCompile(`(?m)multipart\/form-Data; boundary=(.*)`)
	match := re.FindStringSubmatch(contentType)
	if len(match) != 2 {
		return "", errors.New("no boundary in content-type")
	}
	boundary := "--" + match[1]

	// 处理rule
	multiPartContent := ""
	multiFile := strings.Split(ruleBody, boundary)
	if len(multiFile) == 0 {
		return multiPartContent, errors.New("ruleBody.Body multi content format err")
	}

	for _, singleFile := range multiFile {
		//	处理单个文件
		//	文件头和文件响应
		spliteTmp := strings.Split(singleFile, "\n\n")
		if len(spliteTmp) == 2 {
			fileHeader := spliteTmp[0]
			fileBody := spliteTmp[1]
			fileHeader = strings.Replace(fileHeader, "\n", "\r\n", -1)
			multiPartContent += boundary + fileHeader + "\r\n\r\n" + strings.TrimRight(fileBody, "\n") + "\r\n"
		}
	}
	multiPartContent += boundary + "--" + "\r\n"
	return multiPartContent, nil
}

func fulltarget(target, path string) string {
	if len(path) == 0 {
		return target
	}

	i := strings.LastIndex(path, "/")

	if i > 0 && strings.Contains(path, ".") {
		target = fmt.Sprintf("%s%s", target, path[:i])

	} else if !strings.Contains(path, ".") {

		target = fmt.Sprintf("%s%s", target, path)
	}

	return target
}

func simpleRtryHttpGet(target string) ([]byte, int, error) {
	if len(target) == 0 {
		return []byte(""), 0, errors.New("no target specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Add("User-Agent", utils.RandomUA())

	resp, err := RtryNoRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return []byte(""), 0, err
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return []byte(""), 0, err
	}

	return respBody, resp.StatusCode, err
}

func simpleRtryHttpGetTimeout(target string, timeout time.Duration) ([]byte, int, error) {
	if len(target) == 0 {
		return []byte(""), 0, errors.New("no target specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Add("User-Agent", utils.RandomUA())

	resp, err := RtryNoRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return []byte(""), 0, err
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return []byte(""), 0, err
	}

	return respBody, resp.StatusCode, err
}

var (
	HTTP_PREFIX  = "http://"
	HTTPS_PREFIX = "https://"
)

type probeCall struct {
	done   chan struct{}
	result string
	err    error
}

type probeMemo struct {
	okURL       string
	okAt        time.Time
	failUntil   time.Time
	attempts    int
	windowStart time.Time
}

type checkProtocolSuppressedError struct {
	host  string
	until time.Time
}

func (e *checkProtocolSuppressedError) Error() string {
	if e == nil {
		return "check protocol suppressed"
	}
	if !e.until.IsZero() {
		return fmt.Sprintf("check protocol suppressed for %q until %s", e.host, e.until.UTC().Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("check protocol suppressed for %q", e.host)
}

func IsCheckProtocolSuppressed(err error) bool {
	var se *checkProtocolSuppressedError
	return errors.As(err, &se)
}

var (
	probeMu    sync.Mutex
	probeCalls = make(map[string]*probeCall)
	probeMemos = make(map[string]*probeMemo)
)

var (
	checkProtocolAttemptWindow        = 10 * time.Minute
	checkProtocolMaxAttemptsPerWindow = 1
	checkProtocolFailCooldownBase     = 30 * time.Second
	checkProtocolFailCooldownMax      = 10 * time.Minute
)

func CheckProtocol(host string) (string, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return "", fmt.Errorf("host %q is empty", host)
	}
	key := strings.ToLower(trimmed)

	now := time.Now()
	probeMu.Lock()

	// 1. Check for ongoing probe calls first.
	// If a probe is already in progress, wait for it to complete and share the result.
	// This prevents concurrent requests from being rejected by the attempts limit before they even start.
	if c := probeCalls[key]; c != nil {
		probeMu.Unlock()
		<-c.done
		return c.result, c.err
	}

	if memo := probeMemos[key]; memo != nil {
		if u := strings.TrimSpace(memo.okURL); u != "" {
			probeMu.Unlock()
			return u, nil
		}
		if !memo.failUntil.IsZero() && now.Before(memo.failUntil) {
			until := memo.failUntil
			probeMu.Unlock()
			return "", &checkProtocolSuppressedError{host: trimmed, until: until}
		}
		if checkProtocolMaxAttemptsPerWindow > 0 {
			if memo.windowStart.IsZero() || now.Sub(memo.windowStart) >= checkProtocolAttemptWindow {
				memo.windowStart = now
				memo.attempts = 0
			}
			if memo.attempts >= checkProtocolMaxAttemptsPerWindow {
				until := memo.windowStart.Add(checkProtocolAttemptWindow)
				probeMu.Unlock()
				return "", &checkProtocolSuppressedError{host: trimmed, until: until}
			}
		}
	}

	memo := probeMemos[key]
	if memo == nil {
		memo = &probeMemo{}
		probeMemos[key] = memo
	}
	if checkProtocolMaxAttemptsPerWindow > 0 {
		if memo.windowStart.IsZero() || now.Sub(memo.windowStart) >= checkProtocolAttemptWindow {
			memo.windowStart = now
			memo.attempts = 0
		}
		memo.attempts++
	}

	c := &probeCall{done: make(chan struct{})}
	probeCalls[key] = c
	probeMu.Unlock()

	var result string
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("check protocol failed for %q", host)
			}
		}()
		result, err = checkProtocolDirect(host)
	}()

	c.result = result
	c.err = err

	probeMu.Lock()
	if memo := probeMemos[key]; memo != nil {
		if err == nil && strings.TrimSpace(result) != "" {
			memo.okURL = result
			memo.okAt = time.Now()
			memo.failUntil = time.Time{}
		} else {
			attempt := memo.attempts
			if attempt <= 0 {
				attempt = 1
			}
			cooldown := checkProtocolFailCooldownBase
			if attempt > 1 {
				for i := 1; i < attempt; i++ {
					if cooldown >= checkProtocolFailCooldownMax {
						cooldown = checkProtocolFailCooldownMax
						break
					}
					cooldown *= 2
					if cooldown > checkProtocolFailCooldownMax {
						cooldown = checkProtocolFailCooldownMax
						break
					}
				}
			}
			if cooldown <= 0 {
				cooldown = 30 * time.Second
			}
			memo.failUntil = time.Now().Add(cooldown)
		}
	}
	delete(probeCalls, key)
	probeMu.Unlock()
	close(c.done)

	return result, err
}

func checkProtocolDirect(host string) (string, error) {
	var (
		err       error
		result    string
		parsePort string
		lastErr   error
	)

	if len(strings.TrimSpace(host)) == 0 {
		return result, fmt.Errorf("host %q is empty", host)
	}

	probeTimeout := defaultTimeout
	if probeTimeout > 5*time.Second {
		probeTimeout = 5 * time.Second
	}

	if strings.HasPrefix(host, HTTPS_PREFIX) {
		_, err := checkTarget(host, probeTimeout)
		if err != nil {
			lastErr = err
			return result, err
		}

		return host, nil
	}

	if strings.HasPrefix(host, HTTP_PREFIX) {
		_, err := checkTarget(host, probeTimeout)
		if err != nil {
			lastErr = err
			return result, err
		}

		return host, nil
	}

	u, err := url.Parse(HTTP_PREFIX + host)
	if err != nil {
		return result, err
	}
	parsePort = u.Port()

	switch {
	case parsePort == "80":
		_, err := checkTarget(HTTP_PREFIX+host, probeTimeout)
		if err != nil {
			lastErr = err
			return result, err
		}

		return HTTP_PREFIX + host, nil

	case parsePort == "443":
		_, err := checkTarget(HTTPS_PREFIX+host, probeTimeout)
		if err != nil {
			lastErr = err
			return result, err
		}

		return HTTPS_PREFIX + host, nil

	default:
		preferHTTPS := false
		if parsePort == "" {
			preferHTTPS = true
		} else {
			switch parsePort {
			case "443", "8443", "9443", "10443":
				preferHTTPS = true
			}
		}

		tryFirst := HTTP_PREFIX
		trySecond := HTTPS_PREFIX
		if preferHTTPS {
			tryFirst = HTTPS_PREFIX
			trySecond = HTTP_PREFIX
		}

		body, err := checkTarget(tryFirst+host, probeTimeout)
		if err == nil {
			if tryFirst == HTTP_PREFIX && strings.Contains(body, "<title>400 The plain HTTP request was sent to HTTPS port</title>") {
				return HTTPS_PREFIX + host, nil
			}
			return tryFirst + host, nil
		}
		lastErr = err

		body, err = checkTarget(trySecond+host, probeTimeout)
		if err == nil {
			if trySecond == HTTP_PREFIX && strings.Contains(body, "<title>400 The plain HTTP request was sent to HTTPS port</title>") {
				return HTTPS_PREFIX + host, nil
			}
			return trySecond + host, nil
		}
		lastErr = err

	}

	if lastErr != nil {
		return "", fmt.Errorf("check protocol failed for %q: %w", host, lastErr)
	}
	return "", fmt.Errorf("check protocol failed for %q", host)
}

func checkTarget(target string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", utils.RandomUA())

	resp, err := RtryNoRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "", err
	}
	defer resp.Body.Close()

	maxRead := int64(8192)
	if maxDefaultBody > 0 && maxDefaultBody < maxRead {
		maxRead = maxDefaultBody
	}
	reader := io.LimitReader(resp.Body, maxRead)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	if !isTargetLive(resp.StatusCode) {
		return "", fmt.Errorf("status code is not live %d", resp.StatusCode)
	}

	return string(respBody), nil
}

func isTargetLive(code int) bool {
	return true
}

// Reverse URL Get request
func ReverseGet(target string) ([]byte, error) {
	if len(target) == 0 {
		return []byte(""), errors.New("target not find")
	}
	respBody, _, err := simpleRtryHttpGet(target)
	return respBody, err
}

func Get(target string) ([]byte, int, error) {
	return simpleRtryHttpGetTimeout(target, defaultTimeout)
}

func GetTimeout(target string, timeout time.Duration) ([]byte, int, error) {
	return simpleRtryHttpGetTimeout(target, timeout)
}

func Url2UrlType(u *url.URL) *proto.UrlType {
	return &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

func ParseRequest(oReq *http.Request) (*proto.Request, error) {
	req := &proto.Request{}
	req.Method = oReq.Method
	req.Url = Url2UrlType(oReq.URL)
	header := make(map[string]string)
	for k := range oReq.Header {
		header[k] = oReq.Header.Get(k)
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := io.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	}
	return req, nil
}

func GetDefaultTimeout() time.Duration {
	return defaultTimeout
}

func GetMaxDefaultBody() int64 {
	if maxDefaultBody == 0 {
		return int64(2 * 1024 * 1024)
	}

	return maxDefaultBody
}

func DefaultAcceptEnabled() bool {
	return defaultAccept
}
