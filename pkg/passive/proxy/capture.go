package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/martian/v3"
	"github.com/rs/xid"
	"github.com/zan8in/afrog/v3/pkg/passive"
)

// txCtxKey 是事务在 martian Context 中的键。
// 请求阶段写入，响应阶段取出，从而把一次请求/响应配对成完整事务。
const txCtxKey = "afrog.passive.tx"

// capture 同时实现 martian 的请求与响应修改器，负责把流量归一化成事务对象。
type capture struct {
	onTx      func(*passive.CapturedTransaction)
	onTraffic func(passive.TrafficEvent)
	maxBody   int64
}

// ModifyRequest 归一化请求并暂存事务。
//
// 归一化的重点是补齐 scheme 与 host：MITM 隧道的请求在 Go 的 server 侧可能不完整，
// 缺了它们后续重放就无法定位目标。
func (c *capture) ModifyRequest(req *http.Request) error {
	if req == nil {
		return nil
	}
	// CONNECT 只是建立 HTTPS 隧道的握手，隧道内的真实请求会再次进入这里。
	// 为它上报「方法跳过」会让每条 HTTPS 流量凭空多出一条噪音记录。
	if req.Method == http.MethodConnect {
		return nil
	}
	// 被放过的请求同样要上报：使用者看到「捕获数不涨」时，最需要知道的是
	// 流量被哪条规则挡在了检测之外（静态资源 / 方法 / 无法归一化）。
	if verdict, reason, skip := skipReason(req); skip {
		c.emitSkip(req, verdict, reason)
		return nil
	}

	ctx := martian.NewContext(req)
	if ctx == nil {
		c.emitSkip(req, passive.VerdictSkippedPath, "无法建立代理会话上下文")
		return nil
	}

	scheme := "http"
	if ctx.Session() != nil && ctx.Session().IsSecure() {
		scheme = "https"
	}

	u := req.URL
	if u == nil {
		c.emitSkip(req, passive.VerdictSkippedPath, "请求缺少 URL")
		return nil
	}
	// 不要污染原始请求：这里只读取，不修改 req.URL。
	urlCopy := *u
	if urlCopy.Scheme == "" {
		urlCopy.Scheme = scheme
	}
	if urlCopy.Host == "" {
		urlCopy.Host = req.Host
	}
	if urlCopy.Host == "" {
		c.emitSkip(req, passive.VerdictSkippedPath, "无法确定目标主机")
		return nil
	}

	headers := req.Header.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	if req.Host != "" {
		headers.Set("Host", req.Host)
	}

	body, err := readAndRestoreBody(&req.Body, c.maxBody)
	if err != nil {
		c.emitSkip(req, passive.VerdictError, "读取请求体失败: "+err.Error())
		return nil
	}

	// 去掉客户端的 Accept-Encoding，让上游返回明文，同时由 Transport 负责解压。
	// 否则检测器会在压缩字节上做相似度比较，结论完全不可信。
	req.Header.Del("Accept-Encoding")

	tx := &passive.CapturedTransaction{
		ID: xid.New().String(),
		Request: &passive.CapturedRequest{
			Method:  req.Method,
			URL:     &urlCopy,
			Headers: headers,
			Body:    body,
		},
		ClientIP: clientIP(req),
		StartAt:  time.Now(),
	}
	ctx.Set(txCtxKey, tx)
	return nil
}

// ModifyResponse 读取响应体、恢复给客户端，并产出完整事务。
func (c *capture) ModifyResponse(res *http.Response) error {
	if res == nil || res.Request == nil {
		return nil
	}
	ctx := martian.NewContext(res.Request)
	if ctx == nil {
		return nil
	}
	v, ok := ctx.Get(txCtxKey)
	if !ok {
		return nil
	}
	tx, ok := v.(*passive.CapturedTransaction)
	if !ok {
		return nil
	}

	body, err := readAndRestoreBody(&res.Body, c.maxBody)
	if err != nil {
		if c.onTraffic != nil {
			ev := passive.TrafficEvent{
				ID:      tx.ID,
				Time:    tx.StartAt,
				Status:  res.StatusCode,
				Verdict: passive.VerdictError,
				Reason:  "读取响应体失败",
				Error:   err.Error(),
			}
			if tx.Request != nil {
				ev.Method = tx.Request.Method
				if tx.Request.URL != nil {
					ev.URL = tx.Request.URL.String()
				}
			}
			c.onTraffic(ev)
		}
		return nil
	}

	// 读完 body 后必须重建长度信息，否则客户端会按原始 Content-Length 读取而报错。
	if res.Header != nil {
		res.Header.Del("Content-Encoding")
		res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	res.ContentLength = int64(len(body))
	res.TransferEncoding = nil

	tx.Response = &passive.CapturedResponse{
		Status:   res.StatusCode,
		Headers:  res.Header.Clone(),
		Body:     body,
		Duration: time.Since(tx.StartAt),
	}

	if c.onTx != nil {
		c.onTx(tx)
	}
	return nil
}

// readAndRestoreBody 读取至多 max 字节，并把请求/响应体的读取位置复位。
//
// 不限定上限会让大文件下载把内存打满，这是被动代理最容易踩的坑。
func readAndRestoreBody(rc *io.ReadCloser, max int64) ([]byte, error) {
	if rc == nil || *rc == nil {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(*rc, max+1))
	_ = (*rc).Close()
	if err != nil {
		*rc = io.NopCloser(bytes.NewReader(b))
		return nil, err
	}
	*rc = io.NopCloser(bytes.NewReader(b))
	if int64(len(b)) > max {
		return b[:max], nil
	}
	return b, nil
}

// staticExts 是不参与被动检测的静态资源后缀。
// 这些请求没有可注入参数，放行到调度层只会白白占用队列。
var staticExts = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".mp3", ".zip", ".gz",
}

// skipReason 判断请求是否应该直接被放过，并给出可读原因。
//
// 返回值语义与 shouldSkip 一致，只是把「为什么」一并带出来供界面展示。
func skipReason(req *http.Request) (passive.TrafficVerdict, string, bool) {
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return passive.VerdictSkippedMethod, "请求方法 " + req.Method + " 不在检测范围内", true
	}
	if req.URL == nil {
		return passive.VerdictSkippedPath, "请求缺少 URL", true
	}
	path := strings.ToLower(req.URL.Path)
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return passive.VerdictSkippedStatic, "静态资源 " + ext + "，不参与注入检测", true
		}
	}
	return "", "", false
}

// emitSkip 上报一条被放过的流量。上报失败绝不影响转发。
func (c *capture) emitSkip(req *http.Request, verdict passive.TrafficVerdict, reason string) {
	if c.onTraffic == nil {
		return
	}
	ev := passive.TrafficEvent{
		Time:    time.Now(),
		Method:  req.Method,
		Verdict: verdict,
		Reason:  reason,
	}
	if req.URL != nil {
		ev.URL = req.URL.String()
	}
	c.onTraffic(ev)
}

func clientIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	addr := req.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}
