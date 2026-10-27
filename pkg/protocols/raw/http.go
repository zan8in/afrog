package raw

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/rawhttp"
)

var (
	rawHttpClientsMu sync.Mutex
	rawHttpClients   = make(map[string]*rawhttp.Client)
)

type RawHttp struct {
	RawhttpClient   *rawhttp.Client
	MaxRespBodySize int
}

// GetRawHTTP 按 proxy + timeout 缓存 rawhttp 客户端。
// 注意 rawhttp.DefaultOptions 是指针，必须先做值拷贝再改字段，
// 否则会污染库级默认配置。
func GetRawHTTP(proxy string, timeout int) *rawhttp.Client {
	key := fmt.Sprintf("%s|%d", proxy, timeout)

	rawHttpClientsMu.Lock()
	defer rawHttpClientsMu.Unlock()
	if client, ok := rawHttpClients[key]; ok {
		return client
	}

	opts := *rawhttp.DefaultOptions

	if len(proxy) > 0 {
		if err := LoadProxyServers(proxy); err == nil {
			if ProxyURL != "" {
				opts.Proxy = ProxyURL
			} else if ProxySocksURL != "" {
				opts.Proxy = ProxySocksURL
			}
		}
	}

	opts.Timeout = time.Duration(timeout) * time.Second
	// raw 请求自带 Host 头，不再让库自动覆盖，raw 里写的 Host 才能生效；
	// 若 raw 未给出可用 Host，RawHttpRequest 会用目标主机兜底。
	opts.AutomaticHostHeader = false

	client := rawhttp.NewClient(&opts)
	rawHttpClients[key] = client
	return client
}

// 自定义 cookie 已弃用 2024.04.13
// func addCookie(request, cookie string) string {
// 	if len(cookie) == 0 {
// 		return request
// 	}

// 	list := strings.Split(request, "\n")
// 	isCookie := false
// 	for k, l := range list {
// 		if strings.HasPrefix(strings.ToLower(l), "cookie:") {
// 			list[k] = strings.TrimSuffix(l, ";") + "; " + cookie
// 			isCookie = true
// 		}
// 	}

// 	if !isCookie && len(list) > 2 {
// 		list = append(list[:2], append([]string{"Cookie: " + cookie}, list[2:]...)...)
// 	}

// 	return strings.Join(list, "\n")
// }

// 自定义 header 代替 自定义 cookie 2024.04.13
// 口径与非 raw 路径的 retryhttpclient.ApplyHeaderLines 对齐：
//   - 关键 header（host/cookie/authorization/user-agent/content-type/accept）覆盖原值；
//   - 其余 header 已存在时追加一行（HTTP 允许同名头多行），否则插入请求头块末尾。
func addHeader(request, key, value string) string {
	if len(key) == 0 {
		return request
	}

	line := key + ": " + strings.TrimSpace(value)
	lines := strings.Split(request, "\n")
	end := headerBlockEnd(lines)

	for i := 0; i < end; i++ {
		if !strings.HasPrefix(strings.ToLower(lines[i]), strings.ToLower(key)+":") {
			continue
		}
		if retryhttpclient.IsCriticalHeader(key) {
			lines[i] = line
			return strings.Join(lines, "\n")
		}
		lines = append(lines[:i+1], append([]string{line}, lines[i+1:]...)...)
		return strings.Join(lines, "\n")
	}

	lines = append(lines[:end], append([]string{line}, lines[end:]...)...)
	return strings.Join(lines, "\n")
}

// headerBlockEnd 返回请求头块结束的位置：首个空行的下标，没有空行时是总行数。
// 请求行（首行）之后的空行才是头与 body 的分隔。
func headerBlockEnd(lines []string) int {
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			return i
		}
	}
	return len(lines)
}

// headerKey 在大小写不敏感的前提下查找 header map 中已存在的键。
func headerKey(headers map[string]string, name string) (string, bool) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}
	return "", false
}

func appendHeader(request string, header []string) string {
	if len(header) == 0 {
		return request
	}
	for _, va := range header {
		arr := strings.Split(va, ":")
		key := strings.TrimSpace(arr[0])
		if found, ok := strings.CutPrefix(va, key+":"); ok && len(key) > 0 {
			request = addHeader(request, key, strings.TrimSpace(found))
		}
	}
	return request
}

func (r *RawHttp) RawHttpRequest(request, baseurl string, header []string, variableMap map[string]any) error {
	var err error
	var resp *http.Response

	variableMap["request"] = nil
	variableMap["response"] = nil

	request = AssignVariableRaw(request, variableMap)

	newheader := appendHeader(request, header)

	rhttp, err := Parse(newheader, baseurl, true)
	if err != nil {
		return fmt.Errorf("parse Failed, %s", err.Error())
	}

	// 路径拼接：与非 raw PoC（retryhttpclient.Request）语义对齐。
	//   - 以 "/" 开头的绝对路径 → 拼 base URL 的子路径（默认行为）
	//   - 以 "^" 开头 → 去掉 "^"，强制根路径不拼（与非 raw PoC 一致）
	//   - 相对路径（不以 "/" 开头，如 a/xxx、.//xxx）→ 保留原样，这通常是故意的路径穿越
	//   - 完整 URL（包含 "://"）→ 保留原样
	// 同时改写 UnsafeRawBytes 里的请求行，使 request.raw 与实际发包一致。
	if requrl, perr := url.Parse(baseurl); perr == nil {
		newPath := rhttp.Path
		forceRoot := false
		if strings.HasPrefix(newPath, "^") {
			forceRoot = true
			newPath = newPath[1:]
		}
		isAbsPath := strings.HasPrefix(newPath, "/")
		isFullURL := strings.Contains(newPath, "://")
		if isAbsPath && !forceRoot && !isFullURL {
			bp := strings.TrimRight(requrl.Path, "/")
			if bp != "" {
				newPath = bp + newPath
			}
		}
		if newPath != rhttp.Path {
			// 重写 Path（DoRaw 用）
			rhttp.Path = newPath
			// 同步重写 UnsafeRawBytes 里的请求行（request.raw 变量用）
			raw := rhttp.UnsafeRawBytes
			if idx := bytes.Index(raw, []byte("\n")); idx > 0 {
				reqLine := raw[:idx]
				rest := raw[idx:]
				parts := bytes.SplitN(reqLine, []byte(" "), 3)
				if len(parts) >= 2 {
					parts[1] = []byte(newPath)
					newReqLine := bytes.Join(parts, []byte(" "))
					rhttp.UnsafeRawBytes = append(newReqLine, rest...)
				}
			}
		}
	}

	ct := strings.ToLower(rhttp.Headers["Content-Type"])
	if strings.Contains(ct, "multipart/") {
		if strings.Contains(rhttp.Data, "\n") && !strings.Contains(rhttp.Data, "\r\n") {
			rhttp.Data = strings.ReplaceAll(rhttp.Data, "\n", "\r\n")
			if !strings.HasSuffix(rhttp.Data, "\r\n") {
				rhttp.Data = rhttp.Data + "\r\n"
			}
		}
		rhttp.Headers["Content-Length"] = fmt.Sprintf("%d", len(rhttp.Data))
	}

	if requrl, uerr := url.Parse(baseurl); uerr == nil {
		port := requrl.Port()
		if port == "" {
			if strings.EqualFold(requrl.Scheme, "https") {
				port = "443"
			} else {
				port = "80"
			}
		}
		// Host 兜底：rawhttp 已关闭自动 Host，若 raw 没有可用 Host（缺失或占位符
		// 未解析），用目标主机补上，避免发出非法的 HTTP/1.1 请求。
		if key, ok := headerKey(rhttp.Headers, "Host"); ok {
			if v := strings.TrimSpace(rhttp.Headers[key]); v == "" || strings.Contains(v, "{{") {
				rhttp.Headers[key] = requrl.Host
			}
		} else {
			rhttp.Headers["Host"] = requrl.Host
		}
		baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseCtx, retryhttpclient.GetDefaultTimeout())
		if err := retryhttpclient.WaitHostPort(ctx, requrl.Hostname(), port); err != nil {
			cancel()
			return err
		}
		cancel()
	}

	retryhttpclient.AddRawInflight(1)
	defer retryhttpclient.AddRawInflight(-1)
	// rawhttp 的 DoRaw 读到响应头即返回，这里的耗时接近首字节时延（毫秒），
	// 与非 raw 路径的 GotFirstResponseByte 口径一致。
	start := time.Now()
	resp, err = r.RawhttpClient.DoRaw(rhttp.Method, baseurl, rhttp.Path, ExpandMapValues(rhttp.Headers), io.NopCloser(strings.NewReader(rhttp.Data)))
	latency := time.Since(start).Nanoseconds() / 1e6
	if err != nil {
		//fmt.Println(err.Error())
		return fmt.Errorf("doRaw Failed, %s", err.Error())
	}
	defer resp.Body.Close()

	// 新增最大响应体限制
	// @editor 2024/02/06
	maxDefaultBody := int64(r.MaxRespBodySize * 1024 * 1024)
	lr := &io.LimitedReader{R: resp.Body, N: maxDefaultBody}
	respBody, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("readAll Failed, %s", err.Error())
	}
	// 与非 raw 路径口径一致：读满上限后再探一个字节，区分「正好等于上限」与「确实被截断」。
	bodyTruncated := false
	if lr.N <= 0 {
		var probe [1]byte
		if n, _ := resp.Body.Read(probe[:]); n > 0 {
			bodyTruncated = true
		}
	}
	variableMap[retryhttpclient.VarResponseBodyTruncated] = bodyTruncated

	dumpedResponseHeaders, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return fmt.Errorf("dumpResponse Failed, %s", err.Error())
	}

	tempResultResponse := &proto.Response{}
	tempResultResponse.Status = int32(resp.StatusCode)
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultResponse.Url = retryhttpclient.Url2UrlType(requrl)
	}
	// 同名多值头用 ";" 拼接，与非 raw 路径一致
	newheader2 := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		newheader2[strings.ToLower(k)] = strings.Join(v, ";")
	}
	tempResultResponse.Headers = newheader2
	tempResultResponse.Latency = latency
	tempResultResponse.ContentType = resp.Header.Get("Content-Type")

	// gzip 解压支持
	bodyOut := respBody
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		if decompressed, derr := gunzip(respBody); derr == nil {
			bodyOut = decompressed
		}
	}

	tempResultResponse.Body = bodyOut
	rawPrefix := append(dumpedResponseHeaders, '\n')
	tempResultResponse.Raw = append(rawPrefix, bodyOut...)
	tempResultResponse.RawHeader = dumpedResponseHeaders
	variableMap["response"] = tempResultResponse
	variableMap["response_text"] = utils.Str2UTF8(string(bodyOut))

	tempResultRequest := &proto.Request{}
	tempResultRequest.Method = rhttp.Method
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultRequest.Url = retryhttpclient.Url2UrlType(requrl)
	}
	newheader1 := map[string]string{}
	for _, v := range rhttp.UnsafeHeaders {
		key, _ := v.Key, v.Value
		if len(strings.TrimSpace(key)) == 0 {
			continue
		}
		key = strings.Trim(key, ":")
		hslice := strings.SplitN(key, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader1[k] != "" {
			newheader1[k] += v
		} else {
			newheader1[k] = v
		}
	}
	tempResultRequest.Headers = newheader1
	tempResultRequest.Raw = rhttp.UnsafeRawBytes
	if len(string(rhttp.UnsafeRawBytes)) > 0 {
		rawSplit := strings.Split(string(rhttp.UnsafeRawBytes), "\n\n")
		if len(rawSplit) > 1 {
			tempResultRequest.RawHeader = []byte(rawSplit[0])
		} else {
			tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
		}
	} else {
		tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
	}
	tempResultRequest.Body = []byte(rhttp.Data)
	tempResultRequest.ContentType = tempResultRequest.Headers["content-type"]
	variableMap["request"] = tempResultRequest

	variableMap["fulltarget"] = fmt.Sprintf("%s://%s%s", tempResultRequest.Url.Scheme, tempResultRequest.Url.Host, rhttp.Path)

	return err
}

func AssignVariableRaw(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		newstr := fmt.Sprintf("%v", v)
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, newstr)
	}
	return find
}

func gunzip(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	br := bytes.NewReader(data)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return out, nil
}
