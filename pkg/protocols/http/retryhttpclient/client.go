package retryhttpclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/retryablehttp"
	"golang.org/x/net/context"
)

var (
	RtryRedirect   *retryablehttp.Client
	RtryNoRedirect *retryablehttp.Client

	defaultTimeout = 50 * time.Second

	maxDefaultBody int64
)

type Options struct {
	Proxy           string
	Timeout         int
	Retries         int
	MaxRespBodySize int
}

func Init(opt *Options) (err error) {
	po := &retryablehttp.DefaultPoolOptions
	po.Proxy = opt.Proxy
	po.Timeout = opt.Timeout
	po.Retries = opt.Retries
	po.DisableRedirects = true

	// -timeout 参数默认是 50s @editor 2024/11/03
	defaultTimeout = time.Duration(opt.Timeout) * time.Second

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

	maxDefaultBody = int64(opt.MaxRespBodySize * 1024 * 1024)

	return nil
}

func Request(target string, header []string, rule poc.Rule, variableMap map[string]any) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	variableMap["request"] = nil
	variableMap["response"] = nil

	u, err := url.Parse(target)
	if err != nil {
		return err
	}

	// target
	target = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	if !strings.HasPrefix(rule.Request.Path, "^") {
		targetfull := fulltarget(fmt.Sprintf("%s://%s", u.Scheme, u.Host), u.Path)
		if targetfull != target {
			target = targetfull
		}
	}
	target = strings.TrimRight(target, "/")

	// path
	rule.Request.Path = setVariableMap(strings.TrimSpace(rule.Request.Path), variableMap)

	newpath := rule.Request.Path
	if strings.HasPrefix(rule.Request.Path, "^") {
		newpath = "/" + rule.Request.Path[1:]
	}

	if !strings.HasPrefix(newpath, "/") {
		newpath = "/" + newpath
	}

	newpath = strings.ReplaceAll(newpath, " ", "%20")
	// newpath = strings.ReplaceAll(newpath, "+", "%20")
	newpath = strings.ReplaceAll(newpath, "#", "%23")

	target = target + newpath

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

	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Add("User-Agent", utils.RandomUA())
	}

	// default post content-type
	if rule.Request.Method == http.MethodPost && len(req.Header.Get("Content-Type")) == 0 {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	// 自定义 header，2024.04.13
	if len(header) > 0 {
		for _, va := range header {
			arr := strings.Split(va, ":")
			key := strings.TrimSpace(arr[0])
			if found, ok := strings.CutPrefix(va, key+":"); ok && len(key) > 0 {
				req.Header.Add(key, strings.TrimSpace(found))
			}
		}
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

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		// 解决 https 使用 proxy http 代理时，user canceled 导致 afrog 接收不到响应的问题
		// @editor 2024/01/08
		if !strings.Contains(err.Error(), "user canceled") {
			resp.Body.Close()
			return err
		}

	}
	resp.Body.Close()

	// respbody gbk to utf8 encoding
	utf8RespBody := ""
	if len(respBody) > 0 {
		utf8RespBody = utils.Str2UTF8(string(respBody))
		// utf8RespBody := string(respBody) // fixed issue with https://github.com/zan8in/afrog/v3/issues/68
	}

	// store the response
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
	protoResp.Body = []byte(utf8RespBody)
	protoResp.Raw = []byte(resp.Proto + " " + resp.Status + "\n" + strings.Trim(rawHeaderBuilder.String(), "\n") + "\n\n" + utf8RespBody)
	protoResp.RawHeader = []byte(strings.Trim(rawHeaderBuilder.String(), "\n"))
	protoResp.Latency = milliseconds
	variableMap["response"] = protoResp

	// store the request
	protoReq := &proto.Request{}
	protoReq.Method = rule.Request.Method
	protoReq.Url = url2ProtoUrl(req.URL.URL)

	newReqHeader := make(map[string]string)
	rawReqHeaderBuilder := strings.Builder{}
	for k := range req.Header {
		newReqHeader[k] = req.Header.Get(k)

		rawReqHeaderBuilder.WriteString(k)
		rawReqHeaderBuilder.WriteString(": ")
		rawReqHeaderBuilder.WriteString(req.Header.Get(k))
		rawReqHeaderBuilder.WriteString("\n")
	}

	protoReq.Headers = newReqHeader
	protoReq.ContentType = req.Header.Get("Content-Type")
	protoReq.Body = []byte(rule.Request.Body)

	reqPath := strings.Replace(target, fmt.Sprintf("%s://%s", u.Scheme, u.Host), "", 1)
	protoReq.Raw = []byte(req.Method + " " + reqPath + " " + req.Proto + "\n" + "Host: " + resp.Request.Host + "\n" + strings.Trim(rawReqHeaderBuilder.String(), "\n") + "\n\n" + string(rule.Request.Body))
	protoReq.RawHeader = []byte(strings.Trim(rawReqHeaderBuilder.String(), "\n"))
	variableMap["request"] = protoReq

	// store the full target url
	variableMap["fulltarget"] = target

	return nil
}

func convertCookie(old, new string) string {

	if len(new) > 0 && len(old) > 0 {
		return fmt.Sprintf(strings.TrimSuffix(new, ";") + ";" + old)
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

// return error if host is not living
// or if host is live return http(s) url
func CheckProtocol(host string) (string, error) {
	var (
		err       error
		result    string
		parsePort string
	)

	if len(strings.TrimSpace(host)) == 0 {
		return result, fmt.Errorf("host %q is empty", host)
	}

	if strings.HasPrefix(host, HTTPS_PREFIX) {
		_, err := checkTarget(host)
		if err != nil {
			return result, err
		}

		return host, nil
	}

	if strings.HasPrefix(host, HTTP_PREFIX) {
		_, err := checkTarget(host)
		if err != nil {
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
		_, err := checkTarget(HTTP_PREFIX + host)
		if err != nil {
			return result, err
		}

		return HTTP_PREFIX + host, nil

	case parsePort == "443":
		_, err := checkTarget(HTTPS_PREFIX + host)
		if err != nil {
			return result, err
		}

		return HTTPS_PREFIX + host, nil

	default:
		_, err := checkTarget(HTTPS_PREFIX + host)
		if err == nil {
			return HTTPS_PREFIX + host, err
		}

		body, err := checkTarget(HTTP_PREFIX + host)
		if err == nil {
			if strings.Contains(body, "<title>400 The plain HTTP request was sent to HTTPS port</title>") {
				return HTTPS_PREFIX + host, nil
			}
			return HTTP_PREFIX + host, nil
		}

	}

	return "", fmt.Errorf("host %q is empty", host)
}

func checkTarget(target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
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

	reader := io.LimitReader(resp.Body, maxDefaultBody)
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
