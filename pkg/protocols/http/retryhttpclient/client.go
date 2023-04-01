package retryhttpclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

var (
	RtryRedirect   *retryablehttp.Client
	RtryNoRedirect *retryablehttp.Client

	RtryNoRedirectHttpClient *http.Client
	RtryRedirectHttpClient   *http.Client
	defaultMaxRedirects      = 10
)

const maxDefaultBody = 2 * 1024 * 1024

func Init(options *config.Options) (err error) {
	retryableHttpOptions := retryablehttp.DefaultOptionsSpraying
	maxIdleConns := 0
	maxConnsPerHost := 0
	maxIdleConnsPerHost := -1
	disableKeepAlives := true // 默认 false

	// retryableHttpOptions = retryablehttp.DefaultOptionsSingle
	// disableKeepAlives = false
	// maxIdleConnsPerHost = 500
	// maxConnsPerHost = 500

	maxIdleConns = 1000                        //
	maxIdleConnsPerHost = runtime.NumCPU() * 2 //
	idleConnTimeout := 15 * time.Second        //
	tLSHandshakeTimeout := 5 * time.Second     //

	dialer := &net.Dialer{ //
		Timeout:   time.Duration(options.Timeout) * time.Second,
		KeepAlive: 15 * time.Second,
	}

	retryableHttpOptions.RetryWaitMax = 10 * time.Second
	retryableHttpOptions.RetryMax = options.Retries

	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   disableKeepAlives,
		TLSHandshakeTimeout: tLSHandshakeTimeout, //
		IdleConnTimeout:     idleConnTimeout,     //
	}

	// transport = &http.Transport{
	// 	// DialContext:         dialer.Dial,
	// 	// DialTLSContext:      dialer.DialTLS,
	// 	MaxIdleConns:        500,
	// 	MaxIdleConnsPerHost: 500,
	// 	MaxConnsPerHost:     500,
	// 	TLSClientConfig:     tlsConfig,
	// }

	// proxy

	if config.ProxyURL != "" {
		if proxyURL, err := url.Parse(config.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if config.ProxySocksURL != "" {
		socksURL, proxyErr := url.Parse(config.ProxySocksURL)
		if proxyErr != nil {
			return proxyErr
		}
		dialer, err := proxy.FromURL(socksURL, proxy.Direct)
		if err != nil {
			return err
		}

		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		if proxyErr == nil {
			transport.DialContext = dc.DialContext
			transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				// upgrade proxy connection to tls
				conn, err := dc.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return tls.Client(conn, tlsConfig), nil
			}
		}
	}

	// follow redirects client
	// clientCookieJar, _ := cookiejar.New(nil)

	httpRedirectClient := http.Client{
		Transport: transport,
		Timeout:   time.Duration(options.Timeout) * time.Second,
		// Jar:       clientCookieJar,
	}

	RtryRedirect = retryablehttp.NewWithHTTPClient(&httpRedirectClient, retryableHttpOptions)
	RtryRedirect.CheckRetry = retryablehttp.HostSprayRetryPolicy()
	RtryRedirectHttpClient = RtryRedirect.HTTPClient

	// whitespace

	// disabled follow redirects client
	// clientNoRedirectCookieJar, _ := cookiejar.New(nil)

	httpNoRedirectClient := http.Client{
		Transport: transport,
		Timeout:   time.Duration(options.Timeout) * time.Second,
		// Jar:           clientNoRedirectCookieJar,
		CheckRedirect: makeCheckRedirectFunc(false, defaultMaxRedirects),
	}

	RtryNoRedirect = retryablehttp.NewWithHTTPClient(&httpNoRedirectClient, retryableHttpOptions)
	RtryNoRedirect.CheckRetry = retryablehttp.HostSprayRetryPolicy()
	RtryNoRedirectHttpClient = RtryNoRedirect.HTTPClient

	return err
}

func Request(ctx context.Context, target string, rule poc.Rule, variableMap map[string]any) error {
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
	newpath = strings.ReplaceAll(newpath, "+", "%20")
	newpath = strings.ReplaceAll(newpath, "#", "%23")

	target = target + newpath

	// body
	if strings.HasPrefix(strings.ToLower(rule.Request.Headers["Content-Type"]), "multipart/form-Data") && strings.Contains(rule.Request.Body, "\n\n") {
		multipartBody, err := dealMultipart(rule.Request.Headers["Content-Type"], rule.Request.Body)
		if err != nil {
			return err
		}
		rule.Request.Body = setVariableMap(strings.TrimSpace(multipartBody), variableMap)
	} else {
		rule.Request.Body = setVariableMap(strings.TrimSpace(rule.Request.Body), variableMap)
	}

	// newhttprequest
	req, err := retryablehttp.NewRequest(rule.Request.Method, target, nil)
	if len(rule.Request.Body) > 0 {
		req, err = retryablehttp.NewRequest(rule.Request.Method, target, strings.NewReader(rule.Request.Body))
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
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	// respbody gbk to utf8 encoding
	utf8RespBody := utils.Str2UTF8(string(respBody))

	// store the response
	protoResp := &proto.Response{}
	protoResp.Status = int32(resp.StatusCode)
	protoResp.Url = url2ProtoUrl(resp.Request.URL)

	newRespHeader := make(map[string]string)
	rawHeaderBuilder := strings.Builder{}
	for k := range resp.Header {
		newRespHeader[strings.ToLower(k)] = resp.Header.Get(k)

		rawHeaderBuilder.WriteString(k)
		rawHeaderBuilder.WriteString(": ")
		rawHeaderBuilder.WriteString(resp.Header.Get(k))
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
	protoReq.Url = url2ProtoUrl(req.URL)

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
	protoReq.Raw = []byte(req.Method + " " + reqPath + " " + req.Proto + "\n" + "Host: " + req.URL.Host + "\n" + strings.Trim(rawReqHeaderBuilder.String(), "\n") + "\n\n" + string(rule.Request.Body))
	protoReq.RawHeader = []byte(strings.Trim(rawReqHeaderBuilder.String(), "\n"))
	variableMap["request"] = protoReq

	// store the full target url
	variableMap["fulltarget"] = target

	return nil
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

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(followRedirects bool, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}

		if maxRedirects == 0 {
			if len(via) > defaultMaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}

		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func simpleRtryHttpGet(target string) ([]byte, int, error) {
	if len(target) == 0 {
		return []byte(""), 0, errors.New("no target specified")
	}

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
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

// body is parameters 1
// headers is parameters 2
// statusCode is parameters 3
// err is parameters 4
func simpleRtryRedirectGet(target string) ([]byte, map[string][]string, int, error) {
	if len(target) == 0 {
		return []byte(""), nil, 0, errors.New("no target specified")
	}

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	req.Header.Add("User-Agent", utils.RandomUA())

	resp, err := RtryRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return []byte(""), nil, 0, err
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return []byte(""), nil, 0, err
	}

	newheader := make(map[string][]string)
	for k := range resp.Header {
		newheader[k] = []string{resp.Header.Get(k)}

	}

	return respBody, newheader, resp.StatusCode, nil
}

// Check http or https And Check host live status
// returns response body and status code
// status code = -1 means server responded failed
func CheckHttpsAndLives(target string) (string, int) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		_, statusCode, err := simpleRtryHttpGet(target)
		if err == nil {
			return target, statusCode
		}
		return target, -1
	}

	u, err := url.Parse("http://" + target)
	if err != nil {
		return target, -1
	}

	port := u.Port()

	switch {
	case port == "80" || len(port) == 0:
		_, statusCode, err := simpleRtryHttpGet("http://" + target)
		if err == nil {
			return "http://" + target, statusCode
		}
		return target, -1

	case port == "443" || strings.HasSuffix(port, "443"):
		_, statusCode, err := simpleRtryHttpGet("https://" + target)
		if err == nil {
			return "https://" + target, statusCode
		}
		return target, -1
	}

	resp, statusCode, err := simpleRtryHttpGet("http://" + target)
	if err == nil {
		if bytes.Contains(resp, []byte("<title>400 The plain HTTP request was sent to HTTPS port</title>")) {
			return "https://" + target, statusCode
		}
		return "http://" + target, statusCode
	}

	_, statusCode, err = simpleRtryHttpGet("https://" + target)
	if err == nil {
		return "https://" + target, statusCode
	}

	return target, -1
}

// Reverse URL Get request
func ReverseGet(target string) ([]byte, error) {
	if len(target) == 0 {
		return []byte(""), errors.New("target not find")
	}
	respBody, _, err := simpleRtryHttpGet(target)
	return respBody, err
}

func FingerPrintGet(target string) ([]byte, map[string][]string, int, error) {
	return simpleRtryRedirectGet(target)
}
