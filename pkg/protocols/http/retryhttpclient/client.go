package retryhttpclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/retryablehttp"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

var (
	RtryRedirect   *retryablehttp.Client
	RtryNoRedirect *retryablehttp.Client

	RtryNoRedirectHttpClient *http.Client
	RtryRedirectHttpClient   *http.Client

	defaultMaxRedirects = 10
	defaultTimeout      = 20 * time.Second
)

const maxDefaultBody = 2 * 1024 * 1024

func Init(options *config.Options) (err error) {
	po := &retryablehttp.DefaultPoolOptions
	po.Proxy = options.Proxy
	po.Timeout = options.Timeout
	po.Retries = options.Retries
	po.DisableRedirects = true

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

	return nil
}

func Init2(options *config.Options) (err error) {
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

func Request(target string, rule poc.Rule, variableMap map[string]any) error {
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

	resp, err := RtryRedirect.Do(req)
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
		data, err := ioutil.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}
	return req, nil
}
