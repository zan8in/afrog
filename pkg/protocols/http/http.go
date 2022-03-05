package http

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
)

type FastClient struct {
	Client          *fasthttp.Client
	MaxRedirect     int32
	NewProtoRequest *proto.Request  // 变形后request
	ResultResponse  *proto.Response // 储存结果
	Data            []byte          // post data
	VariableMap     map[string]interface{}
}

var protoRequestPool sync.Pool = sync.Pool{
	New: func() interface{} {
		return new(proto.Request)
	},
}

var protoResponsePool sync.Pool = sync.Pool{
	New: func() interface{} {
		return new(proto.Response)
	},
}

// fasthttp initialization
// configuration proxy、readtimeout、writetimeout、max_idle、concurrency、max_responsebody_sizse、max_redirect_count eg.
func New(options *config.Options) *fasthttp.Client {
	readTimeout, _ := time.ParseDuration(options.Config.ConfigHttp.ReadTimeout)
	writeTimeout, _ := time.ParseDuration(options.Config.ConfigHttp.WriteTimeout)
	maxIdleConnDuration, _ := time.ParseDuration(options.Config.ConfigHttp.MaxIdle)
	client := &fasthttp.Client{
		TLSConfig:                     &tls.Config{InsecureSkipVerify: true},
		MaxConnsPerHost:               options.Config.ConfigHttp.MaxConnsPerHost,
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		MaxIdleConnDuration:           maxIdleConnDuration,
		NoDefaultUserAgentHeader:      true, // Don't send: User-Agent: fasthttp
		DisableHeaderNamesNormalizing: true, // If you set the case on your headers correctly you can enable this
		DisablePathNormalizing:        true,
		MaxResponseBodySize:           options.Config.ConfigHttp.MaxResponseBodySize, // 2m
		// increase DNS cache time to an hour instead of default minute
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      options.Config.ConfigHttp.Concurrency,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}
	if len(strings.TrimSpace(options.Config.ConfigHttp.Proxy)) > 0 {
		// client.Dial = fasthttpproxy.FasthttpHTTPDialerTimeout("localhost:10808", time.Second*5) // http proxy 有问题，不支持https访问
		client.Dial = fasthttpproxy.FasthttpSocksDialer("socks5://" + options.Config.ConfigHttp.Proxy)
	}

	return client
}

func (fc *FastClient) HTTPRequest(httpRequest *http.Request, rule poc.Rule, params map[string]interface{}) error {
	var err error
	fc.VariableMap = params
	fc.NewProtoRequest = GetProtoRequestPool()
	fc.ResultResponse = GetProtoResponsePool()

	reqUrl := httpRequest.URL.String()

	// 处理 fasthttp 请求
	fastReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fastReq)

	err = CopyRequest(httpRequest, fastReq, fc.Data)
	if err != nil {
		log.Log().Error(fmt.Sprintf("Request Body [%s] 原始请求转为fasthttp失败", reqUrl))
		return err
	}

	// 覆盖 header
	fastReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range rule.Request.Headers {
		fastReq.Header.Set(k, fc.AssignVariableMap(v))
	}
	// 覆盖 method
	fastReq.Header.SetMethod(rule.Request.Method)

	// 覆盖path变量
	tempPath := ""
	if strings.HasPrefix(rule.Request.Path, "/") {
		// 如果 path 是以 / 开头的， 取 dir 路径拼接
		tempPath = strings.TrimRight(httpRequest.URL.Path, "/") + rule.Request.Path
	} else if strings.HasPrefix(rule.Request.Path, "^") {
		// 如果 path 是以 ^ 开头的， uri 直接取该路径
		tempPath = "/" + rule.Request.Path[1:]
	}
	// 某些poc没有区分path和query，需要处理
	tempPath = strings.ReplaceAll(tempPath, " ", "%20")
	tempPath = strings.ReplaceAll(tempPath, "+", "%20")
	// fastReq.SetRequestURI(tempPath)
	fastReq.URI().Update(fc.AssignVariableMap(strings.TrimSpace(tempPath)))

	// 处理 multipart 及 覆盖body变量
	contentType := string(fastReq.Header.ContentType())
	if strings.HasPrefix(strings.ToLower(contentType), "multipart/form-Data") && strings.Contains(rule.Request.Body, "\n\n") {
		multipartBody, err := DealMultipart(contentType, rule.Request.Body)
		if err != nil {
			return err
		}
		fastReq.SetBody([]byte(fc.AssignVariableMap(strings.TrimSpace(multipartBody))))
	} else {
		fastReq.SetBody([]byte(fc.AssignVariableMap(strings.TrimSpace(rule.Request.Body))))
	}

	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fastResp)
	if rule.Request.FollowRedirects {
		maxrd := 5
		if fc.MaxRedirect > 0 {
			maxrd = int(fc.MaxRedirect)
		}
		err = fc.Client.DoRedirects(fastReq, fastResp, maxrd)
	} else {
		err = fc.Client.DoTimeout(fastReq, fastResp, time.Second*15)
	}
	if err != nil {
		log.Log().Error(err.Error())
		return err
	}

	// log.Log().Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	// log.Log().Info(fastReq.URI().String())
	// log.Log().Info(string(fastReq.RequestURI()))
	// log.Log().Info(string(fastReq.Header.Header()))
	// log.Log().Info(string(fastReq.Body()))
	// // log.Log().Info(fastReq.String())
	// log.Log().Info("-----------------------------------------------------")

	var respBody []byte
	contentEncoding := strings.ToLower(string(fastResp.Header.Peek("Content-Encoding")))
	switch contentEncoding {
	case "", "none", "identity":
		respBody = fastResp.Body()
	case "gzip":
		respBody, err = fastResp.BodyGunzip()
	case "deflate":
		respBody, err = fastResp.BodyInflate()
	default:
		respBody = []byte{}
	}
	if err != nil {
		log.Log().Error(err.Error())
		return err
	}
	fastResp.SetBody(respBody)

	// 处理 reponse
	fc.ResultResponse = protoResponsePool.Get().(*proto.Response)
	fc.ResultResponse.Status = int32(fastResp.StatusCode())
	u, err := url.Parse(fastReq.URI().String())
	if err != nil {
		log.Log().Error(err.Error())
		return err
	}
	urlType := &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.Path,
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
	fc.ResultResponse.Url = urlType

	newheader := make(map[string]string)
	respHeaderSlice := strings.Split(fastResp.Header.String(), "\r\n")
	for _, h := range respHeaderSlice {
		hslice := strings.SplitN(h, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader[k] != "" {
			newheader[k] += v
		} else {
			newheader[k] = v
		}
	}
	fc.ResultResponse.Headers = newheader
	fc.ResultResponse.ContentType = string(fastResp.Header.ContentType())
	fc.ResultResponse.Body = fastResp.Body()

	fc.ResultResponse.Raw = []byte(fastResp.String())
	fc.ResultResponse.RawHeader = fastResp.Header.Header()
	// fc.ResultResponse.Conn.Source.Addr = fastResp.LocalAddr().String()
	// fc.ResultResponse.Conn.Destination.Addr = fastResp.RemoteAddr().String()

	fc.VariableMap["response"] = fc.ResultResponse

	// 处理 request
	fc.NewProtoRequest.Method = string(fastReq.Header.Method())
	fc.NewProtoRequest.Url = urlType

	newReqheader := make(map[string]string)
	reqHeaderSlice := strings.Split(fastReq.Header.String(), "\r\n")
	for _, h := range reqHeaderSlice {
		hslice := strings.SplitN(h, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newReqheader[k] != "" {
			newReqheader[k] += v
		} else {
			newReqheader[k] = v
		}
	}
	fc.NewProtoRequest.Headers = newReqheader
	fc.NewProtoRequest.ContentType = newReqheader["Content-Type"]
	fc.NewProtoRequest.Body = fastReq.Body()
	fc.VariableMap["request"] = fc.NewProtoRequest

	// fmt.Println("+++++++++++++++++++++++++++++")
	// fmt.Println(string(fastReq.URI().RequestURI()))
	// fmt.Println(string(fastReq.RequestURI()))
	// fmt.Println("+++++++++++++++++++++++++++++")

	return err
}

func DealMultipart(contentType string, ruleBody string) (result string, err error) {
	errMsg := ""
	// 处理multipart的/n
	re := regexp.MustCompile(`(?m)multipart\/form-Data; boundary=(.*)`)
	match := re.FindStringSubmatch(contentType)
	if len(match) != 2 {
		errMsg = "no boundary in content-type"
		return "", errors.New(errMsg)
	}
	boundary := "--" + match[1]
	multiPartContent := ""

	// 处理rule
	multiFile := strings.Split(ruleBody, boundary)
	if len(multiFile) == 0 {
		errMsg = "ruleBody.Body multi content format err"
		//logging.GlobalLogger.Error("util/requests.go:DealMultipart Err", errMsg)
		return multiPartContent, errors.New(errMsg)
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

// 替换变量的值
// find string 规定要查找的值
// oldstr 规定被搜索的字符串
// newstr 规定替换的值
func (fc *FastClient) AssignVariableMap(find string) string {
	for k, v := range fc.VariableMap {
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

func CopyRequest(req *http.Request, dstRequest *fasthttp.Request, data []byte) error {
	curURL := req.URL.String()
	dstRequest.SetRequestURI(curURL)
	dstRequest.Header.SetMethod(req.Method)

	for name, values := range req.Header {
		// Loop over all values for the name.
		for index, value := range values {
			if index > 0 {
				dstRequest.Header.Add(name, value)
			} else {
				dstRequest.Header.Set(name, value)
			}
		}
	}
	dstRequest.SetBodyRaw(data)
	return nil
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

func GetProtoRequestPool() *proto.Request {
	return protoRequestPool.Get().(*proto.Request)
}

func PutProtoRequestPool(req *proto.Request) {
	if req != nil {
		req.Reset()
		protoRequestPool.Put(req)
	}
}

func GetProtoResponsePool() *proto.Response {
	return protoResponsePool.Get().(*proto.Response)
}

func PutProtoResponsePool(rsp *proto.Response) {
	if rsp != nil {
		rsp.Reset()
		protoResponsePool.Put(rsp)
	}
}
