package poc

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/xfrog/gocel"
)

var client *fasthttp.Client

var UrlTypePool = sync.Pool{
	New: func() interface{} {
		return new(gocel.UrlType)
	},
}

var fastReqPool = sync.Pool{
	New: func() interface{} {
		return *fasthttp.AcquireRequest()
	},
}

var fastRespPool = sync.Pool{
	New: func() interface{} {
		return *fasthttp.AcquireResponse()
	},
}

func init() {
	// You may read the timeouts from some config
	readTimeout, _ := time.ParseDuration("5000ms")
	writeTimeout, _ := time.ParseDuration("5000ms")
	maxIdleConnDuration, _ := time.ParseDuration("1h")
	client = &fasthttp.Client{
		TLSConfig:                     &tls.Config{InsecureSkipVerify: true},
		MaxConnsPerHost:               10000,
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		MaxIdleConnDuration:           maxIdleConnDuration,
		NoDefaultUserAgentHeader:      true, // Don't send: User-Agent: fasthttp
		DisableHeaderNamesNormalizing: true, // If you set the case on your headers correctly you can enable this
		DisablePathNormalizing:        true,
		MaxResponseBodySize:           1024 * 1024 * 2, // 2m
		// increase DNS cache time to an hour instead of default minute
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4096,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}
	client.Dial = fasthttpproxy.FasthttpHTTPDialerTimeout("localhost:10808", time.Second*5)
	// client.Dial = fasthttpproxy.FasthttpSocksDialer("socks5://localhost:10808")
	fmt.Println("======== fasthttp init()")
}

func (runner Runner) SendGetRequest(reqUrl string, ruleReq Rule) {
	fastReq := fasthttp.AcquireRequest()

	fastReq.SetRequestURI(reqUrl)
	fastReq.Header.SetMethod(ruleReq.Request.Method)

	for name, value := range ruleReq.Request.Headers {
		fastReq.Header.Set(name, value)
	}
	fastReq.SetBodyRaw([]byte(ruleReq.Request.Body))

	resp := fasthttp.AcquireResponse()
	err := client.DoRedirects(fastReq, resp, 5)

	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Println("DEBUG Response: ", resp.StatusCode(), string(fastReq.Header.RequestURI()))
	fmt.Println("DEBUG Request: ", string(fastReq.Header.Header()))
	fmt.Println("DEBUG Body: ", string(fastReq.Body()))

	//TODO 保存 gocel.response
	runner.GocelResponse.Url = ParseUrl(runner.TargetRequest.URL)
	runner.GocelResponse.Status = int32(resp.StatusCode())
	runner.GocelResponse.RawHeader = resp.Header.Header()
	runner.GocelResponse.Body = resp.Body()
	runner.GocelResponse.ContentType = string(resp.Header.ContentType())

	runner.Variablemap["response"] = runner.GocelResponse

	SetRunnerPool(runner)

	fasthttp.ReleaseRequest(fastReq)
	if err == nil {
		statusCode := resp.StatusCode()
		// respBody := resp.Body()
		if statusCode == http.StatusOK {
			// respEntity := &Entity{}
			// err = json.Unmarshal(respBody, respEntity)
			if err == io.EOF || err == nil {
				fmt.Printf("DEBUG Parsed Response: %s\n", resp.Header.ContentType())
			} else {
				fmt.Fprintf(os.Stderr, "ERR failed to parse reponse: %s\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "ERR invalid HTTP response code: %d\n", statusCode)
		}
	} else {
		fmt.Fprintf(os.Stderr, "ERR Connection error: %s\n", err)
	}
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	fasthttp.ReleaseResponse(resp)
}

func ParseUrl(u *url.URL) *gocel.UrlType {
	urlType := UrlTypePool.Get().(*gocel.UrlType)

	urlType.Scheme = u.Scheme
	urlType.Domain = u.Hostname()
	urlType.Host = u.Host
	urlType.Port = u.Port()
	urlType.Path = u.Path
	urlType.Query = u.RawQuery
	urlType.Fragment = u.Fragment

	return urlType
}

func SendGetRequest(reqUrl string) {
	fastReq := fasthttp.AcquireRequest()

	fastReq.SetRequestURI(reqUrl)

	resp := fasthttp.AcquireResponse()
	err := client.DoRedirects(fastReq, resp, 5)

	fasthttp.ReleaseRequest(fastReq)
	if err == nil {
		statusCode := resp.StatusCode()
		respBody := resp.Body()
		log.Log().Debug(string(respBody))
		if statusCode == http.StatusOK {
			// respEntity := &Entity{}
			// err = json.Unmarshal(respBody, respEntity)
			if err == io.EOF || err == nil {
				fmt.Printf("DEBUG Parsed Response: %s\n", resp.Header.ContentType())
			} else {
				fmt.Fprintf(os.Stderr, "ERR failed to parse reponse: %s\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "ERR invalid HTTP response code: %d\n", statusCode)
		}
	} else {
		fmt.Fprintf(os.Stderr, "ERR Connection error: %s\n", err)
	}
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	fasthttp.ReleaseResponse(resp)
}
