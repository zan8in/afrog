package http

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/proto"
)

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
func New( /*option Options*/ ) *fasthttp.Client {
	readTimeout, _ := time.ParseDuration("15000ms")
	writeTimeout, _ := time.ParseDuration("15000ms")
	maxIdleConnDuration, _ := time.ParseDuration("1h")
	client := &fasthttp.Client{
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
	// client.Dial = fasthttpproxy.FasthttpHTTPDialerTimeout("localhost:10808", time.Second*5)
	// client.Dial = fasthttpproxy.FasthttpSocksDialer("socks5://localhost:10808")
	return client
}

func HTTPRequest(reqUrl string, FollowRedirects bool) error {
	var err error

	client := New()
	fastReq := fasthttp.AcquireRequest()
	fastReq.SetRequestURI(reqUrl)
	defer fasthttp.ReleaseRequest(fastReq)

	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fastResp)

	if FollowRedirects {
		err = client.DoRedirects(fastReq, fastResp, 5)
	} else {
		err = client.DoTimeout(fastReq, fastResp, time.Second*15)
	}
	if err != nil {
		log.Log().Error(err.Error())
		return err
	}

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

	protoRespPool := protoResponsePool.Get().(*proto.Response)
	protoRespPool.Status = int32(fastResp.StatusCode())
	u, err := url.Parse(fastReq.URI().String())
	if err != nil {
		log.Log().Error(err.Error())
		return err
	}
	protoRespPool.Url = &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
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
	protoRespPool.Headers = newheader
	protoRespPool.ContentType = string(fastResp.Header.ContentType())
	protoRespPool.Body = fastResp.Body()

	protoRespPool.Raw = []byte(fastResp.String())
	protoRespPool.RawHeader = fastResp.Header.Header()
	log.Log().Warn(string(fastResp.Header.Header()))
	fmt.Println("===========")
	fmt.Println(protoRespPool.Headers)

	return err
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
