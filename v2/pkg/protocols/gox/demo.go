package gox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/retryablehttp"
)

func demo(target string, variableMap map[string]any) error {
	data := "hello world"
	setRequest(target+"\r\n"+data, variableMap)

	body := "hello world"
	setResponse(body, variableMap)

	// err := ExampleGet("http://example.com", true)
	// fmt.Println(err)

	setFullTarget(target, variableMap)

	return nil
}

func init() {
	funcMap["demo"] = demo
}

// GET 请求示例
// target  get request url
func ExampleGet(target string, redirect bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), retryhttpclient.GetDefaultTimeout())
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return err
	}

	// 自定义 headers
	req.Header.Add("Content-Type", "application/json")

	resp := &http.Response{}
	if !redirect {
		// 不重定向
		resp, err = retryhttpclient.RtryNoRedirect.Do(req)
	} else {
		// 重定向
		resp, err = retryhttpclient.RtryRedirect.Do(req)
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}

	// 获取 response body
	reader := io.LimitReader(resp.Body, retryhttpclient.GetMaxDefaultBody())
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	// GBK TO UTF-8
	utf8RespBody := utils.Str2UTF8(string(respBody))

	fmt.Println(resp.StatusCode)
	fmt.Println(utf8RespBody)

	return nil
}

// POST 请求示例
// target  post request url
// body  post request body
func ExamplePost(target, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), retryhttpclient.GetDefaultTimeout())
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return err
	}

	// 自定义 headers
	req.Header.Add("Content-Type", "application/json")

	resp, err := retryhttpclient.RtryNoRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}

	// 获取 response body
	reader := io.LimitReader(resp.Body, retryhttpclient.GetMaxDefaultBody())
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	// GBK TO UTF-8
	utf8RespBody := utils.Str2UTF8(string(respBody))

	fmt.Println(resp.StatusCode)
	fmt.Println(utf8RespBody)

	return nil
}
