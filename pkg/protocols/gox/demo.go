package gox

import (
	"fmt"
	"net/http"
	"github.com/zan8in/afrog/v3/pkg/utils"
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
	respBody, status, _, err := FetchLimited(http.MethodGet, target, nil, nil, redirect, 0, 0, nil)
	if err != nil {
		return err
	}
	utf8RespBody := utils.Str2UTF8(string(respBody))

	fmt.Println(status)
	fmt.Println(utf8RespBody)

	return nil
}

// POST 请求示例
// target  post request url
// body  post request body
func ExamplePost(target, body string) error {
	headers := map[string]string{"Content-Type": "application/json"}
	respBody, status, _, err := FetchLimited(http.MethodPost, target, []byte(body), headers, false, 0, 0, nil)
	if err != nil {
		return err
	}

	// GBK TO UTF-8
	utf8RespBody := utils.Str2UTF8(string(respBody))

	fmt.Println(status)
	fmt.Println(utf8RespBody)

	return nil
}
