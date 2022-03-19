package main

import (
	"fmt"
	"net/http"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

func main() {
	urlStr := "http://baidu.com"

	options := config.Options{}
	// init config file
	config, err := config.New()
	if err != nil {
		return
	}
	options.Config = config

	FastClientReverse := http2.FastClient{}
	FastClientReverse.DialTimeout = 5
	FastClientReverse.Client = http2.New(&options)
	req, _ := http.NewRequest("GET", urlStr, nil)
	resp, err := FastClientReverse.SampleHTTPRequest(req)
	if err != nil {
		log.Log().Error(err.Error())
	}

	fmt.Println(string(resp.Body))
}
