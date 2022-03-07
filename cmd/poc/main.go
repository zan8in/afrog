package main

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/dlclark/regexp2"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

var options = &config.Options{}

func main() {
	readConfig()

	FastClient := &http2.FastClient{}
	FastClient.DialTimeout = 15
	FastClient.Client = http2.New(options)
	req, _ := http.NewRequest("GET", options.Targets[0], nil)
	resp, _ := FastClient.SampleHTTPRequest(req)

	body := resp.GetBody()

	v2 := "\"da2ta\":(?P<outputtest>.+?)}"
	re := regexp.MustCompile(v2)
	isMatch := re.MatchString(string(body))
	fmt.Println(isMatch)

	var resultMap = make(map[string]string)
	//v22 := "\"data\":(?P<outputtest>.+?)}"
	v22 := "<br/>(?P<path>.+?).ASPX"
	re2 := regexp2.MustCompile(string(v22), regexp2.RE2)
	if m, _ := re2.FindStringMatch(string(body)); m != nil {
		gps := m.Groups()
		for n, gp := range gps {
			if n == 0 {
				continue
			}
			resultMap[gp.Name] = gp.String()
		}
	}
	for k, v := range resultMap {
		fmt.Println(k, v)
	}

}

func readConfig() {
	options.Targets.Set("http://127.0.0.1/test1.php")

	pocsDir, err := poc.InitPocHomeDirectory()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.PocsDirectory.Set(pocsDir)

	config, err := config.New()
	if err != nil {
		log.Log().Fatal(err.Error())
	}
	options.Config = config

}
