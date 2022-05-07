package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/axgle/mahonia"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/fingerprint"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	options = &config.Options{}
	pTitle  = regexp.MustCompile(`(?i:)<title>(.*?)</title>`)
)

func main() {
	urls, err := utils.ReadFileLineByLine("./test2.txt")
	if err != nil {
		fmt.Println("urls is empty.")
		return
	}
	config, err := config.New()
	if err != nil {
		fmt.Println("config is empty.")
		return
	}
	options.Config = config
	http2.Init(options)

	rand.Seed(time.Now().UnixNano())

	options.Targets = append(options.Targets, urls...)
	service, err := fingerprint.New(options)
	if err != nil {
		return
	}
	service.Execute()

	fmt.Println("endding.....")

}

func title(url string) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//fmt.Println("NewRequest", url, err.Error())
		return
	}
	resp, status, err := http2.GetTitleRedirect(req, 3)
	if err != nil {
		//fmt.Println("FastRequest", url, resp, err.Error())
		return
	}
	titleArr := pTitle.FindStringSubmatch(string(resp))
	if titleArr != nil {
		if len(titleArr) == 2 {
			sTitle := titleArr[1]
			if !utf8.ValidString(sTitle) {
				sTitle = mahonia.NewDecoder("gb18030").ConvertString(sTitle)
			}
			fmt.Println(url, status, sTitle)
		}
	} else {
		fmt.Println(url, status)
	}
}
