package main

import (
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/config"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/utils"
	"math/rand"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"
)

var (
	options = &config.Options{}
	pTitle  = regexp.MustCompile(`(?i:)<title>(.*?)</title>`)
)

func main() {
	urls, err := utils.ReadFileLineByLine("./test.txt")
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

	// Typical use-case:
	// 50 queries must be executed as quick as possible
	// but without overloading the database, so only
	// 8 routines should be started concurrently.
	swg := sizedwaitgroup.New(118)
	for _, url := range urls {
		swg.Add()
		go func(url string) {
			defer swg.Done()
			title(url)
		}(url)
	}

	swg.Wait()

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
