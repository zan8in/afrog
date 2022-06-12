package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/axgle/mahonia"
	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/config"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/scan"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	options = &config.Options{}
	pTitle  = regexp.MustCompile(`(?i:)<title>(.*?)</title>`)
)

func main() {
	urls, err := utils.ReadFileLineByLine("./urls.txt")
	if err != nil {
		fmt.Println("urls is empty.")
		return
	}

	for _, u := range urls {
		ip, err := scan.Target2ip(u)
		if err != nil {
			fmt.Println(err.Error(), u)
			continue
		}
		fmt.Println(u, ip)
	}

	return
	config, err := config.New()
	if err != nil {
		fmt.Println("config is empty.")
		return
	}
	options.Config = config
	http2.Init(options)

	// rand.Seed(time.Now().UnixNano())

	swg := sizedwaitgroup.New(50)
	for _, url := range urls {
		swg.Add()
		go func(url string) {
			defer swg.Done()
			ipscan(url)
		}(url)
	}

	swg.Wait()

}

func ipscan(url string) {
	// Typical use-case:
	// 50 queries must be executed as quick as possible
	// but without overloading the database, so only
	// 8 routines should be started concurrently.
	portSlice := []int{80, 443, 8080, 7001}
	swg := sizedwaitgroup.New(500)
	// for i := 1; i < 65535; i++ {
	for _, i := range portSlice {
		swg.Add()
		go func(url string, i int) {
			defer swg.Done()
			err := title(url, i, 0)
			if err != nil {
				title(url, i, 1)
			}
		}(url, i)
	}

	swg.Wait()
}

func title(url string, port, https int) error {
	if https == 0 {
		url = "http://" + url + ":" + strconv.Itoa(port)
	} else {
		url = "https://" + url + ":" + strconv.Itoa(port)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, status, err := http2.GetTitleRedirect(req, 3)
	if err != nil {
		return err
	}
	if status < 200 || (status >= 300 && status < 400) || status >= 600 {
		return err
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
	return nil
}
