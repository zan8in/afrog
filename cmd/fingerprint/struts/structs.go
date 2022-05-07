package struts

import (
	"encoding/json"
	"fmt"

	"github.com/zan8in/afrog/pkg/utils"
)

type FingerPrint struct {
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestData    string            `json:"request_data"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Keyword        []string          `json:"keyword"`
	FaviconHash    []string          `json:"favicon_hash"`
	Priority       int               `json:"priority"`
}

func GetFingerList() {
	content, err := utils.ReadFromFile("C:\\Users\\zanbi\\go\\src\\github.com\\zan8in\\afrog\\cmd\\fingerprint\\struts\\web_fingerprint_v3.json")
	if err != nil {
		fmt.Println("err,", err.Error())
		return
	}
	var ff []FingerPrint
	err = json.Unmarshal(content, &ff)
	if err != nil {
		fmt.Println("2err,", err.Error())
		return
	}
	fmt.Println(len(ff))
}
