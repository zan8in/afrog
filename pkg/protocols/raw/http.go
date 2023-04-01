package raw

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/rawhttp"
	"github.com/zan8in/afrog/pkg/proto"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

var (
	rawHttpClient *rawhttp.Client
)

type RawHttp struct {
	RawhttpClient *rawhttp.Client
}

func GetRawHTTP(timeout int) *rawhttp.Client {
	if rawHttpClient == nil {
		rawHttpOptions := rawhttp.DefaultOptions
		rawHttpOptions.Timeout = time.Duration(timeout) * time.Second
		rawHttpClient = rawhttp.NewClient(rawHttpOptions)
	}
	return rawHttpClient
}

func (r *RawHttp) RawHttpRequest(request, baseurl string, variableMap map[string]any) error {
	var err error
	var resp *http.Response

	variableMap["request"] = nil
	variableMap["response"] = nil

	request = AssignVariableRaw(request, variableMap)

	rhttp, err := Parse(request, baseurl, true)
	if err != nil {
		return fmt.Errorf("parse Failed, %s", err.Error())
	}

	resp, err = r.RawhttpClient.DoRaw(rhttp.Method, baseurl, rhttp.Path, ExpandMapValues(rhttp.Headers), ioutil.NopCloser(strings.NewReader(rhttp.Data)))
	if err != nil {
		//fmt.Println(err.Error())
		return fmt.Errorf("doRaw Failed, %s", err.Error())
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("readAll Failed, %s", err.Error())
	}

	dumpedResponseHeaders, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return fmt.Errorf("dumpResponse Failed, %s", err.Error())
	}

	tempResultResponse := &proto.Response{}
	tempResultResponse.Status = int32(resp.StatusCode)
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultResponse.Url = http2.Url2UrlType(requrl)
	}
	newheader2 := make(map[string]string)
	respHeaderSlice := strings.Split(strings.TrimSpace(string(dumpedResponseHeaders)), "\n")
	for _, h := range respHeaderSlice {
		h = strings.Trim(h, "\r\n")
		hslice := strings.SplitN(h, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader2[k] != "" {
			newheader2[k] += v
		} else {
			newheader2[k] = v
		}
	}
	tempResultResponse.Headers = newheader2
	tempResultResponse.ContentType = resp.Header.Get("Content-Type")
	tempResultResponse.Body = respBody
	tempResultResponse.Raw = []byte(string(dumpedResponseHeaders) + "\n" + string(respBody))
	tempResultResponse.RawHeader = dumpedResponseHeaders
	variableMap["response"] = tempResultResponse

	tempResultRequest := &proto.Request{}
	tempResultRequest.Method = rhttp.Method
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultRequest.Url = http2.Url2UrlType(requrl)
	}
	newheader1 := map[string]string{}
	for _, v := range rhttp.UnsafeHeaders {
		key, _ := v.Key, v.Value
		if len(strings.TrimSpace(key)) == 0 {
			continue
		}
		key = strings.Trim(key, ":")
		hslice := strings.SplitN(key, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader1[k] != "" {
			newheader1[k] += v
		} else {
			newheader1[k] = v
		}
	}
	tempResultRequest.Headers = newheader1
	tempResultRequest.Raw = rhttp.UnsafeRawBytes
	if len(string(rhttp.UnsafeRawBytes)) > 0 {
		rawSplit := strings.Split(string(rhttp.UnsafeRawBytes), "\n\n")
		if len(rawSplit) > 1 {
			tempResultRequest.RawHeader = []byte(rawSplit[0])
		} else {
			tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
		}
	} else {
		tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
	}
	tempResultRequest.Body = []byte(rhttp.Data)
	tempResultRequest.ContentType = tempResultRequest.Headers["content-type"]
	variableMap["request"] = tempResultRequest

	variableMap["fulltarget"] = fmt.Sprintf("%s://%s%s", tempResultRequest.Url.Scheme, tempResultRequest.Url.Host, tempResultRequest.Url.Path)

	return err
}

func AssignVariableRaw(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		newstr := fmt.Sprintf("%v", v)
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, newstr)
	}
	return find
}
