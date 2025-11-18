package raw

import (
    "bytes"
    "compress/gzip"
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"

    "github.com/zan8in/afrog/v3/pkg/proto"
    "github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
    "github.com/zan8in/rawhttp"
)

var (
	rawHttpClient *rawhttp.Client
)

type RawHttp struct {
	RawhttpClient   *rawhttp.Client
	MaxRespBodySize int
}

func GetRawHTTP(proxy string, timeout int) *rawhttp.Client {
	if rawHttpClient == nil {
		rawHttpOptions := rawhttp.DefaultOptions

		if len(proxy) > 0 {
			if err := LoadProxyServers(proxy); err == nil {
				if ProxyURL != "" {
					rawHttpOptions.Proxy = ProxyURL
				} else if ProxySocksURL != "" {
					rawHttpOptions.Proxy = ProxySocksURL
				}
			}
		}

		rawHttpOptions.Timeout = time.Duration(timeout) * time.Second
		rawHttpClient = rawhttp.NewClient(rawHttpOptions)
	}
	return rawHttpClient
}

// 自定义 cookie 已弃用 2024.04.13
// func addCookie(request, cookie string) string {
// 	if len(cookie) == 0 {
// 		return request
// 	}

// 	list := strings.Split(request, "\n")
// 	isCookie := false
// 	for k, l := range list {
// 		if strings.HasPrefix(strings.ToLower(l), "cookie:") {
// 			list[k] = strings.TrimSuffix(l, ";") + "; " + cookie
// 			isCookie = true
// 		}
// 	}

// 	if !isCookie && len(list) > 2 {
// 		list = append(list[:2], append([]string{"Cookie: " + cookie}, list[2:]...)...)
// 	}

// 	return strings.Join(list, "\n")
// }

// 自定义 header 代替 自定义 cookie 2024.04.13
func addHeader(request, key, value string) string {
	if len(key) == 0 {
		return request
	}

	list := strings.Split(request, "\n")

	for k, l := range list {
		if strings.HasPrefix(strings.ToLower(l), strings.ToLower(key)+":") {
			list[k] = strings.TrimSuffix(l, ";") + "; " + strings.TrimLeft(value, " ")
			return strings.Join(list, "\n")
		}
	}

	if len(list) > 1 {
		list = append(list[:2], append([]string{key + ": " + strings.TrimLeft(value, " ")}, list[2:]...)...)
	}

	return strings.Join(list, "\n")
}

func appendHeader(request string, header []string) string {
	if len(header) == 0 {
		return request
	}
	for _, va := range header {
		arr := strings.Split(va, ":")
		key := strings.TrimSpace(arr[0])
		if found, ok := strings.CutPrefix(va, key+":"); ok && len(key) > 0 {
			request = addHeader(request, key, strings.TrimSpace(found))
		}
	}
	return request
}

func (r *RawHttp) RawHttpRequest(request, baseurl string, header []string, variableMap map[string]any) error {
	var err error
	var resp *http.Response

	variableMap["request"] = nil
	variableMap["response"] = nil

	request = AssignVariableRaw(request, variableMap)

	newheader := appendHeader(request, header)

    rhttp, err := Parse(newheader, baseurl, true)
    if err != nil {
        return fmt.Errorf("parse Failed, %s", err.Error())
    }

    ct := strings.ToLower(rhttp.Headers["Content-Type"])
    if strings.Contains(ct, "multipart/") {
        if strings.Contains(rhttp.Data, "\n") && !strings.Contains(rhttp.Data, "\r\n") {
            rhttp.Data = strings.ReplaceAll(rhttp.Data, "\n", "\r\n")
            if !strings.HasSuffix(rhttp.Data, "\r\n") {
                rhttp.Data = rhttp.Data + "\r\n"
            }
        }
        rhttp.Headers["Content-Length"] = fmt.Sprintf("%d", len(rhttp.Data))
    }

    resp, err = r.RawhttpClient.DoRaw(rhttp.Method, baseurl, rhttp.Path, ExpandMapValues(rhttp.Headers), io.NopCloser(strings.NewReader(rhttp.Data)))
	if err != nil {
		//fmt.Println(err.Error())
		return fmt.Errorf("doRaw Failed, %s", err.Error())
	}
	defer resp.Body.Close()

	// 新增最大响应体限制
	// @editor 2024/02/06
	maxDefaultBody := int64(r.MaxRespBodySize * 1024 * 1024)
    reader := io.LimitReader(resp.Body, maxDefaultBody)
    respBody, err := io.ReadAll(reader)
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
        tempResultResponse.Url = retryhttpclient.Url2UrlType(requrl)
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

    // gzip 解压支持
    bodyOut := respBody
    if strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
        if decompressed, derr := gunzip(respBody); derr == nil {
            bodyOut = decompressed
        }
    }

    tempResultResponse.Body = bodyOut
    tempResultResponse.Raw = []byte(string(dumpedResponseHeaders) + "\n" + string(bodyOut))
    tempResultResponse.RawHeader = dumpedResponseHeaders
    variableMap["response"] = tempResultResponse

	tempResultRequest := &proto.Request{}
	tempResultRequest.Method = rhttp.Method
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultRequest.Url = retryhttpclient.Url2UrlType(requrl)
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

    variableMap["fulltarget"] = fmt.Sprintf("%s://%s%s", tempResultRequest.Url.Scheme, tempResultRequest.Url.Host, rhttp.Path)

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

func gunzip(data []byte) ([]byte, error) {
    if len(data) == 0 {
        return data, nil
    }
    br := bytes.NewReader(data)
    zr, err := gzip.NewReader(br)
    if err != nil {
        return nil, err
    }
    defer zr.Close()
    out, err := io.ReadAll(zr)
    if err != nil {
        return nil, err
    }
    return out, nil
}
