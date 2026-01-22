package gox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"github.com/zan8in/retryablehttp"
)

var funcMap = map[string]any{}

const httpSenderVarKey = "__gox_http_sender"

func Request(target, data string, variableMap map[string]any) error {
	if variableMap == nil {
		variableMap = make(map[string]any)
	}
	err := callFunction(data, []any{target, variableMap}, funcMap)
	if err != nil {
		return err.(error)
	}

	if variableMap["target"] == nil {
		variableMap["target"] = target
	}
	if variableMap["fulltarget"] == nil {
		if s, ok := variableMap["target"].(string); ok && len(strings.TrimSpace(s)) > 0 {
			variableMap["fulltarget"] = s
		} else {
			variableMap["fulltarget"] = target
		}
	}
	if variableMap["request"] == nil {
		variableMap["request"] = &proto.Request{}
	}
	if variableMap["response"] == nil {
		variableMap["response"] = &proto.Response{}
	}
	return nil
}

func callFunction(name string, args []interface{}, funcMap map[string]interface{}) interface{} {
	f, ok := funcMap[name]
	if !ok {
		gologger.Debug().Msgf("function %s not found", name)
		return nil
	}

	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Func {
		gologger.Debug().Msgf("%s is not a function", name)
		return nil
	}
	in := make([]reflect.Value, len(args))
	for i, arg := range args {
		in[i] = reflect.ValueOf(arg)
	}
	out := v.Call(in)
	if len(out) == 0 {
		return nil
	}
	return out[0].Interface()
}

func setRequest(data string, vmap map[string]any) {
	vmap["request"] = &proto.Request{
		Raw:  []byte(data),
		Body: []byte(data),
	}
}

func setResponse(data string, vmap map[string]any) {
	vmap["response"] = &proto.Response{
		Raw:  []byte(data),
		Body: []byte(data),
	}
	if vmap != nil {
		vmap["response_text"] = utils.Str2UTF8(data)
	}
}

func setFullTarget(data string, vmap map[string]any) {
	vmap["fulltarget"] = data
}

func setTarget(data string, vmap map[string]any) {
	vmap["target"] = data
}

type HTTPSender interface {
	Do(ctx context.Context, method string, target string, body []byte, headers map[string]string, followRedirects bool, variableMap map[string]any) (*proto.Response, error)
}

type defaultHTTPSender struct{}

func (s *defaultHTTPSender) Do(ctx context.Context, method string, target string, body []byte, headers map[string]string, followRedirects bool, variableMap map[string]any) (*proto.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("empty target")
	}

	var req *retryablehttp.Request
	var err error
	if body == nil {
		req, err = retryablehttp.NewRequestWithContext(ctx, method, target, nil)
	} else {
		req, err = retryablehttp.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	}
	if err != nil {
		return nil, err
	}

	if variableMap != nil {
		if v := variableMap["__global_headers"]; v != nil {
			if headerLines, ok := v.([]string); ok && len(headerLines) > 0 {
				retryhttpclient.ApplyHeaderLines(req, headerLines, false)
			}
		}
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Request.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	if retryhttpclient.DefaultAcceptEnabled() && len(req.Header.Get("Accept")) == 0 {
		req.Header.Add("Accept", "*/*")
	}

	if strings.EqualFold(method, http.MethodPost) && len(req.Header.Get("Content-Type")) == 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Add("User-Agent", utils.RandomUA())
	}

	var milliseconds int64
	start := time.Now()
	trace := httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			milliseconds = time.Since(start).Nanoseconds() / 1e6
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	resp := &http.Response{}
	if !followRedirects {
		resp, err = retryhttpclient.RtryNoRedirect.Do(req)
	} else {
		resp, err = retryhttpclient.RtryRedirect.Do(req)
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}

	var buf bytes.Buffer
	lr := io.LimitedReader{R: resp.Body, N: retryhttpclient.GetMaxDefaultBody()}
	_, err = io.Copy(&buf, &lr)
	if err != nil {
		if !strings.Contains(err.Error(), "user canceled") && !errors.Is(err, io.ErrUnexpectedEOF) {
			resp.Body.Close()
			return nil, err
		}
	}
	resp.Body.Close()
	respBody := buf.Bytes()

	responseText := ""
	if len(respBody) > 0 {
		responseText = utils.Str2UTF8(string(respBody))
	}

	if variableMap != nil {
		variableMap["response_text"] = responseText
	}
	retryhttpclient.WriteHTTPResponseToVars(variableMap, resp, respBody, milliseconds)
	retryhttpclient.WriteHTTPRequestToVars(variableMap, req, string(body), target, req.URL.URL)
	if variableMap != nil {
		if resp != nil && resp.Request != nil && resp.Request.URL != nil {
			variableMap["fulltarget"] = resp.Request.URL.String()
		} else {
			variableMap["fulltarget"] = target
		}
	}

	if v := variableMap["response"]; v != nil {
		if pr, ok := v.(*proto.Response); ok {
			return pr, nil
		}
	}
	return nil, nil
}

func InjectDefaultHTTPSender(variableMap map[string]any) {
	if variableMap == nil {
		return
	}
	if _, ok := variableMap[httpSenderVarKey]; ok {
		return
	}
	variableMap[httpSenderVarKey] = &defaultHTTPSender{}
}

func getHTTPSender(variableMap map[string]any) HTTPSender {
	if variableMap == nil {
		return &defaultHTTPSender{}
	}
	if v, ok := variableMap[httpSenderVarKey]; ok && v != nil {
		if s, ok := v.(HTTPSender); ok && s != nil {
			return s
		}
	}
	s := &defaultHTTPSender{}
	variableMap[httpSenderVarKey] = s
	return s
}

func DoHTTP(method string, target string, body []byte, headers map[string]string, followRedirects bool, variableMap map[string]any) (*proto.Response, error) {
	if variableMap == nil {
		variableMap = make(map[string]any)
	}
	baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, retryhttpclient.GetDefaultTimeout())
	defer cancel()
	return getHTTPSender(variableMap).Do(ctx, method, target, body, headers, followRedirects, variableMap)
}

func DoHTTPWithTimeout(timeout time.Duration, method string, target string, body []byte, headers map[string]string, followRedirects bool, variableMap map[string]any) (*proto.Response, error) {
	if timeout <= 0 {
		timeout = retryhttpclient.GetDefaultTimeout()
	}
	if variableMap == nil {
		variableMap = make(map[string]any)
	}
	baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()
	return getHTTPSender(variableMap).Do(ctx, method, target, body, headers, followRedirects, variableMap)
}

func FetchLimited(method string, target string, body []byte, headers map[string]string, followRedirects bool, timeout time.Duration, maxBytes int64, variableMap map[string]any) ([]byte, int, int64, error) {
	if timeout <= 0 {
		timeout = retryhttpclient.GetDefaultTimeout()
	}
	if maxBytes <= 0 {
		maxBytes = retryhttpclient.GetMaxDefaultBody()
	}
	baseCtx := retryhttpclient.ContextFromVariableMap(variableMap)
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	var req *retryablehttp.Request
	var err error
	if body == nil {
		req, err = retryablehttp.NewRequestWithContext(ctx, method, target, nil)
	} else {
		req, err = retryablehttp.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	}
	if err != nil {
		return nil, 0, 0, err
	}

	if variableMap != nil {
		if v := variableMap["__global_headers"]; v != nil {
			if headerLines, ok := v.([]string); ok && len(headerLines) > 0 {
				retryhttpclient.ApplyHeaderLines(req, headerLines, false)
			}
		}
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Request.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	if retryhttpclient.DefaultAcceptEnabled() && len(req.Header.Get("Accept")) == 0 {
		req.Header.Add("Accept", "*/*")
	}

	if strings.EqualFold(method, http.MethodPost) && len(req.Header.Get("Content-Type")) == 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Add("User-Agent", utils.RandomUA())
	}

	var milliseconds int64
	start := time.Now()
	trace := httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			milliseconds = time.Since(start).Nanoseconds() / 1e6
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	resp := &http.Response{}
	if !followRedirects {
		resp, err = retryhttpclient.RtryNoRedirect.Do(req)
	} else {
		resp, err = retryhttpclient.RtryRedirect.Do(req)
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, 0, milliseconds, err
	}
	defer resp.Body.Close()

	reader := io.LimitReader(resp.Body, maxBytes)
	data, err := io.ReadAll(reader)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), "user canceled") {
		return nil, resp.StatusCode, milliseconds, err
	}

	if variableMap != nil {
		responseText := ""
		if len(data) > 0 {
			responseText = utils.Str2UTF8(string(data))
		}
		variableMap["response_text"] = responseText
		retryhttpclient.WriteHTTPResponseToVars(variableMap, resp, data, milliseconds)
		retryhttpclient.WriteHTTPRequestToVars(variableMap, req, string(body), target, req.URL.URL)
		if resp != nil && resp.Request != nil && resp.Request.URL != nil {
			variableMap["fulltarget"] = resp.Request.URL.String()
		} else {
			variableMap["fulltarget"] = target
		}
	}

	return data, resp.StatusCode, milliseconds, nil
}
