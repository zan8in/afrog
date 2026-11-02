package passive

import (
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxParamValueLen 限制参与检测的参数值长度。超长值多为 token / 签名 / 序列化
// blob，对它们做变异既无意义又会产生大量误报，直接跳过。
const maxParamValueLen = 512

// maxInjectionPoints 限制单个事务的注入点数量，避免参数极多的请求放大重放流量。
const maxInjectionPoints = 32

// ParseInjectionPoints 从事务请求中提取可注入点。
//
// 这是跨检测器复用的能力：SQLi、XSS 等检测器共用同一套参数提取与排除规则，
// 避免每个检测器各写一份导致口径不一致。
//
// 第一版只覆盖 query、form body 与 cookie 三类结构化输入。JSON body、multipart
// 与自定义 header 暂不纳入：它们的上下文语义更复杂，强行检测会显著抬高误报。
func ParseInjectionPoints(req *CapturedRequest) []InjectionPoint {
	if req == nil || req.URL == nil {
		return nil
	}

	points := make([]InjectionPoint, 0, 8)

	points = appendInjectionPoints(points, LocationQuery, parseOrdered(req.URL.RawQuery))
	if isFormBody(req.Headers) {
		points = appendInjectionPoints(points, LocationBody, parseOrdered(string(req.Body)))
	}
	if c := req.Headers.Get("Cookie"); c != "" {
		points = appendInjectionPoints(points, LocationCookie, parseCookies(c))
	}

	if len(points) > maxInjectionPoints {
		points = points[:maxInjectionPoints]
	}
	return points
}

// ApplyMutation 把变异应用到请求副本上。调用方应传入 Clone 后的请求。
func ApplyMutation(req *CapturedRequest, m Mutation) error {
	if req == nil {
		return nil
	}
	switch m.Point.Location {
	case LocationQuery:
		if req.URL == nil {
			return nil
		}
		kvs := parseOrdered(req.URL.RawQuery)
		if !replaceNth(kvs, m.Point.Name, m.Point.Index, m.Value) {
			return nil
		}
		req.URL.RawQuery = encodeOrdered(kvs)
		req.URL.RawPath = ""
	case LocationBody:
		kvs := parseOrdered(string(req.Body))
		if !replaceNth(kvs, m.Point.Name, m.Point.Index, m.Value) {
			return nil
		}
		body := encodeOrdered(kvs)
		req.Body = []byte(body)
		req.Headers.Set("Content-Length", strconv.Itoa(len(body)))
	case LocationCookie:
		c := req.Headers.Get("Cookie")
		if nc, ok := replaceCookie(c, m.Point.Name, m.Point.Index, m.Value); ok {
			req.Headers.Set("Cookie", nc)
		}
	case LocationHeader:
		req.Headers.Set(m.Point.Name, m.Value)
	}
	return nil
}

// appendInjectionPoints 按出现顺序追加注入点。
// 同名参数的 Index 在过滤前计数，保证 ?id=1&id=2 中第二个 id 的索引仍是 1。
func appendInjectionPoints(dst []InjectionPoint, loc ParamLocation, kvs []orderedKV) []InjectionPoint {
	seen := make(map[string]int, len(kvs))
	for _, kv := range kvs {
		idx := seen[kv.k]
		seen[kv.k] = idx + 1
		if !isInjectable(kv.k, kv.v) {
			continue
		}
		dst = append(dst, InjectionPoint{
			Location: loc,
			Name:     kv.k,
			Original: kv.v,
			Index:    idx,
		})
	}
	return dst
}

type orderedKV struct {
	k, v string
}

func parseOrdered(raw string) []orderedKV {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "&")
	out := make([]orderedKV, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		k, v, found := strings.Cut(p, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv := ""
		if found {
			if dv2, err := url.QueryUnescape(v); err == nil {
				dv = dv2
			} else {
				dv = v
			}
		}
		out = append(out, orderedKV{k: dk, v: dv})
	}
	return out
}

func encodeOrdered(kvs []orderedKV) string {
	var b strings.Builder
	for i, kv := range kvs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(kv.k))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(kv.v))
	}
	return b.String()
}

// replaceNth 替换第 index 个同名参数的值。
func replaceNth(kvs []orderedKV, name string, index int, value string) bool {
	n := 0
	for i := range kvs {
		if kvs[i].k != name {
			continue
		}
		if n == index {
			kvs[i].v = value
			return true
		}
		n++
	}
	return false
}

func parseCookies(raw string) []orderedKV {
	parts := strings.Split(raw, ";")
	out := make([]orderedKV, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, found := strings.Cut(p, "=")
		if !found {
			continue
		}
		out = append(out, orderedKV{k: strings.TrimSpace(k), v: strings.TrimSpace(v)})
	}
	return out
}

func replaceCookie(raw, name string, index int, value string) (string, bool) {
	parts := strings.Split(raw, ";")
	n := 0
	replaced := false
	for i, p := range parts {
		trimmed := strings.TrimSpace(p)
		k, _, found := strings.Cut(trimmed, "=")
		if !found || strings.TrimSpace(k) != name {
			continue
		}
		if n == index {
			parts[i] = " " + name + "=" + value
			replaced = true
			break
		}
		n++
	}
	if !replaced {
		return raw, false
	}
	return strings.TrimSpace(strings.Join(parts, ";")), true
}

func isFormBody(h http.Header) bool {
	if h == nil {
		return false
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/x-www-form-urlencoded"
}

// isInjectable 判断一个参数值是否值得做变异检测。
//
// 这里的排除规则直接服务于误报控制：过长、空值、纯数字时间戳/哈希等「一眼不是
// 用户输入」的参数一律跳过，避免把缓存键、签名、埋点参数当成注入点。
func isInjectable(name, value string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	// 值过长，多为 token / 序列化数据。
	if len(value) > maxParamValueLen {
		return false
	}
	// 空值没有可闭合的上下文，布尔差分无从谈起。
	if value == "" {
		return false
	}
	return true
}
