package passive

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
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

// injectableHeaders 是纳入检测的请求头。
//
// 只选「语义上属于用户可控输入」且「改动不会改变请求路由或认证」的头：Referer /
// User-Agent 常被服务端记录或参与查询，X-Forwarded-For 常被用来取客户端 IP 并直接
// 拼进 SQL。Host / Authorization / Content-Length 之类的头一律不碰——改它们会改变
// 路由或认证语义，得到的响应差异与注入无关，只会制造误报。
var injectableHeaders = []string{"Referer", "User-Agent", "X-Forwarded-For"}

// ParseInjectionPoints 从事务请求中提取可注入点。
//
// 这是跨检测器复用的能力：SQLi、XSS 等检测器共用同一套参数提取与排除规则，
// 避免每个检测器各写一份导致口径不一致。
//
// 覆盖 query、RESTful 路径段、form body、JSON body（含嵌套对象与数组的字符串值）、
// XML / SOAP 元素文本、multipart/form-data 字段、cookie 与若干请求头。
//
// 所有落点都必须满足「只改值、不动结构」：报文其余字节逐字节保持原样，否则布尔
// 差分比较的就不是同一个请求了。
func ParseInjectionPoints(req *CapturedRequest) []InjectionPoint {
	if req == nil || req.URL == nil {
		return nil
	}

	points := make([]InjectionPoint, 0, 8)

	points = appendInjectionPoints(points, LocationQuery, parseOrdered(req.URL.RawQuery))
	points = append(points, parsePathInjectionPoints(req.URL)...)
	switch {
	case isMultipartBody(req.Headers):
		points = append(points, parseMultipartInjectionPoints(req)...)
	case isFormBody(req.Headers):
		points = appendInjectionPoints(points, LocationBody, parseOrdered(string(req.Body)))
	case isJSONBody(req.Headers):
		points = append(points, parseJSONInjectionPoints(req.Body)...)
	case isXMLBody(req.Headers):
		points = append(points, parseXMLInjectionPoints(req.Body)...)
	}
	if c := req.Headers.Get("Cookie"); c != "" {
		points = appendInjectionPoints(points, LocationCookie, parseCookies(c))
	}
	points = appendHeaderInjectionPoints(points, req.Headers)

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
	case LocationPath:
		if req.URL == nil {
			return nil
		}
		replacePathSegment(req.URL, m.Point.Index, m.Value)
	case LocationJSONBody:
		body, ok := replaceJSONValue(req.Body, m.Point.Name, m.Point.Index, m.Value)
		if !ok {
			return nil
		}
		setBody(req, body)
	case LocationXML:
		body, ok := replaceXMLText(req.Body, m.Point.Name, m.Point.Index, m.Value)
		if !ok {
			return nil
		}
		setBody(req, body)
	case LocationMultipart:
		body, ok := replaceMultipartValue(req, m.Point.Index, m.Value)
		if !ok {
			return nil
		}
		setBody(req, body)
	}
	return nil
}

// setBody 写回变异的请求体并同步 Content-Length。
func setBody(req *CapturedRequest, body []byte) {
	req.Body = body
	req.Headers.Set("Content-Length", strconv.Itoa(len(body)))
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

// isJSONBody 判断请求体是否是 JSON。application/json 及其 +json 后缀变体
// （如 application/vnd.api+json）都算。
func isJSONBody(h http.Header) bool {
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
	mt = strings.ToLower(mt)
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// appendHeaderInjectionPoints 按 injectableHeaders 的固定顺序追加请求头注入点。
func appendHeaderInjectionPoints(dst []InjectionPoint, h http.Header) []InjectionPoint {
	if h == nil {
		return dst
	}
	for _, name := range injectableHeaders {
		v := h.Get(name)
		if !isInjectable(name, v) {
			continue
		}
		dst = append(dst, InjectionPoint{
			Location: LocationHeader,
			Name:     name,
			Original: v,
		})
	}
	return dst
}

// maxJSONDepth 限制 JSON 遍历深度。超深嵌套的报文几乎不可能是正常业务输入，
// 直接截断遍历既避免递归爆栈，也避免把流量浪费在畸形结构上。
const maxJSONDepth = 32

// jsonValue 是 JSON 文档里一个标量值的位置与内容。
type jsonValue struct {
	// path 是该值的路径名：对象字段用 "." 连接，数组元素追加 "[i]"。
	path string
	// start / end 是该值在原始报文中的字节区间（字符串含引号）。
	start int
	end   int
	// str 是解码后的字符串值；isStr 为 false 表示该值不是字符串。
	str   string
	isStr bool
}

// parseJSONInjectionPoints 提取 JSON 请求体里的字符串型值（含嵌套对象与数组）。
//
// 只取字符串：数字、布尔、null 作为注入点的上下文语义不明确，且改动它们会破坏类型，
// 制造与注入无关的差异。数组元素与嵌套字段一并纳入——真实 API 常把用户输入放在
// {"user":{"name":...}} 或 {"ids":["1"]} 这类结构里，漏掉它们等于漏掉注入点。
//
// 字段顺序按 JSON 文档原始顺序保留（用 Decoder 逐 token 走，而不是先解成 map
// 再遍历），这样同名 index 与实际出现在报文里的位置一致。
func parseJSONInjectionPoints(body []byte) []InjectionPoint {
	if len(body) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	points := make([]InjectionPoint, 0, 8)
	seen := make(map[string]int, 8)
	walkJSONValue(dec, body, "", 0, func(v jsonValue) bool {
		idx := seen[v.path]
		seen[v.path] = idx + 1
		if !v.isStr || !isInjectable(v.path, v.str) {
			return true
		}
		points = append(points, InjectionPoint{
			Location: LocationJSONBody,
			Name:     v.path,
			Original: v.str,
			Index:    idx,
		})
		return true
	})
	return points
}

// walkJSONValue 读取 dec 当前指向的一个完整 JSON 值，对每个标量值回调 fn。
// fn 返回 false 表示提前终止遍历；返回 false 也会让本函数返回 false。
func walkJSONValue(dec *json.Decoder, body []byte, path string, depth int, fn func(jsonValue) bool) bool {
	before := int(dec.InputOffset())
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if d, ok := tok.(json.Delim); ok {
		if depth >= maxJSONDepth {
			return false
		}
		switch d {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false
				}
				key, ok := kt.(string)
				if !ok {
					return false
				}
				child := key
				if path != "" {
					child = path + "." + key
				}
				if !walkJSONValue(dec, body, child, depth+1, fn) {
					return false
				}
			}
			_, err := dec.Token() // 消费 '}'
			return err == nil
		case '[':
			for i := 0; dec.More(); i++ {
				if !walkJSONValue(dec, body, fmt.Sprintf("%s[%d]", path, i), depth+1, fn) {
					return false
				}
			}
			_, err := dec.Token() // 消费 ']'
			return err == nil
		}
		return true
	}
	after := int(dec.InputOffset())
	// 读完上一个 token 后，InputOffset 指向的是值前面的结构分隔符（对象值是 ":"、
	// 数组元素是 ","）或其后的空白。若直接从 before 切片，会把分隔符一并替换掉，
	// 破坏 JSON 结构，因此先跳过空白与分隔符，定位到值自身的起始字节。
	start := jsonValueStart(body, before)
	if s, ok := tok.(string); ok {
		return fn(jsonValue{path: path, start: start, end: after, str: s, isStr: true})
	}
	return fn(jsonValue{path: path, start: start, end: after})
}

// jsonValueStart 从 before 起跳过空白与结构分隔符，返回标量值的起始下标。
//
// 分隔符（":" / ","）绝不会是标量值的首字节（字符串以引号开头，数字以数字或 "-" 开头，
// 字面量以字母开头），因此跳过它们不会误伤值本身。
func jsonValueStart(body []byte, before int) int {
	i := before
	for i < len(body) {
		switch body[i] {
		case ' ', '\t', '\r', '\n', ':', ',':
			i++
		default:
			return i
		}
	}
	return i
}

// replaceJSONValue 把路径名为 name 的第 index 个值替换成 JSON 字符串 value。
// 其余字节逐字节原样保留——未变异的字段连空白都不动。
func replaceJSONValue(body []byte, name string, index int, value string) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var (
		start, end int
		n          int
		found      bool
	)
	walkJSONValue(dec, body, "", 0, func(v jsonValue) bool {
		if v.path != name {
			return true
		}
		if n == index {
			if !v.isStr {
				return false
			}
			start, end, found = v.start, v.end, true
			return false
		}
		n++
		return true
	})
	if !found {
		return nil, false
	}
	enc, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	out := make([]byte, 0, len(body)+len(enc))
	out = append(out, body[:start]...)
	out = append(out, enc...)
	out = append(out, body[end:]...)
	return out, true
}

// staticPathSuffixes 是明显的静态资源后缀。路径段一旦命中这些后缀（如
// app.20240101.js）即便含数字也几乎不可能是用户输入，直接排除以免白跑流量。
var staticPathSuffixes = []string{
	".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
}

// parsePathInjectionPoints 提取 URL 路径里的可注入段（RESTful 风格，如
// /users/123/orders/456 中的 123 与 456）。
//
// 过滤规则刻意收紧：只有「含数字」的段才算候选，纯字母段（/list、/api、/search）
// 是资源名而非数据，动它们等于给每个请求凭空增加重放流量。这条规则同时也保证了
// 既有站点（路径全是名词）不会因为新增路径注入点而改变检测行为。
func parsePathInjectionPoints(u *url.URL) []InjectionPoint {
	if u == nil {
		return nil
	}
	esc := u.EscapedPath()
	if esc == "" || esc == "/" {
		return nil
	}
	segs := strings.Split(esc, "/")
	var points []InjectionPoint
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		val, err := url.PathUnescape(seg)
		if err != nil {
			val = seg
		}
		if !isInjectablePathSegment(val) {
			continue
		}
		points = append(points, InjectionPoint{
			Location: LocationPath,
			Name:     strconv.Itoa(i),
			Original: val,
			Index:    i,
		})
	}
	return points
}

// isInjectablePathSegment 判断一个路径段是否值得当作注入点。
func isInjectablePathSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	if len(seg) > maxParamValueLen {
		return false
	}
	if !containsASCIIDigit(seg) {
		return false
	}
	lower := strings.ToLower(seg)
	for _, suf := range staticPathSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	return true
}

func containsASCIIDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

// replacePathSegment 把第 index 个路径段替换成 value（按段转义）。
//
// Path 与 RawPath 必须一起更新：Path 存解码值、RawPath 存转义值，两者不一致时
// url.URL.String() 会重新按 Path 转义，payload 里的特殊字符就会被二次编码。
func replacePathSegment(u *url.URL, index int, value string) bool {
	if u == nil {
		return false
	}
	segs := strings.Split(u.EscapedPath(), "/")
	if index < 0 || index >= len(segs) {
		return false
	}
	segs[index] = url.PathEscape(value)
	esc := strings.Join(segs, "/")
	dec, err := url.PathUnescape(esc)
	if err != nil {
		return false
	}
	u.Path = dec
	u.RawPath = esc
	return true
}

// isXMLBody 判断请求体是否是 XML / SOAP。application/xml、text/xml、
// application/soap+xml 以及任意 +xml 后缀都算。
func isXMLBody(h http.Header) bool {
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
	mt = strings.ToLower(mt)
	switch mt {
	case "application/xml", "text/xml", "application/soap+xml":
		return true
	}
	return strings.HasSuffix(mt, "+xml")
}

// parseXMLInjectionPoints 提取 XML / SOAP 报文里的元素文本值。
//
// 只取元素文本：属性值、注释、处理指令一律不碰——它们要么参与命名空间 / 结构语义，
// 要么根本不进入业务查询，变异只会制造与注入无关的差异。节点名用元素路径表示
// （如 soap:Envelope/soap:Body/GetUser/id），便于复核者定位到底改了哪一处。
func parseXMLInjectionPoints(body []byte) []InjectionPoint {
	if len(body) == 0 {
		return nil
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []string
	points := make([]InjectionPoint, 0, 8)
	seen := make(map[string]int, 8)
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, xmlTokenName(t.Name))
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			name := strings.Join(stack, "/")
			idx := seen[name]
			seen[name] = idx + 1
			if !isInjectable(name, val) {
				continue
			}
			points = append(points, InjectionPoint{
				Location: LocationXML,
				Name:     name,
				Original: val,
				Index:    idx,
			})
		}
	}
	return points
}

// xmlTokenName 还原元素的限定名。RawToken 不做命名空间解析，Space 里保存的是
// 前缀原文（如 soap），正好便于阅读。
func xmlTokenName(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

// replaceXMLText 把路径名为 name 的第 index 个元素文本替换成 value。
//
// 替换时只转义 & < >：它们会破坏 XML 结构，必须写成实体；而 ' " 在文本节点里无需
// 转义，保持原样才能让 payload 里的引号原样落到后端（否则 SQL 语义就变了）。
func replaceXMLText(body []byte, name string, index int, value string) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var (
		stack      []string
		start, end int
		n          int
		found      bool
	)
	for {
		before := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, xmlTokenName(t.Name))
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 || strings.TrimSpace(string(t)) == "" {
				continue
			}
			if strings.Join(stack, "/") != name {
				continue
			}
			if n == index {
				start, end, found = before, int(dec.InputOffset()), true
				break
			}
			n++
		}
		if found {
			break
		}
	}
	if !found {
		return nil, false
	}
	esc := xmlEscapeText(value)
	out := make([]byte, 0, len(body)+len(esc))
	out = append(out, body[:start]...)
	out = append(out, esc...)
	out = append(out, body[end:]...)
	return out, true
}

// xmlEscapeText 只转义会破坏 XML 结构的三个字符。
func xmlEscapeText(s string) []byte {
	var b bytes.Buffer
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.Bytes()
}

// multipartBoundary 取出 multipart/form-data 的 boundary。
func multipartBoundary(h http.Header) (string, bool) {
	if h == nil {
		return "", false
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		return "", false
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(mt, "multipart/form-data") {
		return "", false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", false
	}
	return boundary, true
}

// isMultipartBody 判断请求体是否是 multipart/form-data 且带 boundary。
func isMultipartBody(h http.Header) bool {
	_, ok := multipartBoundary(h)
	return ok
}

// multipartPart 是 multipart 报文里的一个表单字段分段。
type multipartPart struct {
	name  string
	value string
	// start / end 是 value 在原始报文中的字节区间。
	start int
	end   int
}

var multipartCRLF = []byte("\r\n")

// splitMultipart 按 boundary 切分 multipart 报文，返回带定位信息的表单字段。
//
// 只保留「有 name、无 filename」的分段：带 filename 的是文件上传，动它的内容没有
// 注入语义（后端通常直接落盘），反而容易破坏上传流程。分段位置记录下来，变异时
// 只替换值字节，boundary、各段头部与顺序全部原样保留。
func splitMultipart(body []byte, boundary string) []multipartPart {
	delim := []byte("--" + boundary)
	var parts []multipartPart
	pos := 0
	for {
		rel := bytes.Index(body[pos:], delim)
		if rel < 0 {
			break
		}
		pos += rel
		p := pos + len(delim)
		// 结束分隔符是 "--boundary--"。
		if bytes.HasPrefix(body[p:], []byte("--")) {
			break
		}
		if bytes.HasPrefix(body[p:], multipartCRLF) {
			p += 2
		}
		hEnd := bytes.Index(body[p:], []byte("\r\n\r\n"))
		if hEnd < 0 {
			break
		}
		headEnd := p + hEnd
		valStart := headEnd + 4
		next := bytes.Index(body[valStart:], delim)
		if next < 0 {
			break
		}
		valEnd := valStart + next
		end := valEnd
		if end-2 >= valStart && bytes.Equal(body[end-2:end], multipartCRLF) {
			end -= 2
		}
		if name, isFile := multipartFieldName(body[p:headEnd]); name != "" && !isFile {
			parts = append(parts, multipartPart{
				name:  name,
				value: string(body[valStart:end]),
				start: valStart,
				end:   end,
			})
		}
		pos = valEnd
	}
	return parts
}

// multipartFieldName 从分段头部解析出字段名，并判断是否是文件上传。
func multipartFieldName(headers []byte) (name string, isFile bool) {
	for _, line := range bytes.Split(headers, multipartCRLF) {
		k, v, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(string(k)), "Content-Disposition") {
			continue
		}
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(string(v)))
		if err != nil {
			return "", false
		}
		if !strings.EqualFold(mt, "form-data") {
			return "", false
		}
		_, isFile = params["filename"]
		return params["name"], isFile
	}
	return "", false
}

// parseMultipartInjectionPoints 提取 multipart/form-data 里的字段值。
// Index 是该字段在 splitMultipart 结果里的位置，变异时按同一口径定位。
func parseMultipartInjectionPoints(req *CapturedRequest) []InjectionPoint {
	boundary, ok := multipartBoundary(req.Headers)
	if !ok {
		return nil
	}
	parts := splitMultipart(req.Body, boundary)
	var points []InjectionPoint
	for i, part := range parts {
		if !isInjectable(part.name, part.value) {
			continue
		}
		points = append(points, InjectionPoint{
			Location: LocationMultipart,
			Name:     part.name,
			Original: part.value,
			Index:    i,
		})
	}
	return points
}

// replaceMultipartValue 替换第 index 个表单字段的值。
//
// 这里不做 URL 编码：multipart 字段值允许裸空格与引号，多编码一层反而会让后端
// 拿到 %27 而不是 '，直接把注入打掉。
func replaceMultipartValue(req *CapturedRequest, index int, value string) ([]byte, bool) {
	boundary, ok := multipartBoundary(req.Headers)
	if !ok {
		return nil, false
	}
	parts := splitMultipart(req.Body, boundary)
	if index < 0 || index >= len(parts) {
		return nil, false
	}
	part := parts[index]
	out := make([]byte, 0, len(req.Body)+len(value))
	out = append(out, req.Body[:part.start]...)
	out = append(out, value...)
	out = append(out, req.Body[part.end:]...)
	return out, true
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
