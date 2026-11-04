package passive

import (
	"net/http"
	"net/url"
	"time"
)

// CapturedTransaction 是代理层产出的归一化事务，也是所有检测器唯一的输入。
//
// 设计上刻意抹掉了 TLS、分块编码、HTTP/2 等协议细节：检测器只面对「方法、URL、
// 头、正文」四件事，这样新增一类漏洞检测时不必重复处理抓包层逻辑。
type CapturedTransaction struct {
	// ID 与代理侧的事务标识一致，便于把检测结果回溯到原始流量。
	ID string
	// Request 是客户端发出的原始请求（已归一化）。
	Request *CapturedRequest
	// Response 是服务端返回的原始响应。
	Response *CapturedResponse
	// Upstream 是客户端当时使用的上游代理（通常为空，表示直连）。
	// 重放变异请求时沿用同一路径，保证检测流量与用户流量走同一条网络链路。
	Upstream *url.URL
	// ClientIP 是发起请求的客户端地址，便于多用户场景下区分来源。
	ClientIP string
	// Static 标记这是一条**文本类静态资源**请求（.js / .json / .css / .map …）。
	//
	// 代理层对静态资源不再一律丢弃：二进制静态（图片/字体/媒体）没有可提取的信息，
	// 仍在代理层放过；文本类静态（尤其 JS）恰恰是敏感信息的高发地，必须放行。
	// 放行之后，调度层据本标记**只跑本地类检测器**（提取器 + 本地漏洞检测器），
	// 不进入注入检测——静态资源没有可注入参数，网络类检测器对它毫无意义。
	Static bool
	// StartAt 是请求开始时间。
	StartAt time.Time
}

// CapturedRequest 是归一化后的请求。
type CapturedRequest struct {
	Method  string
	URL     *url.URL
	Headers http.Header
	Body    []byte
}

// Clone 返回深拷贝，供检测器在不污染原始事务的前提下做变异。
func (r *CapturedRequest) Clone() *CapturedRequest {
	if r == nil {
		return nil
	}
	out := &CapturedRequest{
		Method:  r.Method,
		Headers: cloneHeader(r.Headers),
	}
	if r.URL != nil {
		out.URL = cloneURL(r.URL)
	}
	if len(r.Body) > 0 {
		out.Body = append([]byte(nil), r.Body...)
	}
	return out
}

// CapturedResponse 是归一化后的响应。
type CapturedResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
	// Duration 是从发出请求到读完响应体的耗时。SQLi 时间盲注的基线依赖它，
	// 因此必须在读完 body 之后才赋值，否则会低估真实耗时。
	Duration time.Duration
}

// Clone 返回深拷贝。
func (r *CapturedResponse) Clone() *CapturedResponse {
	if r == nil {
		return nil
	}
	out := &CapturedResponse{
		Status:   r.Status,
		Headers:  cloneHeader(r.Headers),
		Duration: r.Duration,
	}
	if len(r.Body) > 0 {
		out.Body = append([]byte(nil), r.Body...)
	}
	return out
}

// Clone 返回事务深拷贝。检测器需要保证重放不影响原始捕获数据。
func (t *CapturedTransaction) Clone() *CapturedTransaction {
	if t == nil {
		return nil
	}
	return &CapturedTransaction{
		ID:       t.ID,
		Request:  t.Request.Clone(),
		Response: t.Response.Clone(),
		Upstream: cloneURL(t.Upstream),
		ClientIP: t.ClientIP,
		Static:   t.Static,
		StartAt:  t.StartAt,
	}
}

// ParamLocation 标明注入点位于请求的哪一部分。
type ParamLocation string

const (
	LocationQuery  ParamLocation = "query"
	LocationBody   ParamLocation = "body"
	LocationCookie ParamLocation = "cookie"
	LocationHeader ParamLocation = "header"
	// LocationJSONBody 是 JSON 请求体里的字符串型字段（含嵌套对象与数组元素）。
	LocationJSONBody ParamLocation = "json"
	// LocationPath 是 URL 路径段（RESTful 风格，如 /users/123/orders/456 里的 123）。
	LocationPath ParamLocation = "path"
	// LocationXML 是 XML / SOAP 请求体里的元素文本值。
	LocationXML ParamLocation = "xml"
	// LocationMultipart 是 multipart/form-data 分段里的表单字段值。
	LocationMultipart ParamLocation = "multipart"
)

// InjectionPoint 是一个可注入点。
//
// Index 用于区分同名参数（如 ?id=1&id=2），保证变异落在用户真正关心的那一处，
// 而不是笼统地替换全部同名参数——后者会让布尔差分的对比失真。
type InjectionPoint struct {
	Location ParamLocation
	Name     string
	Original string
	Index    int
}

// Mutation 是对一个注入点的一次替换。
type Mutation struct {
	Point InjectionPoint
	Value string
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	cp := *u
	return &cp
}
