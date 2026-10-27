package raw

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/proto"
)

// 本文件用本地 TCP 服务器抓取 raw 请求实际发出的字节，验证 pkg/protocols/raw 的线上行为。
//
// 背景：raw 路径此前依赖 rawhttp 库自动补 Host 头，掩盖了若干问题；
// 本轮改为「raw 自己声明 Host，缺失或未解析时用目标主机兜底」后，
// 需要把「发出去的到底是什么」固化成可回归的断言。

const okResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"

// captureServer 起一个只服务一次请求的本地 TCP 服务器：抓取客户端发来的原始请求字节，
// 再按 respFn 返回的字节写回响应。返回监听地址与请求字节通道。
func captureServer(t *testing.T, respFn func() []byte) (addr string, reqCh <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		rawReq := readFullRequest(conn)
		ch <- rawReq

		// 响应单独放协程写：响应体可能远大于客户端读取上限，
		// 写阻塞不应拖住测试主流程。
		go func() {
			defer conn.Close()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write(respFn())
		}()
	}()

	return ln.Addr().String(), ch
}

// readFullRequest 读到请求头结束，再按 Content-Length 补齐请求体。
func readFullRequest(conn net.Conn) string {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)

	headerEnd := -1
	for headerEnd < 0 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if i := bytes.Index(buf.Bytes(), []byte("\r\n\r\n")); i >= 0 {
				headerEnd = i + 4
			}
		}
		if err != nil {
			return buf.String()
		}
	}

	body := buf.Bytes()[headerEnd:]
	need := 0
	for _, line := range strings.Split(string(buf.Bytes()[:headerEnd]), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			need, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	for len(body) < need {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			body = buf.Bytes()[headerEnd:]
		}
		if err != nil {
			break
		}
	}
	return buf.String()
}

// requestLineOf 取原始请求的首行（请求行）。
func requestLineOf(rawReq string) string {
	return strings.SplitN(rawReq, "\r\n", 2)[0]
}

// headerValuesOf 收集同名请求头的所有值（大小写不敏感）。
func headerValuesOf(rawReq string, name string) []string {
	head, _, _ := strings.Cut(rawReq, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	var out []string
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// bodyOf 取原始请求的请求体。
func bodyOf(rawReq string) string {
	_, body, ok := strings.Cut(rawReq, "\r\n\r\n")
	if !ok {
		return ""
	}
	return body
}

// TestRaw_HostFromTemplateIsHonored 覆盖「放开 Host 自定义」：
// raw 里写的 Host 必须原样发出，不再被目标主机覆盖。
func TestRaw_HostFromTemplateIsHonored(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	vars := map[string]any{"Hostname": addr}
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	rawTpl := "GET / HTTP/1.1\nHost: custom.example.com\nUser-Agent: t"
	if err := rh.RawHttpRequest(rawTpl, "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	got := headerValuesOf(<-ch, "Host")
	if len(got) != 1 || got[0] != "custom.example.com" {
		t.Fatalf("Host 头应原样发出 custom.example.com，实际: %v", got)
	}
}

// TestRaw_HostPlaceholderFallback 覆盖关键兜底：
// afrog 自有 raw PoC 普遍写 `Host: {{hostname}}`（小写），而变量表里只有 `Hostname`，
// 占位符不会被替换。此时必须回退到目标主机，否则会发出 `Host: {{hostname}}`。
func TestRaw_HostPlaceholderFallback(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	vars := map[string]any{"Hostname": addr} // 故意不含小写 hostname
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	rawTpl := "GET /etc/passwd HTTP/1.1\nHost: {{hostname}}\nUser-Agent: t"
	if err := rh.RawHttpRequest(rawTpl, "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	got := headerValuesOf(<-ch, "Host")
	if len(got) != 1 || got[0] != addr {
		t.Fatalf("未解析的 Host 占位符应回退为目标主机 %s，实际: %v", addr, got)
	}
}

// TestRaw_HostMissingFallback 覆盖 raw 完全没写 Host 的情况：必须补上目标主机。
func TestRaw_HostMissingFallback(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest("GET / HTTP/1.1\nUser-Agent: t", "http://"+addr, nil, map[string]any{}); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	got := headerValuesOf(<-ch, "Host")
	if len(got) != 1 || got[0] != addr {
		t.Fatalf("缺失 Host 时应补目标主机 %s，实际: %v", addr, got)
	}
}

// TestRaw_AbsolutePathConcatBase 覆盖 raw 路径语义：
// 绝对路径（以 "/" 开头）应拼 base URL 的子路径，
// 使 raw 与非 raw PoC 行为对齐；同时 request.raw 必须与实际发出的请求行一致。
func TestRaw_AbsolutePathConcatBase(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	target := "http://" + addr + "/prefix"
	rawTpl := "GET /etc/passwd HTTP/1.1\nHost: {{hostname}}"
	vars := map[string]any{"Hostname": addr}

	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest(rawTpl, target, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	captured := <-ch
	if line := requestLineOf(captured); line != "GET /prefix/etc/passwd HTTP/1.1" {
		t.Fatalf("绝对路径应拼接目标子路径，实际: %q", line)
	}

	req, ok := vars["request"].(*proto.Request)
	if !ok || req == nil {
		t.Fatalf("variableMap[request] 类型异常: %T", vars["request"])
	}
	if !strings.Contains(string(req.Raw), "GET /prefix/etc/passwd HTTP/1.1") {
		t.Fatalf("request.raw 应与实际发出的请求行一致，实际: %q", string(req.Raw))
	}
}

// TestRaw_AbsolutePathForcedRoot 覆盖 "^" 强制根路径选项：
// 即使 base URL 带子路径，请求行 path 以 "^" 开头时也不应拼接。
func TestRaw_AbsolutePathForcedRoot(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	target := "http://" + addr + "/prefix"
	rawTpl := "GET ^/etc/passwd HTTP/1.1\nHost: {{hostname}}"
	vars := map[string]any{"Hostname": addr}

	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest(rawTpl, target, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	captured := <-ch
	if line := requestLineOf(captured); line != "GET /etc/passwd HTTP/1.1" {
		t.Fatalf("带 ^ 前缀时请求行应直接以根路径发出，实际: %q", line)
	}

	req, ok := vars["request"].(*proto.Request)
	if !ok || req == nil {
		t.Fatalf("variableMap[request] 类型异常: %T", vars["request"])
	}
	if !strings.Contains(string(req.Raw), "GET /etc/passwd HTTP/1.1") {
		t.Fatalf("request.raw 应去掉 ^ 前缀并反映真实路径，实际: %q", string(req.Raw))
	}
}

// TestRaw_PathFormsPreserved 覆盖 afrog 自有 PoC 里的几种非常规请求行，
// 它们不是以 "/" 开头，必须逐字节保真。
func TestRaw_PathFormsPreserved(t *testing.T) {
	cases := []string{
		"GET a/etc/passwd HTTP/1.1",                          // CVE-2022-31793
		"GET .//WEB-INF/web.xml HTTP/1.1",                    // CVE-2022-21371
		"GET /static?/%2557EB-INF/web.xml HTTP/1.1",          // CVE-2021-28169
		"GET /?search==%00{.cookie|out|value%3dX.} HTTP/1.1", // hfs-rce
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

			rawTpl := line + "\nHost: {{hostname}}\nUser-Agent: t"
			rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
			if err := rh.RawHttpRequest(rawTpl, "http://"+addr, nil, map[string]any{"Hostname": addr}); err != nil {
				t.Fatalf("RawHttpRequest 失败: %v", err)
			}
			if got := requestLineOf(<-ch); got != line {
				t.Fatalf("请求行应为 %q，实际 %q", line, got)
			}
		})
	}
}

// TestRaw_ExtraHeaderSemantics 覆盖 addHeader 与非 raw 路径对齐后的口径：
// 关键头覆盖、普通头追加、请求体不被破坏。
func TestRaw_ExtraHeaderSemantics(t *testing.T) {
	addr, ch := captureServer(t, func() []byte { return []byte(okResponse) })

	rawTpl := "POST /submit HTTP/1.1\nHost: {{hostname}}\nCookie: b=2\nUser-Agent: origUA\nContent-Length: 7\n\npayload"
	extra := []string{"Cookie: a=1", "User-Agent: myUA", "X-Extra: 1"}

	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest(rawTpl, "http://"+addr, extra, map[string]any{"Hostname": addr}); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	captured := <-ch
	if got := headerValuesOf(captured, "Cookie"); len(got) != 1 || got[0] != "a=1" {
		t.Fatalf("Cookie 是关键头，应被覆盖为 a=1，实际: %v", got)
	}
	if got := headerValuesOf(captured, "User-Agent"); len(got) != 1 || got[0] != "myUA" {
		t.Fatalf("User-Agent 是关键头，应被覆盖为 myUA，实际: %v", got)
	}
	if got := headerValuesOf(captured, "X-Extra"); len(got) != 1 || got[0] != "1" {
		t.Fatalf("X-Extra 应被追加到请求头块内，实际: %v", got)
	}
	if got := bodyOf(captured); got != "payload" {
		t.Fatalf("请求体应保持不变，实际: %q", got)
	}
}

// TestRaw_ResponseMultiValueHeaderJoined 覆盖响应头解析口径：
// 同名多值头用 ";" 拼接，与非 raw 路径一致。
func TestRaw_ResponseMultiValueHeaderJoined(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok"
	addr, _ := captureServer(t, func() []byte { return []byte(resp) })

	vars := map[string]any{"Hostname": addr}
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest("GET / HTTP/1.1\nHost: {{hostname}}", "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	got, ok := vars["response"].(*proto.Response)
	if !ok || got == nil {
		t.Fatalf("variableMap[response] 类型异常: %T", vars["response"])
	}
	if v := got.Headers["set-cookie"]; v != "a=1;b=2" {
		t.Fatalf("同名多值响应头应以 ; 拼接，实际: %q", v)
	}
}

// TestRaw_LatencyMeasured 覆盖 latency：应反映发请求到读到响应头的耗时（毫秒）。
func TestRaw_LatencyMeasured(t *testing.T) {
	addr, _ := captureServer(t, func() []byte {
		time.Sleep(80 * time.Millisecond)
		return []byte(okResponse)
	})

	vars := map[string]any{"Hostname": addr}
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 2}
	if err := rh.RawHttpRequest("GET / HTTP/1.1\nHost: {{hostname}}", "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	got, ok := vars["response"].(*proto.Response)
	if !ok || got == nil {
		t.Fatalf("variableMap[response] 类型异常: %T", vars["response"])
	}
	if got.Latency < 60 {
		t.Fatalf("服务端延迟 80ms，latency 应 >= 60，实际: %d", got.Latency)
	}
}

// TestRaw_BodyTruncationFlag 覆盖响应体截断探针：
// 响应体超过 MaxRespBodySize 时，response_body_truncated 必须为 true。
func TestRaw_BodyTruncationFlag(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 1024*1024+16)
	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+
		strconv.Itoa(len(payload))+"\r\n\r\n"), payload...)
	addr, _ := captureServer(t, func() []byte { return resp })

	vars := map[string]any{"Hostname": addr}
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 1}
	if err := rh.RawHttpRequest("GET / HTTP/1.1\nHost: {{hostname}}", "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	if v, _ := vars["__response_body_truncated"].(bool); !v {
		t.Fatalf("响应体超限时 response_body_truncated 应为 true，实际: %v", vars["__response_body_truncated"])
	}
	if got := len(vars["response"].(*proto.Response).Body); got != 1024*1024 {
		t.Fatalf("响应体应恰好截断在 1MB，实际: %d", got)
	}
}

// TestRaw_NoTruncationWhenExactlyAtLimit 覆盖边界：响应体正好等于上限时不应判定为截断。
func TestRaw_NoTruncationWhenExactlyAtLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 1024*1024)
	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+
		strconv.Itoa(len(payload))+"\r\n\r\n"), payload...)
	addr, _ := captureServer(t, func() []byte { return resp })

	vars := map[string]any{"Hostname": addr}
	rh := RawHttp{RawhttpClient: GetRawHTTP("", 10), MaxRespBodySize: 1}
	if err := rh.RawHttpRequest("GET / HTTP/1.1\nHost: {{hostname}}", "http://"+addr, nil, vars); err != nil {
		t.Fatalf("RawHttpRequest 失败: %v", err)
	}

	if v, _ := vars["__response_body_truncated"].(bool); v {
		t.Fatal("响应体正好等于上限时不应判定为截断")
	}
}

// TestGetRawHTTP_CachedByProxyAndTimeout 覆盖客户端缓存键：
// 不同 proxy/timeout 必须拿到不同实例，相同组合复用同一实例。
func TestGetRawHTTP_CachedByProxyAndTimeout(t *testing.T) {
	a := GetRawHTTP("", 10)
	b := GetRawHTTP("", 10)
	if a != b {
		t.Fatal("相同 proxy/timeout 应复用同一客户端实例")
	}
	if c := GetRawHTTP("", 20); c == a {
		t.Fatal("不同 timeout 不应复用同一客户端实例")
	}
}
