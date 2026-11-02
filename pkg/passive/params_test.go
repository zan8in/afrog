package passive

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestParseInjectionPointsQuery(t *testing.T) {
	req := &CapturedRequest{
		Method:  http.MethodGet,
		URL:     mustURL(t, "http://example.com/list?id=1&name=abc&empty=&long="+longString(600)),
		Headers: http.Header{},
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2 (empty and too-long must be skipped)", len(points))
	}
	if points[0].Name != "id" || points[0].Original != "1" || points[0].Location != LocationQuery {
		t.Errorf("points[0] = %+v", points[0])
	}
	if points[1].Name != "name" || points[1].Original != "abc" {
		t.Errorf("points[1] = %+v", points[1])
	}
}

func TestParseInjectionPointsDuplicateIndex(t *testing.T) {
	req := &CapturedRequest{
		Method:  http.MethodGet,
		URL:     mustURL(t, "http://example.com/list?id=1&id=2"),
		Headers: http.Header{},
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2", len(points))
	}
	if points[0].Index != 0 || points[1].Index != 1 {
		t.Errorf("indexes = %d,%d, want 0,1", points[0].Index, points[1].Index)
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "INJECT"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := clone.URL.Query()["id"]; len(got) != 2 || got[0] != "1" || got[1] != "INJECT" {
		t.Errorf("query after mutation = %v, want [1 INJECT]", got)
	}
}

func TestParseInjectionPointsFormBody(t *testing.T) {
	req := &CapturedRequest{
		Method: http.MethodPost,
		URL:    mustURL(t, "http://example.com/login"),
		Headers: http.Header{
			"Content-Type": []string{"application/x-www-form-urlencoded; charset=utf-8"},
		},
		Body: []byte("username=alice&password=p%40ss"),
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2", len(points))
	}
	if points[1].Name != "password" || points[1].Original != "p@ss" {
		t.Errorf("points[1] = %+v", points[1])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[0], Value: "bob' OR '1'='1"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := string(clone.Body); got != "username=bob%27+OR+%271%27%3D%271&password=p%40ss" {
		t.Errorf("body after mutation = %q", got)
	}
}

func TestParseInjectionPointsCookie(t *testing.T) {
	req := &CapturedRequest{
		Method: http.MethodGet,
		URL:    mustURL(t, "http://example.com/"),
		Headers: http.Header{
			"Cookie": []string{"session=abc; uid=42"},
		},
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2", len(points))
	}
	if points[1].Location != LocationCookie || points[1].Name != "uid" {
		t.Errorf("points[1] = %+v", points[1])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "1 AND 1=2"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := clone.Headers.Get("Cookie"); got != "session=abc; uid=1 AND 1=2" {
		t.Errorf("cookie after mutation = %q", got)
	}
}

func TestParseInjectionPointsJSONBody(t *testing.T) {
	req := &CapturedRequest{
		Method: http.MethodPost,
		URL:    mustURL(t, "http://example.com/api"),
		Headers: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: []byte(`{"id":"1","count":2,"nested":{"a":"b"},"tags":["x"],"note":"hi"}`),
	}

	points := ParseInjectionPoints(req)
	// 只取字符串值：count（数字）不算；nested.a 与 tags[0] 这类嵌套 / 数组元素要纳入。
	if len(points) != 4 {
		t.Fatalf("points = %d, want 4", len(points))
	}
	wantNames := []string{"id", "nested.a", "tags[0]", "note"}
	wantValues := []string{"1", "b", "x", "hi"}
	for i := range wantNames {
		if points[i].Location != LocationJSONBody || points[i].Name != wantNames[i] || points[i].Original != wantValues[i] {
			t.Errorf("points[%d] = %+v, want name=%q value=%q", i, points[i], wantNames[i], wantValues[i])
		}
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[0], Value: "1' AND '1'='1"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	// 只替换目标字段，其余字段的值与顺序必须原样保留，否则「差分」比较的就不是同一个请求了。
	want := `{"id":"1' AND '1'='1","count":2,"nested":{"a":"b"},"tags":["x"],"note":"hi"}`
	if got := string(clone.Body); got != want {
		t.Errorf("body after mutation = %q, want %q", got, want)
	}
}

func TestApplyMutationJSONBodyDuplicateKey(t *testing.T) {
	req := &CapturedRequest{
		Method:  http.MethodPost,
		URL:     mustURL(t, "http://example.com/api"),
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(`{"id":"1","id":"2"}`),
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 || points[0].Index != 0 || points[1].Index != 1 {
		t.Fatalf("points = %+v, want 两个同名 id（index 0/1）", points)
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "X"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := string(clone.Body); got != `{"id":"1","id":"X"}` {
		t.Errorf("body after mutation = %q, want 只改第二个 id", got)
	}
}

func TestParseInjectionPointsHeader(t *testing.T) {
	req := &CapturedRequest{
		Method: http.MethodGet,
		URL:    mustURL(t, "http://example.com/"),
		Headers: http.Header{
			"User-Agent":      []string{"curl/8.0"},
			"X-Forwarded-For": []string{"127.0.0.1"},
			"Host":            []string{"example.com"},
			"Authorization":   []string{"Bearer t"},
		},
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2（只纳入 Referer / User-Agent / X-Forwarded-For）", len(points))
	}
	if points[0].Name != "User-Agent" || points[0].Location != LocationHeader {
		t.Errorf("points[0] = %+v", points[0])
	}
	if points[1].Name != "X-Forwarded-For" {
		t.Errorf("points[1] = %+v", points[1])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "1 AND 1=2"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := clone.Headers.Get("X-Forwarded-For"); got != "1 AND 1=2" {
		t.Errorf("X-Forwarded-For after mutation = %q", got)
	}
	// Host / Authorization 会改变路由与认证语义，必须原样保留。
	if clone.Headers.Get("Host") != "example.com" || clone.Headers.Get("Authorization") != "Bearer t" {
		t.Errorf("不可注入的头被改动: %+v", clone.Headers)
	}
}

// TestApplyMutationJSONNested 验证嵌套对象与数组元素的定位与替换都落在正确位置。
func TestApplyMutationJSONNested(t *testing.T) {
	req := &CapturedRequest{
		Method:  http.MethodPost,
		URL:     mustURL(t, "http://example.com/api"),
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(`{"user":{"name":"alice","age":30},"ids":["1","2"],"note":"hi"}`),
	}

	points := ParseInjectionPoints(req)
	// user.name、ids[0]、ids[1]、note 共 4 个；age 是数字、不参与检测。
	if len(points) != 4 {
		t.Fatalf("points = %d, want 4: %+v", len(points), points)
	}
	if points[1].Name != "ids[0]" || points[2].Name != "ids[1]" {
		t.Errorf("数组元素命名错误: %+v, %+v", points[1], points[2])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "1' OR '1'='1"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	want := `{"user":{"name":"alice","age":30},"ids":["1' OR '1'='1","2"],"note":"hi"}`
	if got := string(clone.Body); got != want {
		t.Errorf("body after mutation = %q, want %q", got, want)
	}
}

// TestParseInjectionPointsPath 验证 RESTful 路径段只在「含数字」时才被当作注入点。
func TestParseInjectionPointsPath(t *testing.T) {
	req := &CapturedRequest{
		Method:  http.MethodGet,
		URL:     mustURL(t, "http://example.com/users/123/orders/abc"),
		Headers: http.Header{},
	}

	points := ParseInjectionPoints(req)
	if len(points) != 1 {
		t.Fatalf("points = %d, want 1（只有含数字的 123 段算候选）: %+v", len(points), points)
	}
	if points[0].Location != LocationPath || points[0].Name != "2" || points[0].Original != "123" {
		t.Errorf("points[0] = %+v", points[0])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[0], Value: "123 AND 1=2"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := clone.URL.EscapedPath(); got != "/users/123%20AND%201=2/orders/abc" {
		t.Errorf("escaped path after mutation = %q", got)
	}
	// 纯字母段不能被当成注入点。
	plain := &CapturedRequest{
		Method:  http.MethodGet,
		URL:     mustURL(t, "http://example.com/list"),
		Headers: http.Header{},
	}
	if n := len(ParseInjectionPoints(plain)); n != 0 {
		t.Errorf("纯字母路径产生了 %d 个注入点，want 0", n)
	}
}

// TestParseInjectionPointsXML 验证 SOAP 报文里的元素文本被识别并可精确替换。
func TestParseInjectionPointsXML(t *testing.T) {
	body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><GetUser><id>1</id><name>alice</name></GetUser></soap:Body></soap:Envelope>`
	req := &CapturedRequest{
		Method:  http.MethodPost,
		URL:     mustURL(t, "http://example.com/api"),
		Headers: http.Header{"Content-Type": []string{"application/soap+xml; charset=utf-8"}},
		Body:    []byte(body),
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2: %+v", len(points), points)
	}
	if points[0].Location != LocationXML || points[0].Original != "1" {
		t.Errorf("points[0] = %+v", points[0])
	}
	if want := "soap:Envelope/soap:Body/GetUser/id"; points[0].Name != want {
		t.Errorf("points[0].Name = %q, want %q", points[0].Name, want)
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[0], Value: "1' AND '1'='1"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	if got := string(clone.Body); !strings.Contains(got, "<id>1' AND '1'='1</id>") {
		t.Errorf("XML body after mutation = %q", got)
	}
}

// TestParseInjectionPointsMultipart 验证 multipart 字段被识别、文件段被排除，
// 且变异只替换值字节、不动 boundary 与分段结构。
func TestParseInjectionPointsMultipart(t *testing.T) {
	boundary := "----afrogBoundary123"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"username\"\r\n\r\n" +
		"alice\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"avatar\"; filename=\"a.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"filecontent\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"uid\"\r\n\r\n" +
		"42\r\n" +
		"--" + boundary + "--\r\n"
	req := &CapturedRequest{
		Method:  http.MethodPost,
		URL:     mustURL(t, "http://example.com/upload"),
		Headers: http.Header{"Content-Type": []string{"multipart/form-data; boundary=" + boundary}},
		Body:    []byte(body),
	}

	points := ParseInjectionPoints(req)
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2（文件段必须排除）: %+v", len(points), points)
	}
	if points[0].Location != LocationMultipart || points[0].Name != "username" || points[0].Original != "alice" {
		t.Errorf("points[0] = %+v", points[0])
	}
	if points[1].Name != "uid" || points[1].Original != "42" {
		t.Errorf("points[1] = %+v", points[1])
	}

	clone := req.Clone()
	if err := ApplyMutation(clone, Mutation{Point: points[1], Value: "1 AND 1=2"}); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	want := strings.Replace(body, "\r\n\r\n42\r\n", "\r\n\r\n1 AND 1=2\r\n", 1)
	if got := string(clone.Body); got != want {
		t.Errorf("body after mutation = %q, want %q", got, want)
	}
	// multipart 值不走 URL 编码：载荷里的空格与引号必须原样落到后端。
	if !strings.Contains(string(clone.Body), "1 AND 1=2") {
		t.Errorf("payload 被编码了: %q", clone.Body)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
