package passive

import (
	"net/http"
	"net/url"
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

func TestParseInjectionPointsSkipsJSONBody(t *testing.T) {
	req := &CapturedRequest{
		Method: http.MethodPost,
		URL:    mustURL(t, "http://example.com/api"),
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: []byte(`{"id":"1"}`),
	}
	if points := ParseInjectionPoints(req); len(points) != 0 {
		t.Fatalf("points = %d, want 0 (JSON body is out of scope in v1)", len(points))
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
