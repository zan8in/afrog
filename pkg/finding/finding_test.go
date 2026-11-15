package finding

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/ref"
)

func TestIDForIsStableAndScoped(t *testing.T) {
	a := IDFor("p-1", "endpoint_abc", "cwe-89")
	b := IDFor("p-1", "endpoint_abc", "cwe-89")
	if a != b {
		t.Fatalf("同一 canonical 必同 id：%q vs %q", a, b)
	}
	if len(a) < 4 || a[:4] != "fnd_" {
		t.Fatalf("id 应带 fnd_ 前缀，实际 %q", a)
	}
	if IDFor("p-2", "endpoint_abc", "cwe-89") == a {
		t.Fatal("项目不同应得到不同 id（项目间不去重）")
	}
	if IDFor("p-1", "endpoint_xyz", "cwe-89") == a {
		t.Fatal("主体不同应得到不同 id")
	}
	if IDFor("p-1", "endpoint_abc", "cwe-79") == a {
		t.Fatal("类目不同应得到不同 id")
	}
}

func TestVulnClassPrecedence(t *testing.T) {
	cases := []struct {
		name             string
		cwe, tags, vulid string
		want             string
	}{
		{"cwe 优先", "CWE-89", "sqli,php", "poc-a", "cwe-89"},
		{"无 cwe 取首个 tag", " ", " sqli , php ", "poc-a", "sqli"},
		{"无 tag 回退 vulid", "", "", "POC-A", "poc-a"},
		{"全空返回空", "", "", "", ""},
	}
	for _, tc := range cases {
		if got := VulnClass(tc.cwe, tc.tags, tc.vulid); got != tc.want {
			t.Fatalf("%s: VulnClass=%q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSubjectForFallback(t *testing.T) {
	// 完整命中是绝对 URL：取端点 id。
	if got := SubjectFor("http://a.example/x", "http://a.example"); got != ref.Endpoint("http://a.example/x") {
		t.Fatalf("fulltarget 有效时应取端点 id，实际 %q", got)
	}
	// fulltarget 无效、target 有效：回退 target。
	if got := SubjectFor("not-a-url", "http://b.example"); got != ref.Endpoint("http://b.example") {
		t.Fatalf("应回退到 target 端点 id，实际 %q", got)
	}
	// 都不是绝对 URL：退到原值，避免主体塌缩成空串。
	if got := SubjectFor("10.0.0.5:80", "10.0.0.5"); got != "10.0.0.5:80" {
		t.Fatalf("非 URL 目标应退到原值，实际 %q", got)
	}
}

func TestStateFromStatus(t *testing.T) {
	cases := map[string]string{
		"":               StateNew,
		"pending":        StateNew,
		"confirmed":      StatePresent,
		"false_positive": StatePresent,
		"fixed":          StateFixed,
		"weird":          StatePresent,
	}
	for status, want := range cases {
		if got := StateFromStatus(status); got != want {
			t.Fatalf("StateFromStatus(%q)=%q, want %q", status, got, want)
		}
	}
}

func TestNewValidatesAndDerivesID(t *testing.T) {
	if _, err := New(Finding{Subject: "", VulnClass: "cwe-89"}); err == nil {
		t.Fatal("缺少 subject 应报错")
	}
	if _, err := New(Finding{Subject: "endpoint_x", VulnClass: ""}); err == nil {
		t.Fatal("缺少 vuln_class 应报错")
	}

	f, err := New(Finding{ProjectID: " p-1 ", Subject: " endpoint_x ", VulnClass: " cwe-89 "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f.ID != IDFor("p-1", "endpoint_x", "cwe-89") {
		t.Fatalf("id 未按内容寻址算出：%q", f.ID)
	}
	if f.Evidence == nil {
		t.Fatal("evidence 应为非 nil 空切片，便于 JSON 序列化")
	}
}
