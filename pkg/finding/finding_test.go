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

func TestTargetForMirrorsSubject(t *testing.T) {
	cases := []struct {
		name               string
		fulltarget, target string
		want               string
	}{
		{"fulltarget 是绝对 URL", "http://a.example/x", "http://a.example", "http://a.example/x"},
		{"fulltarget 无效回退 target", "not-a-url", "http://b.example", "http://b.example"},
		{"都不是 URL 退到原值", "10.0.0.5:80", "10.0.0.5", "10.0.0.5:80"},
	}
	for _, tc := range cases {
		if got := TargetFor(tc.fulltarget, tc.target); got != tc.want {
			t.Fatalf("%s: TargetFor=%q, want %q", tc.name, got, tc.want)
		}
		// Subject 与 Target 必须取自同一个输入：一个是它的 id、一个是它的原值。
		if got := ref.Endpoint(TargetFor(tc.fulltarget, tc.target)); got != "" && got != SubjectFor(tc.fulltarget, tc.target) {
			t.Fatalf("%s: SubjectFor 应等于 TargetFor 的端点 id，实际 %q vs %q", tc.name, SubjectFor(tc.fulltarget, tc.target), got)
		}
	}
}

// SubjectAddressFor 与 SubjectFor 取同一输入、同一优先级，只是返回可读归一化地址而非
// 内容寻址 id：web 目标的 Subject 是 endpoint_<hash>，两者必须不同；非 URL 主体两者相同。
func TestSubjectAddressFor(t *testing.T) {
	// 绝对 URL：地址是可读归一化 URL，Subject 是它的不透明 id，两者刻意不同。
	addr := SubjectAddressFor("HTTP://A.Example:80/login/?x=1", "http://a.example")
	if addr != "http://a.example/login" {
		t.Fatalf("地址应为归一化 URL，实际 %q", addr)
	}
	if subj := SubjectFor("HTTP://A.Example:80/login/?x=1", "http://a.example"); subj == addr {
		t.Fatalf("web 目标的 Subject 是不透明 id，不应等于可读地址：%q", subj)
	}
	// fulltarget 无效、target 有效：回退 target 的地址。
	if got := SubjectAddressFor("not-a-url", "https://b.example/x"); got != "https://b.example/x" {
		t.Fatalf("应回退到 target 的地址，实际 %q", got)
	}
	// 都不是绝对 URL：退到原值，与 SubjectFor 相同（host:port 这类主体两者恰好一致）。
	if got := SubjectAddressFor("10.0.0.5:80", "10.0.0.5"); got != "10.0.0.5:80" {
		t.Fatalf("非 URL 主体应退到原值，实际 %q", got)
	}
	if SubjectAddressFor("10.0.0.5:80", "10.0.0.5") != SubjectFor("10.0.0.5:80", "10.0.0.5") {
		t.Fatal("host:port 主体上地址与 Subject 应恰好相同")
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
