package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestShouldSkipRequires_Strict_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, nil, false) {
		t.Fatalf("expected skip when strict and no fingerprint tags")
	}
}

func TestShouldSkipRequires_Opportunistic_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}, RequiresMode: "opportunistic"}}
	if shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, nil, false) {
		t.Fatalf("expected not skip when opportunistic and no fingerprint tags")
	}
}

func TestShouldSkipRequires_Strict_Match(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]string{
		"127.0.0.1:3306": {"mysql": ""},
	}
	if shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, fingerTagsByKey, false) {
		t.Fatalf("expected not skip when requires matches target fingerprint tags")
	}
}

// requires 命中「指纹 PoC 的 id」（而非 tag）时，同样不应跳过。
// 例：CVE-2020-1938 写 requires: ["ajp-protocol-detect"]，而 ajp-protocol-detect 是
// 指纹 PoC 的 id，其 tags 里并无 "ajp-protocol-detect" 这个 tag。
func TestShouldSkipRequires_Strict_MatchFingerprintPocID(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"ajp-protocol-detect"}}}
	fingerRequiresByKey := map[string]map[string]string{
		"127.0.0.1:8009": {"ajp": "", "tomcat": "", "ajp-protocol-detect": ""},
	}
	if shouldSkipRequires("127.0.0.1:8009", p, func(s string) string { return s }, fingerRequiresByKey, false) {
		t.Fatalf("expected not skip when requires matches fingerprint poc id")
	}
}

func TestShouldSkipRequires_Strict_Mismatch(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]string{
		"127.0.0.1:3306": {"redis": ""},
	}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, fingerTagsByKey, false) {
		t.Fatalf("expected skip when requires does not match target fingerprint tags")
	}
}

func TestShouldSkipRequires_Strict_EmptyKey(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]string{
		"127.0.0.1:3306": {"mysql": ""},
	}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(string) string { return "" }, fingerTagsByKey, false) {
		t.Fatalf("expected skip when strict and target key cannot be resolved")
	}
}

// requires 带版本约束时，命中产品还要版本落在区间内才放行。
func TestShouldSkipRequires_VersionConstraint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"jquery<3.5"}}}

	// 识别到的版本满足约束 → 放行。
	old := map[string]map[string]string{"a.example:80": {"jquery": "3.4.1"}}
	if shouldSkipRequires("a.example:80", p, func(s string) string { return s }, old, false) {
		t.Fatal("expected not skip when version satisfies the constraint")
	}
	// 识别到的版本不满足 → 跳过。
	newer := map[string]map[string]string{"a.example:80": {"jquery": "3.6.0"}}
	if !shouldSkipRequires("a.example:80", p, func(s string) string { return s }, newer, false) {
		t.Fatal("expected skip when version violates the constraint")
	}
	// 版本未知 → 放行，避免因拿不到版本而漏报。
	unknown := map[string]map[string]string{"a.example:80": {"jquery": ""}}
	if shouldSkipRequires("a.example:80", p, func(s string) string { return s }, unknown, false) {
		t.Fatal("expected not skip when version is unknown")
	}
	// 没识别到该产品 → 跳过。
	absent := map[string]map[string]string{"a.example:80": {"nginx": "1.24"}}
	if !shouldSkipRequires("a.example:80", p, func(s string) string { return s }, absent, false) {
		t.Fatal("expected skip when tech is absent")
	}
}

func TestShouldSkipRequires_TestMode(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	if shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, nil, true) {
		t.Fatalf("expected not skip when test mode is enabled")
	}
}

// webTechRequires 把 -w 的技术栈翻译成 requires 词表：站点根与带路径的目标都要覆盖，
// 无关目标不能凭空多出条目。
func TestWebTechRequires(t *testing.T) {
	metas := map[string]WebMeta{
		"127.0.0.1:8080": {URL: "http://127.0.0.1:8080", Technologies: []WebTech{
			{Name: "WordPress", Version: "6.4.2", Category: "cms", RuleID: "wordpress"},
			{Name: "Apache Shiro", Category: "framework", RuleID: "apache-shiro", Confidence: "probable"},
		}},
		// 没有技术栈的探测结果不应产生 requires 词。
		"127.0.0.1:9090": {URL: "http://127.0.0.1:9090"},
	}
	targets := []string{
		"http://127.0.0.1:8080",
		"http://127.0.0.1:8080/wp-login.php",
		"http://127.0.0.1:9090",
		"127.0.0.1:8080",
	}
	got := webTechRequires(targets, metas)

	for _, key := range []string{"127.0.0.1:8080", "127.0.0.1:8080/wp-login.php"} {
		set, ok := got[key]
		if !ok {
			t.Fatalf("missing entry for %s: %v", key, got)
		}
		for _, want := range []string{"wordpress", "cms", "apache-shiro", "apache shiro", "framework"} {
			if _, ok := set[want]; !ok {
				t.Fatalf("key %s missing token %q: %v", key, want, set)
			}
		}
		// 版本要随标识词一起带出，供版本约束门控使用。
		if set["wordpress"] != "6.4.2" {
			t.Fatalf("key %s wordpress version = %q, want 6.4.2", key, set["wordpress"])
		}
	}
	if _, ok := got["127.0.0.1:9090"]; ok {
		t.Fatalf("target without technologies should not appear: %v", got)
	}
	if webTechRequires(nil, metas) != nil {
		t.Fatal("expected nil for empty target list")
	}
	if webTechRequires(targets, nil) != nil {
		t.Fatal("expected nil for empty meta list")
	}
}

// 合并 Web 技术栈后，requires: [wordpress] 应命中 WordPress 站点而跳过其它站点。
func TestShouldSkipRequires_WithWebFingerprint(t *testing.T) {
	metas := map[string]WebMeta{
		"127.0.0.1:8080": {URL: "http://127.0.0.1:8080", Technologies: []WebTech{
			{Name: "WordPress", Category: "cms", RuleID: "wordpress"},
		}},
	}
	merged := webTechRequires([]string{"http://127.0.0.1:8080"}, metas)

	p := poc.Poc{Info: poc.Info{Requires: []string{"wordpress"}}}
	if shouldSkipRequires("http://127.0.0.1:8080", p, keyFromTargetWithPath, merged, false) {
		t.Fatal("expected not skip when requires matches web fingerprint")
	}
	if !shouldSkipRequires("http://127.0.0.1:8081", p, keyFromTargetWithPath, merged, false) {
		t.Fatal("expected skip when target has no matching web fingerprint")
	}

	// opportunistic 下也应有证据才放行：目标有 Web 指纹但不含该技术时跳过。
	op := poc.Poc{Info: poc.Info{Requires: []string{"thinkphp"}, RequiresMode: "opportunistic"}}
	if !shouldSkipRequires("http://127.0.0.1:8080", op, keyFromTargetWithPath, merged, false) {
		t.Fatal("expected skip when opportunistic and web fingerprint mismatches")
	}
}

func TestShouldSkipFingerprintFilteredByMode_Strict_EmptyTargetTags(t *testing.T) {
	global := map[string]struct{}{"redis": {}}
	pocTags := map[string]struct{}{"redis": {}}
	if !shouldSkipFingerprintFilteredByMode("strict", global, nil, pocTags) {
		t.Fatalf("expected skip when strict and target has no fingerprint tags")
	}
}

func TestShouldSkipFingerprintFilteredByMode_Opportunistic_EmptyTargetTags(t *testing.T) {
	global := map[string]struct{}{"redis": {}}
	pocTags := map[string]struct{}{"redis": {}}
	if shouldSkipFingerprintFilteredByMode("opportunistic", global, nil, pocTags) {
		t.Fatalf("expected not skip when opportunistic and target has no fingerprint tags")
	}
}

func TestShouldSkipFingerprintFilteredByMode_MismatchWithEvidence(t *testing.T) {
	global := map[string]struct{}{"redis": {}, "mysql": {}}
	targetTags := map[string]struct{}{"mysql": {}}
	pocTags := map[string]struct{}{"redis": {}}
	if !shouldSkipFingerprintFilteredByMode("opportunistic", global, targetTags, pocTags) {
		t.Fatalf("expected skip when target fingerprint tags do not match poc tags")
	}
}

func TestShouldSkipFingerprintFilteredByMode_NotAppSpecific(t *testing.T) {
	global := map[string]struct{}{"redis": {}}
	targetTags := map[string]struct{}{}
	pocTags := map[string]struct{}{"weird": {}}
	if shouldSkipFingerprintFilteredByMode("strict", global, targetTags, pocTags) {
		t.Fatalf("expected not skip when poc is not app-specific")
	}
}
