package poc

import "testing"

// TestSplitSearchKeywords 锁定三端共用的拆分口径：按逗号拆、小写、去空。
func TestSplitSearchKeywords(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"thinkphp", []string{"thinkphp"}},
		{"ThinkPHP, jquery ,", []string{"thinkphp", "jquery"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := SplitSearchKeywords(c.raw)
		if len(got) != len(c.want) {
			t.Fatalf("SplitSearchKeywords(%q)=%v, want %v", c.raw, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("SplitSearchKeywords(%q)=%v, want %v", c.raw, got, c.want)
			}
		}
	}
}

// TestMatchSearchKeywordsOR 锁定「任一关键词命中即算命中」与「必须逐词比对」：
// "a,b" 不能被当成整串字面量——这正是曾导致 poc.search 与 -s 口径不一致的根因。
func TestMatchSearchKeywordsOR(t *testing.T) {
	terms := SearchTerms{ID: "cve-2021-1234", Name: "apache tomcat", Tags: []string{"java"}}
	if !MatchSearchKeywords(terms, SplitSearchKeywords("tomcat,jquery")) {
		t.Fatal("tomcat 应命中 apache tomcat")
	}
	if !MatchSearchKeywords(terms, SplitSearchKeywords("jquery,cve-2021")) {
		t.Fatal("cve-2021 应命中整串子串")
	}
	if MatchSearchKeywords(terms, SplitSearchKeywords("wordpress,drupal,nginx")) {
		t.Fatal("无匹配关键词时不应命中")
	}
	if MatchSearchKeywords(terms, []string{"tomcat,jquery"}) {
		t.Fatal("整串字面量不应命中——必须拆词比对")
	}
	// 关键词为空即全放行。
	if !MatchSearchKeywords(terms, nil) {
		t.Fatal("无关键词应放行")
	}
}

// TestMatchSearchKeywordsCoversRequires 锁定检索覆盖 requires（含版本约束词条）：
// 名称/标签不含该词、只把依赖写进 requires 的 PoC，也应按该技术词命中。
func TestMatchSearchKeywordsCoversRequires(t *testing.T) {
	terms := SearchTerms{
		ID:       "CVE-2020-1938",
		Name:     "Apache Tomcat AJP 文件读取",
		Tags:     []string{"tomcat", "file-read"},
		Requires: []string{"ajp-protocol-detect", "jquery<3.5"},
	}
	if !MatchSearchKeywords(terms, []string{"ajp-protocol-detect"}) {
		t.Fatal("requires 里的标识词应可被检索到")
	}
	if !MatchSearchKeywords(terms, []string{"jquery"}) {
		t.Fatal("带版本约束的 requires 词条（jquery<3.5）应可被 jquery 检索到")
	}
}
