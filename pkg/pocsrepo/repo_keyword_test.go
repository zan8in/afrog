package pocsrepo

import "testing"

// TestSplitKeywordList 锁定与 afrog -s 一致的拆分口径：按逗号拆、小写、去空。
func TestSplitKeywordList(t *testing.T) {
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
		got := splitKeywordList(c.raw)
		if len(got) != len(c.want) {
			t.Fatalf("splitKeywordList(%q)=%v, want %v", c.raw, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitKeywordList(%q)=%v, want %v", c.raw, got, c.want)
			}
		}
	}
}

// TestContainsAnyKeywordOR 锁定「任一关键词命中即算命中」：这是修 poc.search 与 -s
// 口径不一致的关键——"a,b" 不能当整串字面量比对。
func TestContainsAnyKeywordOR(t *testing.T) {
	hay := []string{"cve-2021-1234", "apache tomcat", "java"}
	if !containsAnyKeyword(hay, splitKeywordList("tomcat,jquery")) {
		t.Fatal("tomcat 应命中 apache tomcat")
	}
	if !containsAnyKeyword(hay, splitKeywordList("jquery,cve-2021")) {
		t.Fatal("cve-2021 应命中整串子串")
	}
	if containsAnyKeyword(hay, splitKeywordList("wordpress,drupal,nginx")) {
		t.Fatal("无匹配关键词时不应命中")
	}
	// 关键回归点：整串 "a,b" 只有在拆分后逐词匹配才对，不能被当成一个词使用。
	if containsAnyKeyword(hay, []string{"tomcat,jquery"}) {
		t.Fatal("整串字面量不应命中——必须拆词比对")
	}
}

// TestListMetaMultiKeywordMatchesCLI 端到端锁定 bug 修复：poc.search 的 Q 与 afrog -s
// 同口径后，多关键词逗号串应能命中（旧实现把整串当字面量，返回 0）。
func TestListMetaMultiKeywordMatchesCLI(t *testing.T) {
	jquery, err := ListMeta(ListOptions{Source: "all", Q: "jquery"})
	if err != nil {
		t.Fatalf("ListMeta(jquery) err=%v", err)
	}
	if len(jquery) == 0 {
		t.Skip("内置 PoC 未加载，跳过端到端断言")
	}
	// 逗号多关键词：加一个必然不存在的词不应减少命中（OR 语义）。
	multi, err := ListMeta(ListOptions{Source: "all", Q: "jquery,zzz-no-such-keyword"})
	if err != nil {
		t.Fatalf("ListMeta(multi) err=%v", err)
	}
	if len(multi) != len(jquery) {
		t.Fatalf("多关键词 OR 语义：len(multi)=%d, len(jquery)=%d", len(multi), len(jquery))
	}
}
