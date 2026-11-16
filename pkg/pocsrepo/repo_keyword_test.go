package pocsrepo

import (
	"strings"
	"testing"
)

// TestListMetaMultiKeywordMatchesCLI 端到端锁定与 afrog -s 的同口径：poc.search 的 Q 按逗号
// 拆词后逐词 OR 匹配（旧实现把整串当字面量，多关键词永远返回 0）。
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

// TestListMetaSearchesRequires 锁定检索覆盖 requires：只把依赖写进 requires、名称/标签里
// 不含该词的 PoC，也应被该关键词搜到——这是「识别到技术栈 → 检索依赖它的 PoC」的前提。
func TestListMetaSearchesRequires(t *testing.T) {
	all, err := ListMeta(ListOptions{Source: "all"})
	if err != nil {
		t.Fatalf("ListMeta(all) err=%v", err)
	}
	// 找一条 requires 里带某技术词、但名称/标签不含该词的样本。
	var tech, id string
	for _, it := range all {
		for _, r := range it.Requires {
			k := r
			if i := strings.IndexAny(k, "<>=!"); i >= 0 {
				k = k[:i]
			}
			k = strings.TrimSpace(k)
			if k == "" || strings.Contains(strings.ToLower(it.Name), k) || strings.Contains(strings.ToLower(strings.Join(it.Tags, ",")), k) {
				continue
			}
			tech, id = k, it.ID
			break
		}
		if tech != "" {
			break
		}
	}
	if tech == "" {
		t.Skip("内置 PoC 里没有「仅靠 requires 才能检索到」的样本，跳过")
	}
	got, err := ListMeta(ListOptions{Source: "all", Q: tech})
	if err != nil {
		t.Fatalf("ListMeta(%s) err=%v", tech, err)
	}
	for _, it := range got {
		if it.ID == id {
			return
		}
	}
	t.Fatalf("按 requires 关键词 %q 检索应命中 %s", tech, id)
}
