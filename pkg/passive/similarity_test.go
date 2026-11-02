package passive

import "testing"

func TestSimilarityIdentical(t *testing.T) {
	body := []byte("<html>\n<body>\n<h1>Hello</h1>\n</body>\n</html>")
	if got := Similarity(body, body); got != 1 {
		t.Fatalf("Similarity(identical) = %v, want 1", got)
	}
}

func TestSimilarityStructuralChange(t *testing.T) {
	base := []byte("<html>\n<h1>List</h1>\n<li>A</li>\n<li>B</li>\n</html>")
	empty := []byte("<html>\n<h1>List</h1>\n</html>")

	if got := Similarity(base, empty); got >= 0.9 {
		t.Fatalf("Similarity(structural change) = %v, want significantly lower", got)
	}
}

// TestDiffLines 校验行级对称差计数：它是短页面判定的绝对量依据。
// 相对量（相似度）在短页面上对「差一行」过度敏感，绝对量能直接回答差了几行。
func TestDiffLines(t *testing.T) {
	base := []byte("<html>\n<h1>List</h1>\n<li>A</li>\n<li>B</li>\n</html>")

	if got := DiffLines(base, base); got != 0 {
		t.Fatalf("DiffLines(identical) = %d, want 0", got)
	}

	// 改一行：对称差为 2（旧行没了 + 新行来了）。
	oneLine := []byte("<html>\n<h1>List</h1>\n<li>C</li>\n<li>B</li>\n</html>")
	if got := DiffLines(base, oneLine); got != 2 {
		t.Fatalf("DiffLines(one line changed) = %d, want 2", got)
	}

	// 结果集消失：移除两行，对称差为 2。
	empty := []byte("<html>\n<h1>List</h1>\n</html>")
	if got := DiffLines(base, empty); got != 2 {
		t.Fatalf("DiffLines(two lines removed) = %d, want 2", got)
	}
}

func TestNormalizeRemovesEcho(t *testing.T) {
	payload := "1' AND '1'='2'-- -"
	body := []byte("<html>\n<h1>Search: 1&#39; AND &#39;1&#39;=&#39;2&#39;-- -</h1>\n<li>A</li>\n</html>")

	normalized := Normalize(body, payload)
	if got := string(normalized); got == string(body) {
		t.Fatalf("Normalize did not strip the reflected payload")
	}

	// 反射内容被抹掉后，与不含反射的页面结构应当高度一致。
	clean := []byte("<html>\n<h1>Search: __AFROG_ECHO__</h1>\n<li>A</li>\n</html>")
	if got := Similarity(normalized, clean); got != 1 {
		t.Fatalf("Similarity after normalize = %v, want 1", got)
	}
}

func TestNormalizeIgnoresShortStrings(t *testing.T) {
	body := []byte("<html>\n<li>1</li>\n<li>2</li>\n</html>")
	if got := string(Normalize(body, "1")); got != string(body) {
		t.Fatalf("short strip must be ignored, got %q", got)
	}
}

// TestNormalizeEntityVariants 覆盖真实站点上常见的引号转义形态。
//
// Go 的 html.EscapeString 会把单引号转义成 &#39;，但很多站点（如 PortSwigger
// 靶场）用的是 XML 命名实体 &apos;。若只覆盖 &#39;，反射文本会残留在正文里，
// 把"结构相同、仅反射不同"误判成结构差异，进而漏报真实注入点。
func TestNormalizeEntityVariants(t *testing.T) {
	payload := "Pets' AND '1'='1'-- -"

	cases := map[string]string{
		"named-entity": "Pets&apos; AND &apos;1&apos;=&apos;1&apos;-- -",
		"decimal":      "Pets&#39; AND &#39;1&#39;=&#39;1&#39;-- -",
		"hex":          "Pets&#x27; AND &#x27;1&#x27;=&#x27;1&#x27;-- -",
	}
	for name, echoed := range cases {
		body := []byte("<html>\n<h1>" + echoed + "</h1>\n<li>A</li>\n</html>")
		normalized := Normalize(body, payload)
		clean := []byte("<html>\n<h1>__AFROG_ECHO__</h1>\n<li>A</li>\n</html>")
		if got := Similarity(normalized, clean); got != 1 {
			t.Fatalf("%s: 反射未被完全剔除，Similarity=%v, want 1", name, got)
		}
	}
}
