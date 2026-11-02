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
