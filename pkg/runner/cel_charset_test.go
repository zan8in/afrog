package runner

import (
	"io"
	"strings"
	"testing"

	"github.com/google/cel-go/checker/decls"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func TestCELBSubmatchBytesGBK(t *testing.T) {
	expected := "致远A6-m协同办公管理平台"
	html := "<title>" + expected + "</title>"

	gbkBytes, err := io.ReadAll(transform.NewReader(strings.NewReader(html), simplifiedchinese.GBK.NewEncoder()))
	if err != nil {
		t.Fatalf("encode gbk error: %v", err)
	}

	lib := NewCustomLib()
	lib.UpdateCompileOption("body", decls.Bytes)

	out, err := lib.RunEval(`"<title>(?P<v>.+)</title>".bsubmatch(body)`, map[string]any{
		"body": gbkBytes,
	})
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}

	m, ok := out.Value().(map[string]string)
	if !ok {
		t.Fatalf("unexpected result type: %T", out.Value())
	}
	if m["v"] == expected {
		t.Fatalf("expected bsubmatch(body) not to decode GBK bytes")
	}

	outText, err := lib.RunEval(`"<title>(?P<v>.+)</title>".submatch(toUtf8(body))`, map[string]any{
		"body": gbkBytes,
	})
	if err != nil {
		t.Fatalf("eval submatch(toUtf8(body)) error: %v", err)
	}
	mText, ok := outText.Value().(map[string]string)
	if !ok {
		t.Fatalf("unexpected result type: %T", outText.Value())
	}
	if mText["v"] != expected {
		t.Fatalf("expected %q, got %q", expected, mText["v"])
	}

	out2, err := lib.RunEval(`"致远".bmatches(body)`, map[string]any{
		"body": gbkBytes,
	})
	if err != nil {
		t.Fatalf("eval bmatches error: %v", err)
	}
	ok2, _ := out2.Value().(bool)
	if ok2 {
		t.Fatalf("expected bmatches=false, got true")
	}

	out2Text, err := lib.RunEval(`toUtf8(body).matches(".*致远.*")`, map[string]any{
		"body": gbkBytes,
	})
	if err != nil {
		t.Fatalf("eval matches(toUtf8(body)) error: %v", err)
	}
	ok2Text, _ := out2Text.Value().(bool)
	if !ok2Text {
		t.Fatalf("expected matches(toUtf8(body))=true, got false")
	}
}

func TestCELRegexCount(t *testing.T) {
	html := "<title>a</title>\n<title>b</title>\n"
	body := []byte(html)

	lib := NewCustomLib()
	lib.UpdateCompileOption("body", decls.Bytes)
	lib.UpdateCompileOption("text", decls.String)

	out, err := lib.RunEval(`"(?is)<title>.*?</title>".bcount(body)`, map[string]any{
		"body": body,
	})
	if err != nil {
		t.Fatalf("eval bcount error: %v", err)
	}
	if got, ok := out.Value().(int64); !ok || got != 2 {
		t.Fatalf("expected bcount=2, got %T(%v)", out.Value(), out.Value())
	}

	out2, err := lib.RunEval(`"(?is)<title>.*?</title>".rcount(text)`, map[string]any{
		"text": html,
	})
	if err != nil {
		t.Fatalf("eval rcount error: %v", err)
	}
	if got, ok := out2.Value().(int64); !ok || got != 2 {
		t.Fatalf("expected rcount=2, got %T(%v)", out2.Value(), out2.Value())
	}
}
