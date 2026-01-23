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

func TestMigrateExpressionResponseBodyRegex(t *testing.T) {
	in := `"(?P<v>.+)".bsubmatch(response.body)["v"] != "" && "abc".bmatches(response.body)`
	out := migrateExpression(in)
	if strings.Contains(out, ".bsubmatch(") || strings.Contains(out, ".bmatches(") {
		t.Fatalf("expected response.body b* calls to be migrated, got %q", out)
	}
	if !strings.Contains(out, `.submatch(response_text)`) {
		t.Fatalf("expected bsubmatch migration, got %q", out)
	}
	if !strings.Contains(out, `.rmatches(response_text)`) {
		t.Fatalf("expected bmatches migration, got %q", out)
	}
}
