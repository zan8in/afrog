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

func TestCELSha1SubstrBytesToUpperBytes(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("b", decls.Bytes)

	out, err := lib.RunEval(`substr(b, 1, 3)`, map[string]any{
		"b": []byte("abcdef"),
	})
	if err != nil {
		t.Fatalf("eval substr(bytes) error: %v", err)
	}
	gotSub, ok := out.Value().([]byte)
	if !ok || string(gotSub) != "bcd" {
		t.Fatalf("expected substr(bytes)='bcd', got %T(%v)", out.Value(), out.Value())
	}

	out2, err := lib.RunEval(`toUpper(b)`, map[string]any{
		"b": []byte("aBcDeF"),
	})
	if err != nil {
		t.Fatalf("eval toUpper(bytes) error: %v", err)
	}
	gotUpper, ok := out2.Value().([]byte)
	if !ok || string(gotUpper) != "ABCDEF" {
		t.Fatalf("expected toUpper(bytes)='ABCDEF', got %T(%v)", out2.Value(), out2.Value())
	}

	out3, err := lib.RunEval(`sha1("abc")`, map[string]any{})
	if err != nil {
		t.Fatalf("eval sha1(string) error: %v", err)
	}
	if got, ok := out3.Value().(string); !ok || got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("expected sha1('abc') match, got %T(%v)", out3.Value(), out3.Value())
	}
}

func TestCELHexAndAesECB(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("t", decls.String)
	lib.UpdateCompileOption("k", decls.String)
	lib.UpdateCompileOption("b", decls.Bytes)

	out, err := lib.RunEval(`hex(b)`, map[string]any{
		"b": []byte{0x00, 0x01, 0xff},
	})
	if err != nil {
		t.Fatalf("eval hex(bytes) error: %v", err)
	}
	if got, ok := out.Value().(string); !ok || got != "0001ff" {
		t.Fatalf("expected hex(bytes)='0001ff', got %T(%v)", out.Value(), out.Value())
	}

	env, err := lib.NewCelEnv()
	if err != nil {
		t.Fatalf("new env error: %v", err)
	}
	ast, iss := env.Compile(`aesECB(t, k)`)
	if iss.Err() != nil {
		t.Fatalf("compile error: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program error: %v", err)
	}
	out2, _, err := prg.Eval(map[string]any{
		"t": "hello",
		"k": "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("eval aesECB error: %v", err)
	}
	got2, ok := out2.Value().([]byte)
	if !ok || len(got2) == 0 || len(got2)%16 != 0 {
		t.Fatalf("expected aesECB return non-empty bytes aligned to 16, got %T(len=%v)", out2.Value(), len(got2))
	}
}

func TestCELPaddingAndAesECBNoPad(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("t", decls.String)
	lib.UpdateCompileOption("k", decls.String)
	lib.UpdateCompileOption("b", decls.Bytes)

	out, err := lib.RunEval(`pkcs7Pad("A", 16)`, map[string]any{})
	if err != nil {
		t.Fatalf("eval pkcs7Pad error: %v", err)
	}
	padded, ok := out.Value().([]byte)
	if !ok || len(padded) != 16 || padded[15] != 15 {
		t.Fatalf("expected pkcs7Pad('A',16) length=16 last=15, got %T(%v)", out.Value(), out.Value())
	}

	out2, err := lib.RunEval(`zeroPad("A", 16)`, map[string]any{})
	if err != nil {
		t.Fatalf("eval zeroPad error: %v", err)
	}
	zeroed, ok := out2.Value().([]byte)
	if !ok || len(zeroed) != 16 || zeroed[1] != 0 {
		t.Fatalf("expected zeroPad('A',16) length=16, got %T(%v)", out2.Value(), out2.Value())
	}

	env, err := lib.NewCelEnv()
	if err != nil {
		t.Fatalf("new env error: %v", err)
	}
	ast, iss := env.Compile(`aesECBNoPad(pkcs7Pad(t, 16), k)`)
	if iss.Err() != nil {
		t.Fatalf("compile error: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program error: %v", err)
	}
	out3, _, err := prg.Eval(map[string]any{
		"t": "hello",
		"k": "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("eval aesECBNoPad error: %v", err)
	}
	got3, ok := out3.Value().([]byte)
	if !ok || len(got3) != 16 {
		t.Fatalf("expected aesECBNoPad output length=16, got %T(%v)", out3.Value(), out3.Value())
	}
}

func TestCELComposeSha1x2KeyDeriveWithGenericFuncs(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("seed", decls.String)
	lib.UpdateCompileOption("text", decls.String)

	expr := `toUpper(hex(aesECB(text, substr(toBytes(hexdecode(sha1(hexdecode(sha1(seed))))), 0, 16))))`
	out, err := lib.RunEval(expr, map[string]any{
		"seed": "872a5b60-9755-4",
		"text": "1,1" + "1700000000",
	})
	if err != nil {
		t.Fatalf("eval compose error: %v", err)
	}
	got, ok := out.Value().(string)
	if !ok || got == "" {
		t.Fatalf("expected non-empty string output, got %T(%v)", out.Value(), out.Value())
	}
}

func TestCELTimestampMilli(t *testing.T) {
	lib := NewCustomLib()
	out, err := lib.RunEval(`timestamp_milli()`, map[string]any{})
	if err != nil {
		t.Fatalf("eval timestamp_milli error: %v", err)
	}
	s, ok := out.Value().(string)
	if !ok || len(s) < 13 {
		t.Fatalf("expected millisecond timestamp string, got %T(%v)", out.Value(), out.Value())
	}
}

func TestCELTimestampSecond(t *testing.T) {
	lib := NewCustomLib()
	out, err := lib.RunEval(`timestamp_second()`, map[string]any{})
	if err != nil {
		t.Fatalf("eval timestamp_second error: %v", err)
	}
	s, ok := out.Value().(string)
	if !ok || len(s) < 10 {
		t.Fatalf("expected second timestamp string, got %T(%v)", out.Value(), out.Value())
	}
}
