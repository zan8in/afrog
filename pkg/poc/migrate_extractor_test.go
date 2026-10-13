package poc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

type testExtractorPoc struct {
	Extractors []Extractors `yaml:"extractors"`
	Rules      map[string]struct {
		Extractors []Extractors `yaml:"extractors"`
	} `yaml:"rules"`
}

func mustParseRuleExtractors(t *testing.T, body string) []Extractors {
	t.Helper()
	var p testExtractorPoc
	if err := yaml.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("migrated output is not valid YAML: %v\n---\n%s", err, body)
	}
	rule, ok := p.Rules["r0"]
	if !ok {
		t.Fatalf("no r0 rule in output:\n%s", body)
	}
	return rule.Extractors
}

func TestMigrateExtractorBlocks_Basic(t *testing.T) {
	in := `id: t
rules:
  r0:
    request:
      method: GET
      path: /
    extractors:
      - type: regex
        extractor:
          ext1: '"\"version\":\"(?P<v>[0-9.]+)\"".bsubmatch(response.body)'
          ver: ext1["v"]
`
	out, n := migrateExtractorBlocks(in)
	if n != 1 {
		t.Fatalf("changes = %d, want 1", n)
	}
	ex := mustParseRuleExtractors(t, out)
	if len(ex) != 1 {
		t.Fatalf("got %d extractors", len(ex))
	}
	got := ex[0]
	if got.Name != "ver" || got.Type != "regex" || got.Part != "body" || got.Group != "v" || got.All {
		t.Fatalf("unexpected extractor: %#v\n---\n%s", got, out)
	}
	if want := `"version":"(?P<v>[0-9.]+)"`; got.Regex != want {
		t.Fatalf("regex = %q, want %q\n---\n%s", got.Regex, want, out)
	}
}

func TestMigrateExtractorBlocks_PartsAndAll(t *testing.T) {
	tests := []struct {
		celLine string
		part    string
		all     bool
	}{
		{`'"<title>(?P<t>.+)</title>".submatch(response_text)'`, "text", false},
		{`'"\"id\":\"(?P<id>[0-9]+)\"".bsubmatchall(response.body)'`, "body", true},
		{`'"(?i)(?P<vnc>RFB ([0-9.]+))".bsubmatch(response.raw)'`, "raw", false},
	}
	for _, tt := range tests {
		in := "rules:\n  r0:\n    extractors:\n      - type: regex\n        extractor:\n          tmp: " + tt.celLine + "\n          out: tmp[\"g\"]\n"
		out, n := migrateExtractorBlocks(in)
		if n != 1 {
			t.Fatalf("%s: changes = %d", tt.celLine, n)
		}
		ex := mustParseRuleExtractors(t, out)
		if len(ex) != 1 || ex[0].Part != tt.part || ex[0].All != tt.all {
			t.Fatalf("%s: got %#v", tt.celLine, ex)
		}
	}
}

func TestMigrateExtractorBlocks_SkipsNonCanonical(t *testing.T) {
	cases := map[string]string{
		"three keys": `    extractors:
      - type: regex
        extractor:
          tmp: '"x".bsubmatch(response.body)'
          a: tmp["v"]
          b: tmp["w"]
`,
		"already typed": `    extractors:
      - name: v
        type: regex
        part: body
        regex: "x"
`,
		"word form": `    extractors:
      - type: word
        extractor:
          pass: "s3cret"
`,
		"ref does not match tmp": `    extractors:
      - type: regex
        extractor:
          tmp: '"x".bsubmatch(response.body)'
          a: other["v"]
`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			in := "rules:\n  r0:\n" + block
			out, n := migrateExtractorBlocks(in)
			if n != 0 {
				t.Fatalf("expected no change, got %d\n%s", n, out)
			}
			if out != in {
				t.Fatalf("output changed unexpectedly:\n%s", out)
			}
		})
	}
}

func TestMigrateExtractorBlocks_MultipleEntriesAndTopLevel(t *testing.T) {
	in := `extractors:
  - type: regex
    extractor:
      ext1: '"\"version\":\"(?P<v>[0-9.]+)\"".bsubmatch(response.body)'
      top_ver: ext1["v"]
rules:
  r0:
    extractors:
      - type: regex
        extractor:
          s: '"Server: (?P<s>[A-Za-z0-9./]+)".submatch(response_text)'
          server: s["s"]
`
	out, n := migrateExtractorBlocks(in)
	if n != 2 {
		t.Fatalf("changes = %d, want 2\n%s", n, out)
	}

	var p testExtractorPoc
	if err := yaml.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out)
	}
	if len(p.Extractors) != 1 || p.Extractors[0].Name != "top_ver" {
		t.Fatalf("top-level extractor: %#v", p.Extractors)
	}
	if len(p.Rules["r0"].Extractors) != 1 || p.Rules["r0"].Extractors[0].Name != "server" {
		t.Fatalf("rule extractor: %#v", p.Rules["r0"].Extractors)
	}
}

func TestMigrateLegacyPocs_MigratesExtractorOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "js.yaml")
	body := `id: t
info:
  name: t
  author: a
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          ext1: '"\"version\":\"(?P<v>[0-9.]+)\"".bsubmatch(response.body)'
          ver: ext1["v"]
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := MigrateLegacyPocs(dir)
	if err != nil {
		t.Fatalf("MigrateLegacyPocs: %v", err)
	}
	if report.FilesChanged != 1 || report.Changes != 1 {
		t.Fatalf("report = %#v", report)
	}

	raw, _ := os.ReadFile(path)
	out := string(raw)
	if !strings.Contains(out, "- name: ver") || strings.Contains(out, "extractor:") {
		t.Fatalf("unexpected migrated file:\n%s", out)
	}
	ex := mustParseRuleExtractors(t, out)
	if len(ex) != 1 || ex[0].Regex != `"version":"(?P<v>[0-9.]+)"` {
		t.Fatalf("migrated extractor parse: %#v", ex)
	}
}
