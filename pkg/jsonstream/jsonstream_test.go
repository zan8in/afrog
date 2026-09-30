package jsonstream

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// resultPocIDs 从事件流里取出结果事件的 PoC ID。
func resultPocIDs(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev, err := scanstream.Parse([]byte(line))
		if err != nil {
			continue
		}
		if ev.Type == scanstream.TypeResult && ev.Result != nil {
			out = append(out, ev.Result.PocID)
		}
	}
	return out
}

// 指纹命中（多为 info，例如 nginx-detect）此前只写报告与台账、不进事件流，
// 于是「台账里看得到、扫描详情的漏洞列表却是 0」。这条通路必须存在。
func TestAttach_EmitsFingerprintHits(t *testing.T) {
	var buf bytes.Buffer
	w := scanstream.NewWriter(&buf, "local", "t1")
	r := &runner.Runner{}

	finish := Attach(w, &config.Options{}, r, time.Now())
	defer finish("completed", 1, 1)

	r.OnFingerprint("http://a.example", []fingerprint.Hit{{
		ID: "nginx-detect", Name: "Nginx检测", Severity: "info",
	}})

	ids := resultPocIDs(t, buf.String())
	if len(ids) != 1 || ids[0] != "nginx-detect" {
		t.Fatalf("result events = %v, want [nginx-detect]\nstream:\n%s", ids, buf.String())
	}
}

// -S 指定了严重级别时，被过滤掉的指纹命中既不进报告/台账，也不该进事件流：
// 否则前端会比台账多出命中，两个口径对不上。
func TestAttach_FingerprintHonoursSeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	w := scanstream.NewWriter(&buf, "local", "t1")
	r := &runner.Runner{}

	finish := Attach(w, &config.Options{Severity: "high"}, r, time.Now())
	defer finish("completed", 0, 1)

	r.OnFingerprint("http://a.example", []fingerprint.Hit{{
		ID: "nginx-detect", Name: "Nginx检测", Severity: "info",
	}})
	r.OnFingerprint("http://a.example", []fingerprint.Hit{{
		ID: "shiro-detect", Name: "Shiro", Severity: "high",
	}})

	ids := resultPocIDs(t, buf.String())
	if len(ids) != 1 || ids[0] != "shiro-detect" {
		t.Fatalf("result events = %v, want only the high-severity hit", ids)
	}
}

func TestShouldReportFingerprint(t *testing.T) {
	cases := []struct {
		severity string
		filter   string
		want     bool
	}{
		{"info", "", true},
		{"info", "high", false},
		{"info", "info", true},
		{"HIGH", "high,critical", true},
		{"high", " high , critical ", true},
	}
	for _, c := range cases {
		got := ShouldReportFingerprint(&config.Options{Severity: c.filter}, c.severity)
		if got != c.want {
			t.Errorf("ShouldReportFingerprint(filter=%q, severity=%q) = %v, want %v",
				c.filter, c.severity, got, c.want)
		}
	}
	if !ShouldReportFingerprint(nil, "info") {
		t.Error("nil options must report everything")
	}
}
