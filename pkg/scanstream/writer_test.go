package scanstream

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// splitLines 去掉结尾换行后按行切分。
func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestEncodeParseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "local", "task-1")

	w.Status("running")
	w.Progress(42, 42, 100, 7, 1234)
	w.Phase("vuln", "running", 3, 10, 30)
	result := &ResultEvent{
		Severity: "high",
		PocID:    "shiro-key",
		PocName:  "Shiro 反序列化",
		Target:   "http://x/?a=1&b=2",
		Evidence: &Evidence{
			Exchanges: []Exchange{
				{Request: "GET / HTTP/1.1\r\nHost: x", Response: "HTTP/1.1 200 OK", Matched: true},
			},
			Extractors: map[string]string{"key": "value"},
		},
	}
	w.Result(result)
	w.Port("1.2.3.4", 8080)
	w.WebProbe(&WebProbeEvent{URL: "http://x", Status: 200, Title: "t", Fingerprint: "nginx"})
	w.Host("1.2.3.4")
	w.Log("info", "hello")
	w.Done("completed", &Summary{Executed: 100, Found: 1, BySeverity: map[string]int64{"high": 1}, ElapsedMs: 999})
	w.Error("scan_failed", "boom")

	lines := splitLines(buf.String())
	if len(lines) != 10 {
		t.Fatalf("want 10 lines, got %d", len(lines))
	}

	events := make([]Event, 0, len(lines))
	for i, line := range lines {
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("line %d contains newline: %q", i, line)
		}
		ev, err := Parse([]byte(line))
		if err != nil {
			t.Fatalf("parse line %d: %v", i, err)
		}
		events = append(events, ev)
	}

	if events[0].Type != TypeStatus || events[0].Status == nil || events[0].Status.Status != "running" {
		t.Fatalf("status payload mismatch: %+v", events[0])
	}
	if got := events[1].Progress; got == nil || got.Percent != 42 || got.Finished != 42 || got.Total != 100 || got.Rate != 7 || got.ElapsedMs != 1234 {
		t.Fatalf("progress payload mismatch: %+v", got)
	}
	if got := events[2].Phase; got == nil || got.Phase != "vuln" || got.Status != "running" || got.Finished != 3 || got.Total != 10 || got.Percent != 30 {
		t.Fatalf("phase payload mismatch: %+v", got)
	}
	if events[3].Type != TypeResult || !reflect.DeepEqual(events[3].Result, result) {
		t.Fatalf("result payload mismatch: %+v", events[3].Result)
	}
	if got := events[4].Port; got == nil || got.Host != "1.2.3.4" || got.Port != 8080 {
		t.Fatalf("port payload mismatch: %+v", got)
	}
	if got := events[5].WebProbe; got == nil || got.URL != "http://x" || got.Status != 200 || got.Title != "t" || got.Fingerprint != "nginx" {
		t.Fatalf("webprobe payload mismatch: %+v", got)
	}
	if got := events[6].Host; got == nil || got.Host != "1.2.3.4" {
		t.Fatalf("host payload mismatch: %+v", got)
	}
	if got := events[7].Log; got == nil || got.Level != "info" || got.Text != "hello" {
		t.Fatalf("log payload mismatch: %+v", got)
	}
	if got := events[8].Done; got == nil || got.Status != "completed" || got.Summary == nil ||
		got.Summary.Executed != 100 || got.Summary.Found != 1 || got.Summary.ElapsedMs != 999 ||
		got.Summary.BySeverity["high"] != 1 {
		t.Fatalf("done payload mismatch: %+v", got)
	}
	if got := events[9].Error; got == nil || got.Code != "scan_failed" || got.Message != "boom" {
		t.Fatalf("error payload mismatch: %+v", got)
	}

	// 信封字段
	for i, ev := range events {
		if ev.V != Version || ev.Node != "local" || ev.Task != "task-1" {
			t.Fatalf("envelope mismatch on line %d: %+v", i, ev)
		}
	}

	// 未设置的载荷必须被省略
	if strings.Contains(lines[0], "progress") || strings.Contains(lines[0], `"result"`) {
		t.Fatalf("unset payloads should be omitted: %s", lines[0])
	}
}

func TestSeqStartsAtOneAndMonotonic(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "local", "task-1")
	for i := 0; i < 5; i++ {
		w.Status("running")
	}

	lines := splitLines(buf.String())
	if len(lines) != 5 {
		t.Fatalf("want 5 lines, got %d", len(lines))
	}
	for i, line := range lines {
		ev, err := Parse([]byte(line))
		if err != nil {
			t.Fatalf("parse line %d: %v", i, err)
		}
		if ev.Seq != uint64(i+1) {
			t.Fatalf("line %d: want seq %d, got %d", i, i+1, ev.Seq)
		}
	}
}

func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "local", "task-1")

	const goroutines = 8
	const perGoroutine = 50

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if i%2 == 0 {
					w.Port("127.0.0.1", 1000+id)
				} else {
					w.Log("info", "concurrent")
				}
			}
		}(g)
	}
	wg.Wait()

	lines := splitLines(buf.String())
	if len(lines) != goroutines*perGoroutine {
		t.Fatalf("want %d lines, got %d", goroutines*perGoroutine, len(lines))
	}

	seen := make(map[uint64]struct{}, len(lines))
	for i, line := range lines {
		ev, err := Parse([]byte(line))
		if err != nil {
			t.Fatalf("parse line %d failed: %v (line=%q)", i, err, line)
		}
		if _, dup := seen[ev.Seq]; dup {
			t.Fatalf("duplicate seq %d", ev.Seq)
		}
		seen[ev.Seq] = struct{}{}
	}
	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("want %d unique seqs, got %d", goroutines*perGoroutine, len(seen))
	}
}

func TestNoHTMLEscaping(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "local", "task-1")
	w.Result(&ResultEvent{
		Severity: "high",
		PocID:    "poc-1",
		PocName:  "中文名称",
		Target:   "http://a.com/?x=1&y=2&z=%3C",
	})

	out := buf.String()
	if strings.Contains(out, `\u0026`) || strings.Contains(out, `\u003c`) {
		t.Fatalf("HTML escaping was not disabled: %s", out)
	}
	if !strings.Contains(out, "&") {
		t.Fatalf("literal & missing: %s", out)
	}
	if !strings.Contains(out, "中文名称") {
		t.Fatalf("non-ascii text should not be escaped: %s", out)
	}

	ev, err := Parse([]byte(strings.TrimRight(out, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Result == nil || ev.Result.Target != "http://a.com/?x=1&y=2&z=%3C" || ev.Result.PocName != "中文名称" {
		t.Fatalf("round trip mismatch: %+v", ev.Result)
	}
}
