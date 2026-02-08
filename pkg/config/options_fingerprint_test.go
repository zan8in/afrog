package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestOptions_FingerprintPoCs(t *testing.T) {
	o := &Options{}
	all := []poc.Poc{
		{Id: "a", Info: poc.Info{Name: "a", Tags: "x,fingerprint,y"}},
		{Id: "b", Info: poc.Info{Name: "b", Tags: "x, y"}},
		{Id: "c", Info: poc.Info{Name: "c", Tags: "Fingerprint"}},
		{Id: "d", Info: poc.Info{Name: "d", Tags: ""}},
	}

	finger, other := o.FingerprintPoCs(all)
	if got, want := len(finger), 2; got != want {
		t.Fatalf("finger len mismatch: got=%d want=%d", got, want)
	}
	if got, want := len(other), 2; got != want {
		t.Fatalf("other len mismatch: got=%d want=%d", got, want)
	}
}

func TestFilterPocSeveritySearchWithFingerprint(t *testing.T) {
	t.Run("includes fingerprint even when severity mismatches", func(t *testing.T) {
		if got := filterPocSeveritySearchWithFingerprint("", "high", "nacos-detect", "Nacos Detect", "info", "nacos,panel,fingerprint"); !got {
			t.Fatalf("expected fingerprint poc to be included when severity mismatches")
		}
		if got := filterPocSeveritySearchWithFingerprint("", "high", "not-finger", "Not Finger", "info", "panel"); got {
			t.Fatalf("expected non-fingerprint poc to be excluded when severity mismatches")
		}
	})

	t.Run("search keyword still restricts fingerprint pocs", func(t *testing.T) {
		if got := filterPocSeveritySearchWithFingerprint("tomcat", "high", "nacos-detect", "Nacos Detect", "info", "nacos,panel,fingerprint"); got {
			t.Fatalf("expected fingerprint poc to be excluded when search mismatches")
		}
		if got := filterPocSeveritySearchWithFingerprint("nacos", "high", "nacos-detect", "Nacos Detect", "info", "nacos,panel,fingerprint"); !got {
			t.Fatalf("expected fingerprint poc to be included when search matches")
		}
	})

	t.Run("includes all when no filters", func(t *testing.T) {
		if got := filterPocSeveritySearchWithFingerprint("", "", "any", "Any", "info", ""); !got {
			t.Fatalf("expected included when no filters are set")
		}
	})

	t.Run("search keyword matches tags", func(t *testing.T) {
		if got := filterPocSeveritySearchWithFingerprint("weblogic", "", "id-not-match", "name-not-match", "high", "java,weblogic,rce"); !got {
			t.Fatalf("expected included when search matches tags")
		}
		if got := filterPocSeveritySearchWithFingerprint("weblogic", "", "id-not-match", "name-not-match", "high", "java,tomcat,rce"); got {
			t.Fatalf("expected excluded when search mismatches tags")
		}
	})
}

func TestOptions_FilterPocSeveritySearch_MatchesTags(t *testing.T) {
	o := &Options{Search: "weblogic"}
	if !o.FilterPocSeveritySearch("id-not-match", "name-not-match", "java,weblogic,rce", "high") {
		t.Fatalf("expected included when search matches tags")
	}
	if o.FilterPocSeveritySearch("id-not-match", "name-not-match", "java,tomcat,rce", "high") {
		t.Fatalf("expected excluded when search mismatches tags")
	}
}

func TestParseNacosDetectPocMeta(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to locate test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	p := filepath.Join(repoRoot, "pocs", "afrog-pocs", "fingerprinting", "nacos-detect.yaml")

	pi, err := poc.LocalReadPocByPath(p)
	if err != nil {
		t.Fatalf("failed to parse nacos-detect.yaml: %v", err)
	}
	if pi.Id != "nacos-detect" {
		t.Fatalf("unexpected id: %q", pi.Id)
	}
	if !strings.EqualFold(strings.TrimSpace(pi.Info.Severity), "info") {
		t.Fatalf("unexpected severity: %q", pi.Info.Severity)
	}
	if !strings.Contains(strings.ToLower(pi.Info.Tags), "fingerprint") {
		t.Fatalf("expected tags to include fingerprint, got: %q", pi.Info.Tags)
	}
}
