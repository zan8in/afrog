package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestNormalizePassiveDefaults(t *testing.T) {
	cfg := &Config{}
	normalizePassiveDefaults(cfg)

	if cfg.Passive.Host != DefaultPassiveHost {
		t.Errorf("host = %q, want %q", cfg.Passive.Host, DefaultPassiveHost)
	}
	if cfg.Passive.Port != DefaultPassivePort {
		t.Errorf("port = %d, want %d", cfg.Passive.Port, DefaultPassivePort)
	}
	if cfg.Passive.MaxRPS != DefaultPassiveMaxRPS {
		t.Errorf("max_rps = %d, want %d", cfg.Passive.MaxRPS, DefaultPassiveMaxRPS)
	}
	if cfg.Passive.HostConcurrency != DefaultPassiveHostConcurrency {
		t.Errorf("host_concurrency = %d, want %d", cfg.Passive.HostConcurrency, DefaultPassiveHostConcurrency)
	}
	if cfg.Passive.Workers != DefaultPassiveWorkers {
		t.Errorf("workers = %d, want %d", cfg.Passive.Workers, DefaultPassiveWorkers)
	}
	if cfg.Passive.DetectWorkers != DefaultPassiveDetectWorkers {
		t.Errorf("detect_workers = %d, want %d", cfg.Passive.DetectWorkers, DefaultPassiveDetectWorkers)
	}
	if cfg.Passive.QueueSize != DefaultPassiveQueueSize {
		t.Errorf("queue_size = %d, want %d", cfg.Passive.QueueSize, DefaultPassiveQueueSize)
	}
	if got := cfg.Passive.EnabledDetectors(); !slices.Equal(got, DefaultPassiveDetectors) {
		t.Errorf("detectors = %v, want %v", got, DefaultPassiveDetectors)
	}
}

func TestPassiveAddrFallsBackToDefaults(t *testing.T) {
	p := Passive{}
	if got := p.Addr(); got != "127.0.0.1:16869" {
		t.Fatalf("Addr() = %q", got)
	}

	p = Passive{Host: "0.0.0.0", Port: 18080}
	if got := p.Addr(); got != "0.0.0.0:18080" {
		t.Fatalf("Addr() = %q", got)
	}
}

func TestEnabledDetectorsDropsBlanks(t *testing.T) {
	p := Passive{Detectors: []string{" SQLI ", "", "  "}}
	got := p.EnabledDetectors()
	if len(got) != 1 || got[0] != "sqli" {
		t.Fatalf("EnabledDetectors() = %v, want [sqli]", got)
	}
}

// TestUpdatePassiveSectionPreservesOtherSections 锁定「只改 passive，不动其它段」。
func TestUpdatePassiveSectionPreservesOtherSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "afrog-config.yaml")

	seed := `server: ":16868"
curated:
  enabled: "auto"
  timeout_sec: 10
`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	want := Passive{
		AutoStart:       true,
		Host:            "0.0.0.0",
		Port:            18080,
		Upstream:        "http://127.0.0.1:8080",
		Detectors:       []string{"sqli"},
		MaxRPS:          200,
		HostConcurrency: 8,
		Workers:         16,
		DetectWorkers:   24,
		QueueSize:       1024,
	}
	if err := UpdatePassiveSection(path, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `server: ":16868"`) {
		t.Errorf("server section must be preserved:\n%s", body)
	}
	if !strings.Contains(body, "curated:") {
		t.Errorf("curated section must be preserved:\n%s", body)
	}

	var got Config
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Passive.AutoStart || got.Passive.Host != "0.0.0.0" || got.Passive.Port != 18080 {
		t.Errorf("passive round-trip mismatch: %+v", got.Passive)
	}
	if got.Passive.Upstream != "http://127.0.0.1:8080" {
		t.Errorf("upstream = %q", got.Passive.Upstream)
	}
	if got.Passive.MaxRPS != 200 || got.Passive.HostConcurrency != 8 {
		t.Errorf("rate limits mismatch: %+v", got.Passive)
	}
	// 调度层的并发参数必须能完整往返：界面保存 passive 段时若丢了这几项，
	// 用户调好的吞吐参数会被静默重置回默认值。
	if got.Passive.Workers != 16 || got.Passive.DetectWorkers != 24 || got.Passive.QueueSize != 1024 {
		t.Errorf("scheduler concurrency mismatch: %+v", got.Passive)
	}
}

// TestUpdatePassiveSectionAppendsWhenMissing 老配置里没有 passive 段时追加，不报错。
func TestUpdatePassiveSectionAppendsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "afrog-config.yaml")
	if err := os.WriteFile(path, []byte("server: \":16868\"\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := UpdatePassiveSection(path, Passive{Host: "127.0.0.1", Port: 16869}); err != nil {
		t.Fatalf("update: %v", err)
	}

	raw, _ := os.ReadFile(path)
	var got Config
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if got.Passive.Port != 16869 {
		t.Fatalf("passive not appended: %+v\n%s", got.Passive, raw)
	}
}
