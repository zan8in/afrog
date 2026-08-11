package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewOptions_Defaults(t *testing.T) {
	o := NewOptions()

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"RateLimit", o.RateLimit, DefaultRateLimit},
		{"Concurrency", o.Concurrency, DefaultConcurrency},
		{"Retries", o.Retries, DefaultRetries},
		{"Timeout", o.Timeout, DefaultTimeout},
		{"MaxHostError", o.MaxHostError, DefaultMaxHostError},
		{"MaxRespBodySize", o.MaxRespBodySize, DefaultMaxRespBodySize},
		{"BruteMaxRequests", o.BruteMaxRequests, DefaultBruteMaxRequests},
		{"StreamBuffer", o.StreamBuffer, DefaultStreamBuffer},
		{"FingerprintFilterMode", o.FingerprintFilterMode, FingerprintStrict},
		{"IncludeRequestResponse", o.IncludeRequestResponse, true},
		{"Verbose", o.Verbose, false},
		{"MaxStoredResults", o.MaxStoredResults, 0},
		{"OOB.RateLimit", o.OOB.RateLimit, DefaultOOBRateLimit},
		{"OOB.Concurrency", o.OOB.Concurrency, DefaultOOBConcurrency},
		{"OOB.PollInterval", o.OOB.PollInterval, DefaultOOBPollInterval},
		{"OOB.HitRetention", o.OOB.HitRetention, DefaultOOBHitRetention},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// The OOB poll cadence must match the command line's. Leaving PollInterval at
// zero makes the engine fall back to one second, which polls the out-of-band
// provider twice as often as afrog's own CLI does.
func TestWithOOB_KeepsPollDefaultsWhenUnset(t *testing.T) {
	o := NewOptions()
	if err := WithOOB(OOBOptions{Adapter: "ceyeio"})(o); err != nil {
		t.Fatalf("WithOOB: %v", err)
	}
	if o.OOB.PollInterval != DefaultOOBPollInterval {
		t.Errorf("PollInterval = %d, want %d", o.OOB.PollInterval, DefaultOOBPollInterval)
	}
	if o.OOB.HitRetention != DefaultOOBHitRetention {
		t.Errorf("HitRetention = %d, want %d", o.OOB.HitRetention, DefaultOOBHitRetention)
	}

	// An explicit value must survive.
	o2 := NewOptions()
	if err := WithOOB(OOBOptions{Adapter: "ceyeio", PollInterval: 7, HitRetention: 3})(o2); err != nil {
		t.Fatalf("WithOOB: %v", err)
	}
	if o2.OOB.PollInterval != 7 || o2.OOB.HitRetention != 3 {
		t.Errorf("explicit values lost: PollInterval=%d HitRetention=%d", o2.OOB.PollInterval, o2.OOB.HitRetention)
	}
}

func TestOptions_ValidationErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: a\ninfo:\n  name: a\n  severity: info\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.status == 200\nexpression: r0()\n"), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}

	tests := []struct {
		name   string
		option Option
	}{
		{"zero concurrency", WithConcurrency(0)},
		{"negative concurrency", WithConcurrency(-1)},
		{"zero rate limit", WithRateLimit(0)},
		{"zero timeout", WithTimeout(0)},
		{"negative retries", WithRetries(-1)},
		{"negative max host error", WithMaxHostError(-1)},
		{"zero response body size", WithMaxRespBodySize(0)},
		{"negative max stored results", WithMaxStoredResults(-1)},
		{"zero stream buffer", WithStreamBuffer(0)},
		{"empty oob adapter", WithOOB(OOBOptions{})},
		{"malformed header", WithHeaders("no-colon")},
		{"unknown fingerprint mode", WithFingerprintFilterMode("bogus")},
		{"nil options", WithOptions(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(),
				WithTargets("http://127.0.0.1:1"),
				WithPocPaths(dir),
				tt.option,
			)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestOptions_MutuallyExclusiveRequestLimits(t *testing.T) {
	o := NewOptions()
	o.Targets = []string{"http://127.0.0.1:1"}
	o.Polite = true
	o.Aggressive = true

	if err := o.validate(); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("error = %v, want ErrInvalidOptions", err)
	}
}

func TestOptions_RequestLimitPresets(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Options)
		want  int
	}{
		{"polite", func(o *Options) { o.Polite = true }, 5},
		{"balanced", func(o *Options) { o.Balanced = true }, 15},
		{"aggressive", func(o *Options) { o.Aggressive = true }, 50},
		{"auto derives from rate limit", func(o *Options) { o.AutoReqLimit = true; o.RateLimit = 100 }, 10},
		{"auto clamps low", func(o *Options) { o.AutoReqLimit = true; o.RateLimit = 10 }, 5},
		{"auto clamps high", func(o *Options) { o.AutoReqLimit = true; o.RateLimit = 1000 }, 15},
		{"auto reduced by high concurrency", func(o *Options) { o.AutoReqLimit = true; o.RateLimit = 1000; o.Concurrency = 100 }, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOptions()
			o.Targets = []string{"http://127.0.0.1:1"}
			tt.apply(o)

			if err := o.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if o.ReqLimitPerTarget != tt.want {
				t.Errorf("ReqLimitPerTarget = %d, want %d", o.ReqLimitPerTarget, tt.want)
			}
		})
	}
}

func TestOptions_NormalisesInvalidValues(t *testing.T) {
	o := NewOptions()
	o.Targets = []string{"http://127.0.0.1:1"}
	o.MaxRespBodySize = 0
	o.StreamBuffer = -1
	o.FingerprintFilterMode = "NONSENSE"
	o.OOB.RateLimit = 0
	o.OOB.Concurrency = -5

	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if o.MaxRespBodySize != DefaultMaxRespBodySize {
		t.Errorf("MaxRespBodySize = %d, want %d", o.MaxRespBodySize, DefaultMaxRespBodySize)
	}
	if o.StreamBuffer != DefaultStreamBuffer {
		t.Errorf("StreamBuffer = %d, want %d", o.StreamBuffer, DefaultStreamBuffer)
	}
	if o.FingerprintFilterMode != FingerprintStrict {
		t.Errorf("FingerprintFilterMode = %q, want %q", o.FingerprintFilterMode, FingerprintStrict)
	}
	if o.OOB.RateLimit != DefaultOOBRateLimit {
		t.Errorf("OOB.RateLimit = %d, want %d", o.OOB.RateLimit, DefaultOOBRateLimit)
	}
	if o.OOB.Concurrency != DefaultOOBConcurrency {
		t.Errorf("OOB.Concurrency = %d, want %d", o.OOB.Concurrency, DefaultOOBConcurrency)
	}
}

func TestWithOptions_PreservesHandlers(t *testing.T) {
	o := NewOptions()
	if err := WithResultHandler(func(Result) {})(o); err != nil {
		t.Fatalf("WithResultHandler: %v", err)
	}

	replacement := NewOptions()
	replacement.Concurrency = 99
	if err := WithOptions(replacement)(o); err != nil {
		t.Fatalf("WithOptions: %v", err)
	}

	if o.Concurrency != 99 {
		t.Errorf("Concurrency = %d, want 99", o.Concurrency)
	}
	if len(o.handlers.result) != 1 {
		t.Errorf("handlers were dropped by WithOptions: got %d, want 1", len(o.handlers.result))
	}
}

func TestWithPortScan_KeepsDefaultsForZeroFields(t *testing.T) {
	o := NewOptions()
	if err := WithPortScan(PortScanOptions{TimeoutMs: 500})(o); err != nil {
		t.Fatalf("WithPortScan: %v", err)
	}

	if !o.EnablePortSan {
		t.Error("WithPortScan should enable the port pre-scan")
	}
	if o.PortScan.Ports != "top" {
		t.Errorf("Ports = %q, want the default \"top\"", o.PortScan.Ports)
	}
	if o.PortScan.ChunkSize != 1000 {
		t.Errorf("ChunkSize = %d, want the default 1000", o.PortScan.ChunkSize)
	}
	if o.PortScan.TimeoutMs != 500 {
		t.Errorf("TimeoutMs = %d, want 500", o.PortScan.TimeoutMs)
	}
}
