package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- checkpoint / resume -----------------------------------------------------

// The engine only reads a checkpoint; writing it is the embedder's job. If the
// SDK does not persist one, WithCheckpoint would look configured but resume
// nothing.
func TestScanner_CheckpointIsWrittenAndSkipsFinishedWork(t *testing.T) {
	srv := newTestServer(t)
	pocDir := t.TempDir()
	writePoc(t, pocDir, "match.yaml", "sdk-test-checkpoint")
	path := filepath.Join(t.TempDir(), "scan.afg")

	scan := func(checkpoint string) *Scanner {
		t.Helper()
		scanner, err := New(context.Background(),
			WithTargets(srv.URL),
			WithPocPaths(pocDir),
			WithPocPathsOnly(),
			WithFingerprintDisabled(),
			WithTimeout(10),
			WithCheckpoint(CheckpointOptions{Path: checkpoint}),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = scanner.Close() })
		if err := scanner.Execute(context.Background()); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		return scanner
	}

	first := scan(path)
	if got := first.ResultCount(); got != 1 {
		t.Fatalf("first scan found %d results, want 1", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("checkpoint was not written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("checkpoint file is empty")
	}

	// The same scan again must skip the work recorded in the checkpoint.
	second := scan(path)
	if got := second.ResultCount(); got != 0 {
		t.Errorf("second scan found %d results, want 0 because the checkpoint marked the PoC done", got)
	}
	if got := second.Stats().CompletedScans; got != 0 {
		t.Errorf("second scan ran %d tasks, want 0", got)
	}

	// Proves the skip above came from the checkpoint rather than from the
	// target or PoC going stale between runs.
	fresh := scan(filepath.Join(t.TempDir(), "fresh.afg"))
	if got := fresh.ResultCount(); got != 1 {
		t.Errorf("scan with a fresh checkpoint found %d results, want 1", got)
	}
}

// A checkpoint path pointing at a file that does not exist yet is the normal
// first run, not an error.
func TestScanner_CheckpointAcceptsMissingFile(t *testing.T) {
	scanner, _ := newTestScanner(t, WithCheckpoint(CheckpointOptions{
		Path:         filepath.Join(t.TempDir(), "does-not-exist.afg"),
		SaveInterval: 50 * time.Millisecond,
	}))
	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := scanner.ResultCount(); got != 1 {
		t.Errorf("found %d results, want 1", got)
	}
}

func TestWithCheckpoint_Validation(t *testing.T) {
	if err := WithCheckpoint(CheckpointOptions{})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("empty path = %v, want ErrInvalidOptions", err)
	}
	if err := WithCheckpoint(CheckpointOptions{Path: "x.afg", SaveInterval: -time.Second})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("negative interval = %v, want ErrInvalidOptions", err)
	}

	o := NewOptions()
	if err := WithCheckpoint(CheckpointOptions{Path: "x.afg"})(o); err != nil {
		t.Fatalf("WithCheckpoint: %v", err)
	}
	if o.Checkpoint.SaveInterval != DefaultCheckpointSaveInterval {
		t.Errorf("SaveInterval = %v, want the default %v", o.Checkpoint.SaveInterval, DefaultCheckpointSaveInterval)
	}
}

// --- cyberspace --------------------------------------------------------------

func TestWithCyberspace_Validation(t *testing.T) {
	tests := []struct {
		name string
		cfg  CyberspaceOptions
	}{
		{"empty engine", CyberspaceOptions{Query: "app:tomcat"}},
		{"unsupported engine", CyberspaceOptions{Engine: "fofa", Query: "app:tomcat"}},
		{"empty query", CyberspaceOptions{Engine: CyberspaceZoomEye}},
		{"negative count", CyberspaceOptions{Engine: CyberspaceZoomEye, Query: "x", Count: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WithCyberspace(tt.cfg)(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("got %v, want ErrInvalidOptions", err)
			}
		})
	}
}

// A search query is a target source, so it must satisfy the "targets are
// required" rule on its own.
func TestOptions_CyberspaceQuerySatisfiesTargetRequirement(t *testing.T) {
	o := NewOptions()
	if err := o.validate(); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("bare options = %v, want ErrNoTargets", err)
	}

	o2 := NewOptions()
	if err := WithCyberspace(CyberspaceOptions{Engine: CyberspaceZoomEye, Query: `app:"tomcat"`})(o2); err != nil {
		t.Fatalf("WithCyberspace: %v", err)
	}
	if err := o2.validate(); err != nil {
		t.Fatalf("validate with a cyberspace query = %v, want nil", err)
	}
}

// --- target pre-probe --------------------------------------------------------

// The pre-probe only starts from Runner.Run. The SDK used to call Execute
// directly, so the option would have been silently inert.
func TestScanner_TargetPreProbeReachesEngineAndStaysSilent(t *testing.T) {
	scanner, _ := newTestScanner(t, WithTargetPreProbe())

	if !scanner.internal.MonitorTargets {
		t.Fatal("TargetPreProbe did not reach the engine options")
	}

	stdout, r, w := captureStdout(t)
	execErr := scanner.Execute(context.Background())
	output := restoreStdout(t, stdout, r, w)

	if execErr != nil {
		t.Fatalf("Execute: %v", execErr)
	}
	if output != "" {
		t.Fatalf("pre-probe wrote to stdout:\n%s", output)
	}
	if got := scanner.ResultCount(); got != 1 {
		t.Errorf("found %d results, want 1", got)
	}
}
