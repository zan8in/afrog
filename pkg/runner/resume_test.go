package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanProgress_OldCSVFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resume.afg")
	if err := os.WriteFile(p, []byte("a,b,c"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sp, err := NewScanProgress(p)
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	if sp.DoneTasks != 0 || sp.TotalTasks != 0 {
		t.Fatalf("expected meta=0, got done=%d total=%d", sp.DoneTasks, sp.TotalTasks)
	}
	for _, id := range []string{"a", "b", "c"} {
		if !sp.Contains(id) {
			t.Fatalf("expected Contains(%q)=true", id)
		}
	}
}

func TestNewScanProgress_MetaAndLineFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resume.afg")
	data := "@done_tasks=12\n@total_tasks=34\na\nb\nc\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sp, err := NewScanProgress(p)
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	if sp.DoneTasks != 12 || sp.TotalTasks != 34 {
		t.Fatalf("unexpected meta: done=%d total=%d", sp.DoneTasks, sp.TotalTasks)
	}
	for _, id := range []string{"a", "b", "c"} {
		if !sp.Contains(id) {
			t.Fatalf("expected Contains(%q)=true", id)
		}
	}
}

func TestScanProgress_AtomicSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resume.afg")

	sp, err := NewScanProgress("")
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	sp.IncrementTask("p1", "http://a")
	sp.IncrementTask("p1", "http://b")
	sp.MarkPocDone("p1")

	if err := sp.AtomicSave(p, 7, 99); err != nil {
		t.Fatalf("AtomicSave: %v", err)
	}

	loaded, err := NewScanProgress(p)
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	if loaded.DoneTasks != 7 || loaded.TotalTasks != 99 {
		t.Fatalf("unexpected meta: done=%d total=%d", loaded.DoneTasks, loaded.TotalTasks)
	}
	if !loaded.ContainsPoc("p1") {
		t.Fatalf("expected poc p1 present")
	}
	if loaded.ContainsTask("p1", "http://a") || loaded.ContainsTask("p1", "http://b") {
		t.Fatalf("expected task keys to be compacted when poc is done")
	}
}

func TestNewScanProgress_TaskKeysWithoutMeta_SetsDoneTasks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resume.afg")
	k1 := taskKey("p1", "http://a")
	k2 := taskKey("p2", "http://b")
	data := k1 + "\n" + k2 + "\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sp, err := NewScanProgress(p)
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	if sp.DoneTasks != 2 {
		t.Fatalf("expected DoneTasks=2, got %d", sp.DoneTasks)
	}
	if !sp.ContainsTask("p1", "http://a") || !sp.ContainsTask("p2", "http://b") {
		t.Fatalf("expected task keys present")
	}
	if sp.ContainsPoc("p1") || sp.ContainsPoc("p2") {
		t.Fatalf("expected poc keys not present")
	}
}
