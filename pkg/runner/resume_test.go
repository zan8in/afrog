package runner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/fingerprint"
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

// Web 探测结论必须整条落盘再整条读回：只记「探测过了」会让恢复后的引擎丢掉指纹，
// 进而让依赖指纹的 PoC 被 requires 门控整批误跳过。
func TestScanProgress_WebProbeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resume.afg")

	// URL 与标题里都带逗号：断点文件里 Web 探测行是 JSON，解析必须在按逗号切分之前
	// 认出来，否则这一行会被拆成若干条不存在的 PoC 进度。
	urlWithComma := "http://a.example.com/a,b"
	key := fingerprint.KeyFromTarget(urlWithComma)
	meta := WebMeta{
		URL:         urlWithComma,
		Status:      200,
		Title:       "a, b",
		Server:      "nginx",
		Fingerprint: "PHP 8.1.2",
		Confidence:  "certain",
		WAF:         "Cloudflare",
		Redirects:   []string{"http://a.example.com/", urlWithComma},
		FaviconHash: "123456",
		TLS:         &TLSInfo{Subject: "a.example.com", Issuer: "Let's Encrypt", NotAfter: "2026-12-31"},
	}

	sp, err := NewScanProgress("")
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	sp.RecordWebProbe(key, meta)
	sp.IncrementTask("p1", "http://a")
	if err := sp.AtomicSave(p, 1, 2); err != nil {
		t.Fatalf("AtomicSave: %v", err)
	}

	loaded, err := NewScanProgress(p)
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	got := loaded.ResumedWebProbes()
	if len(got) != 1 {
		t.Fatalf("expected 1 resumed web probe, got %d", len(got))
	}
	if m, ok := got[key]; !ok {
		t.Fatalf("missing web probe key %q", key)
	} else if !reflect.DeepEqual(m, meta) {
		t.Fatalf("web meta mismatch:\n got %+v\nwant %+v", m, meta)
	}

	// Web 探测行不能被当成 PoC 进度：URL 里的逗号曾被切成一串假 poc id。
	if !loaded.ContainsTask("p1", "http://a") {
		t.Fatalf("expected poc p1 task present")
	}
	if loaded.ContainsPoc("http://a.example.com/a") || loaded.ContainsPoc("b") {
		t.Fatalf("web probe line leaked into poc progress")
	}
}

func TestScanProgress_ResumedWebProbes_NilWithoutData(t *testing.T) {
	sp, err := NewScanProgress("")
	if err != nil {
		t.Fatalf("NewScanProgress: %v", err)
	}
	if got := sp.ResumedWebProbes(); got != nil {
		t.Fatalf("expected nil when nothing was probed, got %v", got)
	}
}
