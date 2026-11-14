package drafter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// withHome 把 HOME 指向隔离目录并打开同一份 sqlite，隔离掉真实待审队列与用户 PoC。
func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(pocsrepo.EnvCuratedDisabled, "1")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)
	return home
}

// writeDraft 在临时目录里落一份可解析的草稿，返回其路径。
func writeDraft(t *testing.T, id string) string {
	t.Helper()
	body := `id: ` + id + `
info:
  name: ` + id + ` check
  author: afrog-test
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
expression: r0()
`
	path := filepath.Join(t.TempDir(), id+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write draft: %v", err)
	}
	return path
}

func TestSubmitRequiresEvidence(t *testing.T) {
	withHome(t)

	if _, err := Submit(SubmitOptions{Path: writeDraft(t, "cand-a"), Target: "http://a.test"}); err == nil {
		t.Fatal("submit without evidence must fail")
	}
}

func TestSubmitRejectsDraftWithoutRules(t *testing.T) {
	withHome(t)

	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte("id: cand-b\ninfo:\n  name: none\n"), 0o644); err != nil {
		t.Fatalf("write draft: %v", err)
	}
	if _, err := Submit(SubmitOptions{Path: path, Target: "http://a.test", EvidenceID: "evd_x"}); err == nil {
		t.Fatal("submit without rules must fail")
	}
}

func TestSubmitThenApproveWritesMyPoc(t *testing.T) {
	home := withHome(t)
	path := writeDraft(t, "cand-c")

	rec, err := Submit(SubmitOptions{
		Path:           path,
		Target:         "http://a.test",
		EvidenceID:     "evd_abc",
		EvidenceDigest: "sha256:abc",
		Requests:       3,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if rec.Status != sqlite.PocDraftPending || rec.ID != "cand-c" || rec.Severity != "high" {
		t.Fatalf("rec = %+v", rec)
	}
	if rec.Capability == "" {
		t.Fatalf("capability should be derived from the draft: %+v", rec)
	}

	pending, err := List(sqlite.PocDraftPending)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "cand-c" {
		t.Fatalf("pending = %+v", pending)
	}

	res, err := Approve("cand-c")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	want := filepath.Join(home, ".config", "afrog", "pocs-my", "cand-c.yaml")
	if res.Path != want {
		t.Fatalf("approve path = %q, want %q", res.Path, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("approved poc missing: %v", err)
	}

	rec, err = Show("cand-c")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if rec.Status != sqlite.PocDraftApproved {
		t.Fatalf("status = %q, want approved", rec.Status)
	}

	// 入库后应能从仓库按 my 源查到。
	items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "my"})
	if err != nil {
		t.Fatalf("list my pocs: %v", err)
	}
	found := false
	for _, it := range items {
		if it.ID == "cand-c" {
			found = true
		}
	}
	if !found {
		t.Fatalf("approved poc not visible in my source: %+v", items)
	}
}

func TestApproveConflictsWithCurated(t *testing.T) {
	home := withHome(t)
	path := writeDraft(t, "cand-d")
	if _, err := Submit(SubmitOptions{Path: path, Target: "http://a.test", EvidenceID: "evd_def"}); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// 造一份同 id 的 curated PoC：跨来源按优先级去重，my 版本会被静默忽略，必须挡住。
	// 需要先把 withHome 关掉的 curated 源重新打开，否则这条来源不参与去重。
	t.Setenv(pocsrepo.EnvCuratedDisabled, "")
	// 用非默认目录：默认目录在无授权时会被 curatedBlocked 清空，导致这条来源落空。
	curatedDir := filepath.Join(home, "curated-x")
	if err := os.MkdirAll(curatedDir, 0o755); err != nil {
		t.Fatalf("mkdir curated: %v", err)
	}
	t.Setenv(pocsrepo.EnvCuratedPocDir, curatedDir)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	if err := os.WriteFile(filepath.Join(curatedDir, "cand-d.yaml"), src, 0o644); err != nil {
		t.Fatalf("write curated poc: %v", err)
	}

	if _, err := Approve("cand-d"); err == nil {
		t.Fatal("approve must fail when the id is already provided by another source")
	}
}

func TestRejectKeepsNote(t *testing.T) {
	withHome(t)
	path := writeDraft(t, "cand-e")
	if _, err := Submit(SubmitOptions{Path: path, Target: "http://a.test", EvidenceID: "evd_ghi"}); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if err := Reject("cand-e", "false positive on staging"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	rec, err := Show("cand-e")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if rec.Status != sqlite.PocDraftRejected || rec.Note != "false positive on staging" {
		t.Fatalf("rec = %+v", rec)
	}
	if len(mustPending(t)) != 0 {
		t.Fatalf("rejected candidate must leave the pending queue")
	}
}

func mustPending(t *testing.T) []sqlite.PocDraft {
	t.Helper()
	items, err := List(sqlite.PocDraftPending)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return items
}

func TestApproveUnknownID(t *testing.T) {
	withHome(t)
	if _, err := Approve("nope"); err == nil {
		t.Fatal("approve of an unknown id must fail")
	}
}

// CLI 入口只做「参数 → 状态机」的分派，这里锁住未知子命令与未知 id 的错误语义。
func TestCommandDispatchErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(pocsrepo.EnvCuratedDisabled, "1")

	if err := Command([]string{"bogus"}); err == nil {
		t.Fatal("unknown subcommand must fail")
	}
	if err := Command([]string{"approve", "nope"}); err == nil {
		t.Fatal("approve of an unknown id must fail")
	}
	if err := Command([]string{"reject"}); err == nil {
		t.Fatal("reject without an id must fail")
	}
}
