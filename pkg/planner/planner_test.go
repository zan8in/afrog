package planner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// withStore 建一个隔离的库，并把 PoC 元信息换成固定桩数据：
// 排序断言不应该随真实漏洞库的内容变化。
func withStore(t *testing.T, items map[string]pocsrepo.Item) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	prev := pocMetadata
	pocMetadata = func(id string) (pocsrepo.Item, bool) {
		it, ok := items[id]
		return it, ok
	}
	t.Cleanup(func() { pocMetadata = prev })

	// OOB 判定也换成桩：默认都不需要带外，需要的那条用例自己改写。
	prevOOB := pocNeedsOOB
	pocNeedsOOB = func(string) bool { return false }
	t.Cleanup(func() { pocNeedsOOB = prevOOB })
}

// 同一源站上的候选 PoC 要合并成一条 scan.start 提议，关键词取技术栈。
func TestBuildProposesScanStartPerOrigin(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-1": {ID: "CVE-2024-1", Severity: "critical"},
		"CVE-2024-2": {ID: "CVE-2024-2", Severity: "low"},
	})

	endpoint := "https://a.example/login"
	if err := sqlite.EnsureEndpointGraph(endpoint, ""); err != nil {
		t.Fatalf("ensure endpoint graph: %v", err)
	}
	if err := sqlite.EnsureTechGraph(endpoint, []string{"ThinkPHP 6"}, map[string][]string{
		"ThinkPHP 6": {"CVE-2024-1", "CVE-2024-2"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 1 {
		t.Fatalf("proposals = %+v, want 同一源站合并成 1 条", plan.Proposals)
	}

	first := plan.Proposals[0]
	if first.Action.Name != "scan.start" || first.Action.Search != "thinkphp 6" {
		t.Fatalf("first proposal = %+v, want scan.start search=thinkphp 6", first)
	}
	if first.Action.Target != "https://a.example" {
		t.Fatalf("target = %q, want 该端点所在源站", first.Action.Target)
	}
	if first.Category != CategoryCandidatePoc || first.Severity != "critical" {
		t.Fatalf("category/severity = %q/%q", first.Category, first.Severity)
	}
	if !contains(first.Evidence, endpoint) || !contains(first.Evidence, "tech:thinkphp 6") {
		t.Fatalf("依据缺失: %+v", first.Evidence)
	}
}

// 不同源站的提议按各自最高等级排序：critical 排在 low 之前。
func TestBuildRanksProposalsBySeverity(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-crit": {ID: "CVE-2024-crit", Severity: "critical"},
		"CVE-2024-low":  {ID: "CVE-2024-low", Severity: "low"},
	})

	if err := sqlite.EnsureTechGraph("https://high.example/login", []string{"ThinkPHP"}, map[string][]string{
		"ThinkPHP": {"CVE-2024-crit"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}
	if err := sqlite.EnsureTechGraph("https://low.example/login", []string{"Jenkins"}, map[string][]string{
		"Jenkins": {"CVE-2024-low"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 2 {
		t.Fatalf("proposals = %+v, want 2", plan.Proposals)
	}
	if plan.Proposals[0].Action.Target != "https://high.example" {
		t.Fatalf("critical 应排在 low 之前: %+v", plan.Proposals)
	}
	if plan.Proposals[0].Score <= plan.Proposals[1].Score {
		t.Fatalf("critical 分数应高于 low: %d vs %d", plan.Proposals[0].Score, plan.Proposals[1].Score)
	}
}

// 同一源站只提议一条，哪怕候选挂在多个端点上。
func TestBuildDedupesByOrigin(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-9": {ID: "CVE-2024-9", Severity: "high"},
	})

	for _, endpoint := range []string{"https://a.example/a", "https://a.example/b"} {
		if err := sqlite.EnsureTechGraph(endpoint, []string{"Jenkins"}, map[string][]string{
			"Jenkins": {"CVE-2024-9"},
		}); err != nil {
			t.Fatalf("ensure tech graph: %v", err)
		}
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 1 {
		t.Fatalf("proposals = %+v, want 归并成 1 条", plan.Proposals)
	}
	if got := endpointEvidence(plan.Proposals[0]); len(got) != 2 {
		t.Fatalf("依据应保留两个端点: %+v", got)
	}
}

// 已经出过结果行的候选不再计入，并计入 Excluded；源站上仍有未出结论的候选时照常提议。
func TestBuildSkipsConcludedCombination(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-1": {ID: "CVE-2024-1", Severity: "critical"},
		"CVE-2024-2": {ID: "CVE-2024-2", Severity: "low"},
	})

	endpoint := "https://a.example/login"
	if err := sqlite.EnsureTechGraph(endpoint, []string{"ThinkPHP 6"}, map[string][]string{
		"ThinkPHP 6": {"CVE-2024-1", "CVE-2024-2"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}
	if _, err := sqlite.InsertWebProbeSummary("t1", "CVE-2024-1", "旧命中",
		"a.example", endpoint, nil); err != nil {
		t.Fatalf("seed result: %v", err)
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if plan.Excluded != 1 {
		t.Fatalf("excluded = %d, want 1", plan.Excluded)
	}
	if len(plan.Proposals) != 1 || plan.Proposals[0].Action.Search != "thinkphp 6" {
		t.Fatalf("proposals = %+v, want 该源站仍合并成 1 条 scan.start", plan.Proposals)
	}
}

// 还没识别过技术栈的源站要提议一次指纹；同一源站已有技术栈时不再提议。
func TestBuildProposesFingerprintForUnknownOrigin(t *testing.T) {
	withStore(t, nil)

	if err := sqlite.EnsureEndpointGraph("http://b.example/admin", ""); err != nil {
		t.Fatalf("ensure endpoint graph: %v", err)
	}
	if err := sqlite.EnsureEndpointGraph("http://c.example/admin", ""); err != nil {
		t.Fatalf("ensure endpoint graph: %v", err)
	}
	// c.example 已经指纹过（另一个端点上有技术栈），整个源站不再提议。
	if err := sqlite.EnsureTechGraph("http://c.example/api", []string{"Nginx"}, nil); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 1 {
		t.Fatalf("proposals = %+v, want 只提议 b.example", plan.Proposals)
	}
	got := plan.Proposals[0]
	if got.Action.Name != "probe.fingerprint" || got.Action.Target != "http://b.example" {
		t.Fatalf("proposal = %+v", got)
	}
	if got.Category != CategoryUnknownTech || len(got.Evidence) != 1 ||
		got.Evidence[0] != "http://b.example/admin" {
		t.Fatalf("proposal 依据 = %+v", got)
	}
}

// subject 精确匹配与前缀展开要按预期收窄范围。
func TestBuildSubjectScoping(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-1": {ID: "CVE-2024-1", Severity: "critical"},
	})

	for _, endpoint := range []string{"https://a.example/a", "https://a.example/b"} {
		if err := sqlite.EnsureTechGraph(endpoint, []string{"ThinkPHP"}, map[string][]string{
			"ThinkPHP": {"CVE-2024-1"},
		}); err != nil {
			t.Fatalf("ensure tech graph: %v", err)
		}
	}

	exact, err := Build(Options{Subject: "https://a.example/a"})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(exact.Proposals) != 1 {
		t.Fatalf("精确匹配应只命中一个端点: %+v", exact.Proposals)
	}
	if got := endpointEvidence(exact.Proposals[0]); len(got) != 1 || got[0] != "https://a.example/a" {
		t.Fatalf("精确匹配的依据 = %+v", got)
	}

	under, err := Build(Options{Subject: "https://a.example", Under: true})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(under.Proposals) != 1 {
		t.Fatalf("前缀匹配应归并成 1 条: %+v", under.Proposals)
	}
	if got := endpointEvidence(under.Proposals[0]); len(got) != 2 {
		t.Fatalf("前缀匹配应覆盖两个端点: %+v", got)
	}
}

// 提议数超过 limit 时截断并置位 Truncated。
func TestBuildTruncates(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-1": {ID: "CVE-2024-1", Severity: "critical"},
		"CVE-2024-2": {ID: "CVE-2024-2", Severity: "high"},
	})

	if err := sqlite.EnsureTechGraph("https://a.example/login", []string{"ThinkPHP"}, map[string][]string{
		"ThinkPHP": {"CVE-2024-1"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}
	if err := sqlite.EnsureTechGraph("https://b.example/login", []string{"Jenkins"}, map[string][]string{
		"Jenkins": {"CVE-2024-2"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	plan, err := Build(Options{Limit: 1})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 1 || !plan.Truncated {
		t.Fatalf("plan = %+v, want 截断到 1 条", plan)
	}
}

// 还依赖带外回连的候选要把 requires_oob 透出来：调用方据此先补反连配置，
// 否则执行时 scan.start 只会 fail-closed。
func TestBuildMarksProposalsRequiringOOB(t *testing.T) {
	withStore(t, map[string]pocsrepo.Item{
		"CVE-2024-oob": {ID: "CVE-2024-oob", Severity: "high"},
		"CVE-2024-dry": {ID: "CVE-2024-dry", Severity: "high"},
	})
	pocNeedsOOB = func(id string) bool { return id == "CVE-2024-oob" }

	if err := sqlite.EnsureTechGraph("https://a.example/login", []string{"ThinkPHP"}, map[string][]string{
		"ThinkPHP": {"CVE-2024-oob"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}
	if err := sqlite.EnsureTechGraph("https://b.example/login", []string{"Jenkins"}, map[string][]string{
		"Jenkins": {"CVE-2024-dry"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	plan, err := Build(Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Proposals) != 2 {
		t.Fatalf("proposals = %+v, want 2", plan.Proposals)
	}
	got := make(map[string]bool, 2)
	for _, p := range plan.Proposals {
		got[p.Action.Target] = p.RequiresOOB
	}
	if !got["https://a.example"] {
		t.Fatal("带 OOB 候选的源站必须标记 requires_oob")
	}
	if got["https://b.example"] {
		t.Fatal("只有普通候选的源站不应标记 requires_oob")
	}
}

// 默认实现认不认「反向 PoC」：直接拿真实 PoC 库里的 oob-http 形态过一遍。
func TestDefaultPocNeedsOOBDistinguishesReversePocs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	pocOOBCacheMu.Lock()
	pocOOBCache = map[string]bool{}
	pocOOBCacheMu.Unlock()

	dir := filepath.Join(os.Getenv("HOME"), ".config", "afrog", "pocs-my")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir pocs-my: %v", err)
	}
	reverse := `id: unit-oob-reverse
info:
  name: unit oob reverse
  author: afrog-test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /?http=curl%20{{oob.HTTP}}
    expression: oobCheck(oob.ProtocolHTTP, 3)
expression: r0()
`
	plain := `id: unit-oob-plain
info:
  name: unit oob plain
  author: afrog-test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
expression: r0()
`
	for name, body := range map[string]string{"unit-oob-reverse.yaml": reverse, "unit-oob-plain.yaml": plain} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if !defaultPocNeedsOOB("unit-oob-reverse") {
		t.Fatal("a reverse PoC must be reported as requiring OOB")
	}
	if defaultPocNeedsOOB("unit-oob-plain") {
		t.Fatal("a plain PoC must not be reported as requiring OOB")
	}
	if defaultPocNeedsOOB("") || defaultPocNeedsOOB("no-such-poc-id") {
		t.Fatal("empty / unknown ids must not be reported as requiring OOB")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// endpointEvidence 只取依据里的端点，过滤掉 tech: 派生节点。
func endpointEvidence(p Proposal) []string {
	out := make([]string, 0, len(p.Evidence))
	for _, v := range p.Evidence {
		if !strings.HasPrefix(v, "tech:") {
			out = append(out, v)
		}
	}
	return out
}
