package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/planner"
	"github.com/zan8in/afrog/v3/pkg/ref"
	"github.com/zan8in/afrog/v3/pkg/sdk"
)

// 端到端验收回归（设计稿 §12）。
//
// 口径：一份固定的离线语料，逐条走通「planner 提议 → 执行 → 落库 → 观测回读 → 重放」，
// 统计四项指标：
//  1. 端到端成功率（目标 → 可重放证据）           ≥ 90%
//  2. Evidence 重放一致率                          ≥ 99%
//  3. 误报率不高于旧引擎（同语料，verify.poc vs 直连 SDK 扫描）
//  4. 旧 CLI / SDK / gRPC 零破坏（由全量 go test / build 覆盖，本文件不重复）
//
// token 成本无对照基线，不在本回归范围内。
//
// 全离线：httptest 靶标 + 临时 HOME 下的本地 PoC，不访问网络。
const (
	acceptanceBudgetRequests = 500
	acceptanceSuccessTarget  = 0.90
	acceptanceReplayTarget   = 0.99
)

// acceptanceShape 决定 PoC 的规则形态，用来覆盖不同请求编排。
type acceptanceShape int

const (
	shapeGet   acceptanceShape = iota // GET + 状态码 + 正文匹配
	shapeIBGet                        // GET + 大小写不敏感正文匹配
	shapePost                         // POST + 正文匹配
	shapeMulti                        // 两条规则 r0() && r1()
)

// acceptanceRoute 是靶标对某个路径的固定响应。
type acceptanceRoute struct {
	status int
	body   string
}

// acceptanceCase 是一条验收用例。
type acceptanceCase struct {
	name     string
	id       string
	severity string
	wantHit  bool
	routes   map[string]acceptanceRoute
	yaml     string
}

func acceptMarker(id string) string { return "AFROG_ACCEPT_" + id }

func acceptHitBody(id string) string {
	return "<html><h1>service</h1>" + acceptMarker(id) + "</html>"
}

func acceptMissBody() string { return "<html><h1>service</h1>absent</html>" }

// renderAcceptancePoc 按规则形态渲染一份合法 PoC YAML。
func renderAcceptancePoc(id, severity string, shape acceptanceShape, marker, path string) string {
	head := fmt.Sprintf("id: %s\n\ninfo:\n  name: acceptance %s\n  author: afrog-acceptance\n  severity: %s\n\ntags: acceptance\n\nrules:\n",
		id, id, severity)
	switch shape {
	case shapePost:
		return head + fmt.Sprintf(
			"  r0:\n    request:\n      method: POST\n      path: %s\n      body: \"probe=1\"\n    expression: response.status == 200 && response.body.bcontains(b\"%s\")\nexpression: r0()\n",
			path, marker)
	case shapeIBGet:
		return head + fmt.Sprintf(
			"  r0:\n    request:\n      method: GET\n      path: %s\n    expression: response.status == 200 && response.body.ibcontains(b\"%s\")\nexpression: r0()\n",
			path, marker)
	case shapeMulti:
		return head + fmt.Sprintf(
			"  r0:\n    request:\n      method: GET\n      path: %s/a\n    expression: response.status == 200 && response.body.bcontains(b\"%s\")\n"+
				"  r1:\n    request:\n      method: GET\n      path: %s/b\n    expression: response.status == 200 && response.body.bcontains(b\"%s\")\nexpression: r0() && r1()\n",
			path, marker, path, marker)
	default:
		return head + fmt.Sprintf(
			"  r0:\n    request:\n      method: GET\n      path: %s\n    expression: response.status == 200 && response.body.bcontains(b\"%s\")\nexpression: r0()\n",
			path, marker)
	}
}

// buildAcceptanceCorpus 构造固定语料：8 条正例（覆盖 rule 形态与 severity）+ 5 条负例。
func buildAcceptanceCorpus() []acceptanceCase {
	mk := func(id, severity string, shape acceptanceShape, hit bool) acceptanceCase {
		path := "/" + id
		c := acceptanceCase{name: id, id: id, severity: severity, wantHit: hit}
		switch shape {
		case shapeMulti:
			a, b := acceptMissBody(), acceptMissBody()
			if hit {
				a, b = acceptHitBody(id), acceptHitBody(id)
			}
			c.routes = map[string]acceptanceRoute{
				path + "/a": {status: http.StatusOK, body: a},
				path + "/b": {status: http.StatusOK, body: b},
			}
		default:
			body := acceptMissBody()
			if hit {
				body = acceptHitBody(id)
				if shape == shapeIBGet {
					// 正文转小写，只有 ibcontains 能命中，用来区分大小写敏感匹配。
					body = strings.ToLower(body)
				}
			}
			c.routes = map[string]acceptanceRoute{path: {status: http.StatusOK, body: body}}
		}
		c.yaml = renderAcceptancePoc(id, severity, shape, acceptMarker(id), path)
		return c
	}

	cases := []acceptanceCase{
		mk("accept-get-info", "info", shapeGet, true),
		mk("accept-get-low", "low", shapeGet, true),
		mk("accept-get-medium", "medium", shapeGet, true),
		mk("accept-get-high", "high", shapeGet, true),
		mk("accept-get-critical", "critical", shapeGet, true),
		mk("accept-ib-get", "info", shapeIBGet, true),
		mk("accept-post", "medium", shapePost, true),
		mk("accept-multi", "high", shapeMulti, true),

		mk("accept-neg-marker", "info", shapeGet, false),
		mk("accept-neg-ib", "info", shapeIBGet, false),
		mk("accept-neg-post", "info", shapePost, false),
	}

	// 负例：状态码不匹配 —— 正文里有 marker，但状态是 500，不能算命中。
	negStatus := mk("accept-neg-status", "low", shapeGet, true)
	negStatus.wantHit = false
	negStatus.routes = map[string]acceptanceRoute{
		"/accept-neg-status": {status: http.StatusInternalServerError, body: acceptHitBody("accept-neg-status")},
	}
	cases = append(cases, negStatus)

	// 负例：多规则只命中一条 —— /a 有 marker，/b 没有，r0() && r1() 应为假。
	negMulti := mk("accept-neg-multi", "medium", shapeMulti, true)
	negMulti.wantHit = false
	negMulti.routes = map[string]acceptanceRoute{
		"/accept-neg-multi/a": {status: http.StatusOK, body: acceptHitBody("accept-neg-multi")},
		"/accept-neg-multi/b": {status: http.StatusOK, body: acceptMissBody()},
	}
	return append(cases, negMulti)
}

// newAcceptanceTarget 按语料路由起一个静态靶标：同一路径永远返回同一份响应，重放才可能一致。
func newAcceptanceTarget(t *testing.T, cases []acceptanceCase) *httptest.Server {
	t.Helper()
	routes := make(map[string]acceptanceRoute, len(cases)*2)
	for _, c := range cases {
		for p, r := range c.routes {
			routes[p] = r
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.WriteHeader(route.status)
		_, _ = w.Write([]byte(route.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// legacyMatchCount 用旧引擎（直连 SDK，即既有 CLI 的检测路径）跑同一份语料，
// 作为误报率对照基线：agent 路径新增的命中数必须不高于它。
func legacyMatchCount(t *testing.T, target, pocPath string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner, err := sdk.New(ctx,
		sdk.WithTargets(target),
		sdk.WithPocPaths(pocPath),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(1),
		sdk.WithRateLimit(10),
		sdk.WithTimeout(20),
		sdk.WithFingerprintDisabled(),
		sdk.WithWebProbe(false),
	)
	if err != nil {
		t.Fatalf("legacy sdk.New: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("legacy scan: %v", err)
	}
	return len(scanner.Results())
}

// acceptanceReport 是验收结论的机器可读形态，供报告引用。
type acceptanceReport struct {
	Suite            string  `json:"suite"`
	GeneratedAt      string  `json:"generated_at"`
	Positives        int     `json:"positives"`
	Successes        int     `json:"successes"`
	SuccessRate      float64 `json:"success_rate"`
	Evidences        int     `json:"evidences"`
	Replays          int     `json:"replays"`
	ReplayConsistent int     `json:"replay_consistent"`
	ReplayRate       float64 `json:"replay_rate"`
	Negatives        int     `json:"negatives"`
	AgentFalsePos    int     `json:"agent_false_positives"`
	LegacyFalsePos   int     `json:"legacy_false_positives"`
	SuccessTarget    float64 `json:"success_target"`
	ReplayTarget     float64 `json:"replay_target"`
}

func TestAgentNativeAcceptanceE2E(t *testing.T) {
	cases := buildAcceptanceCorpus()
	target := newAcceptanceTarget(t, cases)

	s := newIntegrationServer(t, fmt.Sprintf("mode: safe\nbudget:\n  requests: %d\n  duration: 2m\n", acceptanceBudgetRequests))
	if err := db2.NewSnowFlake(); err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	// 把语料 PoC 落到临时 HOME 的 pocs-my，使 verify.poc / verify.replay 能按 poc_id 解析——
	// 这条链路必须与真实使用一致，而不是用 poc_path 走捷径。
	pocDir := filepath.Join(os.Getenv("HOME"), ".config", "afrog", "pocs-my")
	if err := os.MkdirAll(pocDir, 0o700); err != nil {
		t.Fatalf("mkdir pocs-my: %v", err)
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(pocDir, c.id+".yaml"), []byte(c.yaml), 0o600); err != nil {
			t.Fatalf("write poc %s: %v", c.id, err)
		}
	}

	endpoint, err := ref.NormalizeEndpoint(target.URL)
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}

	rep := acceptanceReport{
		Suite:         "afrog agent-native e2e acceptance",
		SuccessTarget: acceptanceSuccessTarget,
		ReplayTarget:  acceptanceReplayTarget,
	}

	resultID := int64(9000)
	for _, c := range cases {
		if c.wantHit {
			rep.Positives++
		} else {
			rep.Negatives++
		}

		t.Run(c.name, func(t *testing.T) {
			pocPath := filepath.Join(pocDir, c.id+".yaml")

			// 0) 种攻击面图：端点 → 技术栈 → 候选 PoC，plan.next 才有依据可提议。
			tech := "accept-" + c.id
			if err := sqlite.EnsureTechGraph(endpoint, []string{tech}, map[string][]string{tech: {c.id}}); err != nil {
				t.Fatalf("seed tech graph: %v", err)
			}

			// 1) plan.next 必须就这条用例给出 verify.poc 提议。
			planOut, err := s.tools["plan.next"].Handler(context.Background(),
				mustJSON(t, map[string]any{"subject": endpoint, "limit": planner.MaxLimit}))
			if err != nil {
				t.Fatalf("plan.next: %v", err)
			}
			plan, ok := planOut.(*planner.Plan)
			if !ok {
				t.Fatalf("plan.next returned %T", planOut)
			}
			proposed := false
			for _, p := range plan.Proposals {
				if p.Action.Name == "verify.poc" && p.Action.PocID == c.id {
					proposed = true
					break
				}
			}
			if !proposed {
				t.Fatalf("plan.next did not propose %s on %s", c.id, endpoint)
			}

			// 2) 执行提议：verify.poc 产出（或判定没有）证据。
			verified, err := s.tools["verify.poc"].Handler(context.Background(),
				mustJSON(t, map[string]any{"poc_id": c.id, "target": endpoint}))
			if err != nil {
				t.Fatalf("verify.poc: %v", err)
			}
			res, ok := verified.(map[string]any)
			if !ok {
				t.Fatalf("verify.poc returned %T", verified)
			}
			found, _ := res["found"].(bool)

			// 3) 旧引擎对照：同语料同一目标。
			legacy := legacyMatchCount(t, endpoint, pocPath)

			if !c.wantHit {
				if found {
					rep.AgentFalsePos++
					t.Errorf("agent false positive on %s", c.id)
				}
				if legacy > 0 {
					rep.LegacyFalsePos++
					t.Errorf("legacy false positive on %s", c.id)
				}
				return
			}

			// 正例：旧引擎必须也能命中，否则语料本身不成立，误报对照失去意义。
			if legacy == 0 {
				t.Errorf("legacy engine missed %s: corpus is invalid", c.id)
			}
			if !found {
				t.Errorf("expected a hit for %s", c.id)
				return
			}

			items, _ := res["results"].([]map[string]any)
			ev := firstEvidence(items)
			if ev == nil {
				t.Errorf("no evidence produced for %s", c.id)
				return
			}
			if !strings.HasPrefix(ev.ID, "evd_") {
				t.Errorf("evidence id = %q, want evd_ prefix", ev.ID)
			}
			if len(ev.Steps) == 0 || !ev.Steps[0].Matched {
				t.Errorf("evidence steps = %+v, want a matched confirm step", ev.Steps)
			}
			if ev.Replay.Command == "" || !ev.Replay.Deterministic {
				t.Errorf("evidence replay = %+v, want a deterministic command", ev.Replay)
			}

			// 4) 落库，让只读数据面能按 evd_ id 回读。
			resultID++
			if err := sqlite.InsertEvidence(ev, resultID, "task-acceptance"); err != nil {
				t.Fatalf("insert evidence: %v", err)
			}
			rep.Evidences++

			// 5) observe.evidence：按内容寻址 id 回读，内容必须一致。
			got, err := s.tools["observe.evidence"].Handler(context.Background(),
				mustJSON(t, map[string]any{"id": ev.ID}))
			if err != nil {
				t.Fatalf("observe.evidence: %v", err)
			}
			back, ok := got.(*evidence.Evidence)
			if !ok || back == nil || back.ID != ev.ID || back.Digest != ev.Digest {
				t.Errorf("observe.evidence mismatch: got %+v want %s/%s", back, ev.ID, ev.Digest)
			}

			// 6) verify.replay：只凭证据 id 复核，必须复现且 digest 一致。
			replayed, err := s.tools["verify.replay"].Handler(context.Background(),
				mustJSON(t, map[string]any{"id": ev.ID}))
			if err != nil {
				t.Fatalf("verify.replay: %v", err)
			}
			rr, ok := replayed.(map[string]any)
			if !ok {
				t.Fatalf("verify.replay returned %T", replayed)
			}
			rep.Replays++
			if rr["replayed"] == true && rr["consistent"] == true {
				rep.ReplayConsistent++
			} else {
				t.Errorf("replay not consistent for %s: %+v", c.id, rr)
			}

			rep.Successes++
		})
	}

	if rep.Positives > 0 {
		rep.SuccessRate = float64(rep.Successes) / float64(rep.Positives)
	}
	if rep.Replays > 0 {
		rep.ReplayRate = float64(rep.ReplayConsistent) / float64(rep.Replays)
	}
	rep.GeneratedAt = time.Now().Format(time.RFC3339)

	// 汇总断言（§12）。
	if rep.SuccessRate < acceptanceSuccessTarget {
		t.Errorf("agent e2e success rate = %.4f, want >= %.2f", rep.SuccessRate, acceptanceSuccessTarget)
	}
	if rep.Replays == 0 || rep.ReplayRate < acceptanceReplayTarget {
		t.Errorf("evidence replay consistency = %.4f (%d/%d), want >= %.2f",
			rep.ReplayRate, rep.ReplayConsistent, rep.Replays, acceptanceReplayTarget)
	}
	if rep.AgentFalsePos > rep.LegacyFalsePos {
		t.Errorf("false positives regressed: agent=%d legacy=%d", rep.AgentFalsePos, rep.LegacyFalsePos)
	}

	raw, _ := json.MarshalIndent(rep, "", "  ")
	t.Logf("acceptance report:\n%s", raw)
	if path := strings.TrimSpace(os.Getenv("AFROG_ACCEPTANCE_REPORT")); path != "" {
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("write acceptance report: %v", err)
		}
	}
}
