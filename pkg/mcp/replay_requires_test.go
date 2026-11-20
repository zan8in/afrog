package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/ref"
)

// verify.replay 只按证据里的 poc_id 单跑一个 PoC（runPocScan 的 -s 就是该 id），不会
// 顺带加载为该 PoC 的 requires 提供准入的指纹 PoC。若单跑时仍走默认门控，任何带
// requires 硬依赖的 PoC 都会被整条跳过——得到一个必然 replayed:false 的假阴性。
//
// 本用例用「指纹 PoC 注册 token + requires 门控 PoC」复现这条链路：先经 scan.start
// 拿到证据（此时指纹 PoC 与门控 PoC 同批加载，requires 按真实指纹放行），再 verify.replay
// 复核，必须复现。它锁定的是 runPocScan 对「单 PoC 实跑」关闭门控这一口径。
func TestVerifyReplayReproducesRequiresGatedPoc(t *testing.T) {
	requireSubprocess(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gate" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("GATE-OK"))
	}))
	t.Cleanup(srv.Close)
	endpoint, err := ref.NormalizeEndpoint(srv.URL)
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}

	s := newSubprocessServer(t, "mode: safe\nbudget:\n  requests: 200\n  duration: 2m\n")
	if err := db2.NewSnowFlake(); err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	// 指纹 PoC：命中后其 id 注册为目标 token，供 requires 门控放行。
	installPoc(t, "mcp-req-fp", `id: mcp-req-fp
info:
  name: req gate fingerprint
  author: afrog-test
  severity: info
  tags: mcpneed,fingerprint
rules:
  r0:
    request:
      method: GET
      path: /gate
    expression: response.status == 200 && response.body.bcontains(b"GATE-OK")
expression: r0()
`)
	// 门控 PoC：严格依赖上面的指纹 PoC（requires 命中其 id 才放行）。
	installPoc(t, "mcp-req-gated", `id: mcp-req-gated
info:
  name: req gated
  author: afrog-test
  severity: high
  tags: mcpneed
  requires: [mcp-req-fp]
rules:
  r0:
    request:
      method: GET
      path: /gate
    expression: response.status == 200 && response.body.bcontains(b"GATE-OK")
expression: r0()
`)

	// scan.start 用共享 tag 关键词一次加载两条：指纹 PoC 先跑并注册 token，门控 PoC
	// 因此按真实指纹放行、产出证据。
	out := runTool(t, s, "scan.start", map[string]any{"target": endpoint, "search": "mcpneed"})
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("scan.start returned %T", out)
	}
	items, _ := res["results"].([]map[string]any)
	var ev *evidence.Evidence
	for _, item := range items {
		if id, _ := item["poc_id"].(string); id != "mcp-req-gated" {
			continue
		}
		if e, ok := item["evidence"].(*evidence.Evidence); ok {
			ev = e
		}
	}
	if ev == nil {
		t.Fatalf("scan.start produced no evidence for the gated PoC: %+v", res)
	}

	// 落库，让 verify.replay 能按 evd_ id 回读证据。
	if err := sqlite.InsertEvidence(ev, 4242, "task-replay-requires"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	replayed := runTool(t, s, "verify.replay", map[string]any{"id": ev.ID})
	rr, ok := replayed.(map[string]any)
	if !ok {
		t.Fatalf("verify.replay returned %T", replayed)
	}
	if rr["replayed"] != true || rr["consistent"] != true {
		t.Fatalf("replay of a requires-gated PoC must reproduce: %+v", rr)
	}
}
