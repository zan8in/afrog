package evidence

import (
	"testing"
	"time"
)

func fixedBuilder() *Builder {
	b := NewBuilder("CVE-2024-0001", "https://example.com/a?id=1")
	b.now = func() time.Time { return time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC) }
	return b
}

func confirmStep() Step {
	return Step{
		Role:     RoleConfirm,
		Matched:  true,
		Request:  Request{Method: "GET", URL: "https://example.com/a?id=1'"},
		Response: Response{Status: 200, Body: "error", LatencyMs: 120},
		Extracted: map[string]string{
			"proof": "SQL syntax",
		},
	}
}

func TestBuildAssignsStableID(t *testing.T) {
	b := fixedBuilder()
	b.AddStep(confirmStep())
	ev := b.Build()
	if ev == nil {
		t.Fatal("expected evidence")
	}
	if ev.ID == "" || ev.Digest == "" {
		t.Fatalf("expected id and digest, got %+v", ev)
	}
	if ev.ID[:4] != "evd_" {
		t.Fatalf("unexpected id prefix: %q", ev.ID)
	}
	if ev.Replay.Command == "" || !ev.Replay.Deterministic {
		t.Fatalf("expected replay command, got %+v", ev.Replay)
	}
	if ev.Created != "2026-11-14T10:00:00Z" {
		t.Fatalf("unexpected created: %q", ev.Created)
	}
}

func TestDigestIgnoresLatencyAndBody(t *testing.T) {
	a := fixedBuilder()
	a.AddStep(confirmStep())

	b := fixedBuilder()
	step := confirmStep()
	step.Response.LatencyMs = 9999
	step.Response.Body = "totally different page each run"
	b.AddStep(step)

	if a.Build().ID != b.Build().ID {
		t.Fatal("latency and response body must not affect the evidence id")
	}
}

func TestDigestCoversProof(t *testing.T) {
	a := fixedBuilder()
	a.AddStep(confirmStep())

	b := fixedBuilder()
	step := confirmStep()
	step.Extracted = map[string]string{"proof": "syntax error near '1'"}
	b.AddStep(step)

	if a.Build().ID == b.Build().ID {
		t.Fatal("different extracted proof must produce a different evidence id")
	}
}

func TestBuildDropsEmptySteps(t *testing.T) {
	b := fixedBuilder()
	b.AddStep(Step{})
	if ev := b.Build(); ev != nil {
		t.Fatalf("expected nil evidence, got %+v", ev)
	}
}

func TestCloneIsDeep(t *testing.T) {
	b := fixedBuilder()
	b.AddStep(confirmStep())
	ev := b.Build()

	cp := ev.Clone()
	cp.Steps[0].Extracted["proof"] = "mutated"
	cp.Steps[0].Response.Status = 500

	if ev.Steps[0].Extracted["proof"] == "mutated" {
		t.Fatal("clone must not share extracted map")
	}
	if ev.Steps[0].Response.Status != 200 {
		t.Fatal("clone must not share response")
	}
}
