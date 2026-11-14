package sdk

import (
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// 证据在 SDK 里只带结构与证明力，原始报文仍由 Exchanges 承载，避免一份命中
// 在事件里出现两份大 payload。
func TestNewResultExposesEvidenceWithoutPayload(t *testing.T) {
	ev := &evidence.Evidence{
		ID:         "evd_x",
		Digest:     "sha256:y",
		PocID:      "poc-x",
		Target:     "http://x/a",
		Confidence: string(evidence.Certain),
		Steps: []evidence.Step{{
			Role:    evidence.RoleConfirm,
			Matched: true,
			Request: evidence.Request{
				Method:  "GET",
				URL:     "http://x/a?id=1'",
				Headers: "Authorization: secret-token",
				Body:    "request-secret",
			},
			Response: evidence.Response{
				Status:    200,
				Headers:   "Set-Cookie: sid=1",
				Body:      "response-secret",
				LatencyMs: 12,
			},
			Extracted: map[string]string{"proof": "SQL syntax"},
		}},
	}

	out := newResult(&result.Result{Evidence: ev}, false, time.Now())
	if out.Evidence == nil {
		t.Fatal("expected evidence in sdk result")
	}
	if out.Evidence.ID != ev.ID || out.Evidence.Digest != ev.Digest {
		t.Fatalf("unexpected evidence identity: %+v", out.Evidence)
	}

	step := out.Evidence.Steps[0]
	if step.Request.Body != "" || step.Response.Body != "" {
		t.Fatalf("body must be stripped from sdk evidence: %+v", step)
	}
	if step.Request.Headers != "" || step.Response.Headers != "" {
		t.Fatalf("headers must be stripped from sdk evidence: %+v", step)
	}
	if step.Request.Method != "GET" || step.Response.Status != 200 || step.Response.LatencyMs != 12 {
		t.Fatalf("structural fields must be preserved: %+v", step)
	}
	if step.Extracted["proof"] != "SQL syntax" {
		t.Fatalf("extracted proof must be preserved: %+v", step.Extracted)
	}

	// 快照必须是深拷贝：SDK 侧清洗不能影响引擎持有的原始对象。
	if ev.Steps[0].Request.Body != "request-secret" {
		t.Fatal("sdk must not mutate the engine's evidence")
	}
}
