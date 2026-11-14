package scanapi

import (
	"encoding/json"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// 原生证据在 proto 里以 JSON 透传，避免在 proto 中镜像第二套 schema。
func TestToProtoEvidenceCarriesNativeJSON(t *testing.T) {
	native := &evidence.Evidence{
		ID:         "evd_x",
		Digest:     "sha256:y",
		PocID:      "poc-x",
		Target:     "http://x/a",
		Confidence: string(evidence.Certain),
		Steps: []evidence.Step{{
			Role:    evidence.RoleConfirm,
			Matched: true,
		}},
	}

	out := ToProtoEvent(&scanstream.Event{
		V:    "1",
		Type: scanstream.TypeResult,
		Result: &scanstream.ResultEvent{
			Severity: "high",
			PocID:    "poc-x",
			Target:   "http://x/a",
			Evidence: &scanstream.Evidence{Native: native},
		},
	})

	raw := out.GetResult().GetEvidence().GetNativeJson()
	if raw == "" {
		t.Fatal("native_json is empty")
	}

	var decoded evidence.Evidence
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("native_json is not valid evidence json: %v", err)
	}
	if decoded.ID != native.ID || decoded.PocID != native.PocID {
		t.Fatalf("unexpected decoded evidence: %+v", decoded)
	}
}

func TestToProtoEvidenceWithoutNative(t *testing.T) {
	out := ToProtoEvent(&scanstream.Event{
		V:    "1",
		Type: scanstream.TypeResult,
		Result: &scanstream.ResultEvent{
			Evidence: &scanstream.Evidence{},
		},
	})
	if got := out.GetResult().GetEvidence().GetNativeJson(); got != "" {
		t.Fatalf("native_json = %q, want empty", got)
	}
}
