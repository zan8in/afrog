package runner

import (
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	afproto "github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

func TestResolveOOBPendingsOncePreservesRequestResponse(t *testing.T) {
	now := time.Now().UTC()
	filterType := "http"
	filter := "f1"
	key := filterType + "|" + filter

	mgr := &OOBManager{
		hitRetention: time.Minute,
		hits: map[string]oobHit{
			key: {
				firstAt: now,
				lastAt:  now,
				count:   1,
				snippet: "callback hit",
			},
		},
		events: map[string][]oobEvent{
			key: {
				{
					at:      now,
					snippet: "callback hit",
				},
			},
		},
	}

	var got *result.Result
	engine := &Engine{}
	engine.oobMgr.Store(mgr)
	r := &Runner{
		engine: engine,
		OnResult: func(rst *result.Result) {
			got = rst
		},
	}

	orig := &result.Result{
		Target:     "http://example.com",
		FullTarget: "http://example.com/xxe",
		PocInfo: &poc.Poc{
			Id: "demo-oob",
			Info: poc.Info{
				Name:     "demo",
				Severity: "critical",
			},
		},
		AllPocResult: []*result.PocResult{
			{
				FullTarget: "http://example.com/xxe",
				ResultRequest: &afproto.Request{
					Raw: []byte("POST /xxe HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
				},
				ResultResponse: &afproto.Response{
					Raw:     []byte("HTTP/1.1 200 OK\r\n\r\nok"),
					Latency: 123,
				},
			},
		},
		Extractor: yaml.MapSlice{{Key: "foo", Value: "bar"}},
	}

	r.registerOOBPendings(orig, []OOBPending{{
		Filter:     filter,
		FilterType: filterType,
		TimeoutSec: 3,
	}})

	if resolved := r.resolveOOBPendingsOnce(); resolved != 1 {
		t.Fatalf("expected 1 resolved pending, got %d", resolved)
	}
	if got == nil {
		t.Fatal("expected resolved result")
	}
	if !got.IsVul {
		t.Fatal("expected resolved result to be vulnerable")
	}
	if !got.SkipCount {
		t.Fatal("expected resolved result to skip count")
	}
	if len(got.AllPocResult) != 1 {
		t.Fatalf("expected 1 poc result, got %d", len(got.AllPocResult))
	}
	pr := got.AllPocResult[0]
	if pr == nil {
		t.Fatal("expected poc result to be non-nil")
	}
	if !pr.IsVul {
		t.Fatal("expected resolved poc result to be marked vulnerable")
	}
	if pr.ResultRequest == nil || string(pr.ResultRequest.Raw) == "" {
		t.Fatal("expected request snapshot to be preserved")
	}
	if pr.ResultResponse == nil || string(pr.ResultResponse.Raw) == "" {
		t.Fatal("expected response snapshot to be preserved")
	}

	foundEvidence := false
	for _, it := range got.Extractor {
		if k, ok := it.Key.(string); ok && k == "oob_evidence" {
			foundEvidence = true
			break
		}
	}
	if !foundEvidence {
		t.Fatal("expected oob_evidence to be attached")
	}
}
