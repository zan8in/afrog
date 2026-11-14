package scanapi

import (
	"encoding/json"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
)

// proto 只是传输形态：一次编解码之后内部事件必须逐字段一致，
// 否则集群回传的落库结果会和本机执行的不一样。
func TestFromProtoEventRoundTrip(t *testing.T) {
	native := &evidence.Evidence{
		ID:         "evd_round",
		Digest:     "sha256:round",
		PocID:      "poc-round",
		Target:     "http://x/a",
		Confidence: string(evidence.Certain),
		Steps: []evidence.Step{{
			Role:    evidence.RoleConfirm,
			Matched: true,
		}},
	}

	cases := []*scanstream.Event{
		{Type: scanstream.TypeStatus, Status: &scanstream.StatusEvent{Status: "running"}},
		{Type: scanstream.TypeScanInfo, ScanInfo: &scanstream.ScanInfoEvent{
			TotalTargets: 3, TotalPocs: 7, TotalScans: 21, OOBEnabled: true, OOBStatus: "ok",
		}},
		{Type: scanstream.TypeProgress, Progress: &scanstream.ProgressEvent{
			Percent: 42, Finished: 8, Total: 19, Rate: 5, ElapsedMs: 1234,
		}},
		{Type: scanstream.TypePhase, Phase: &scanstream.PhaseEvent{
			Phase: "vuln", Status: "running", Finished: 2, Total: 4, Percent: 50,
		}},
		{Type: scanstream.TypeResult, Result: &scanstream.ResultEvent{
			Severity: "high",
			PocID:    "poc-round",
			PocName:  "demo",
			Target:   "http://x/a",
			Evidence: &scanstream.Evidence{
				Exchanges:  []scanstream.Exchange{{Request: "GET / HTTP/1.1", Response: "200 OK", Matched: true}},
				Extractors: map[string]string{"version": "1.2.3"},
				Native:     native,
			},
		}},
		{Type: scanstream.TypePort, Port: &scanstream.PortEvent{
			Host: "x", Port: 443, Service: "https", Product: "nginx", Version: "1.25",
			Device: "router", Hostname: "web-1", OS: "linux", CPE: "cpe:/a:nginx",
			Info: "tls", TLS: true, Confidence: "certain", Banner: "HTTP/1.1 200",
			Extras: map[string]string{"cdn": "cloudflare"},
		}},
		{Type: scanstream.TypeWebProbe, WebProbe: &scanstream.WebProbeEvent{
			URL: "https://x/", Status: 200, Title: "home", Server: "nginx", PoweredBy: "PHP/8",
			Fingerprint: "nginx, php", Confidence: "certain",
			Technologies: []scanstream.WebTechnologyEvent{{Name: "nginx", Version: "1.25", Category: "server", CPE: "cpe:/a:nginx", Confidence: "certain"}},
			Redirects:    []string{"https://x/home"},
			FaviconHash:  "123456",
			TLS:          &scanstream.WebTLSEvent{Subject: "CN=x", Issuer: "CN=ca", NotAfter: "2027-01-01", DNSNames: []string{"x"}},
			WAF:          "cloudflare",
		}},
		{Type: scanstream.TypeHost, Host: &scanstream.HostEvent{Host: "10.0.0.5", Proto: "icmp"}},
		{Type: scanstream.TypeLog, Log: &scanstream.LogEvent{Level: "warn", Text: "slow target"}},
		{Type: scanstream.TypeDone, Done: &scanstream.DoneEvent{
			Status: "completed",
			Summary: &scanstream.Summary{
				Executed: 10, Found: 2, BySeverity: map[string]int64{"high": 1, "info": 1}, ElapsedMs: 999,
			},
		}},
		{Type: scanstream.TypeError, Error: &scanstream.ErrorEvent{Code: "E_TARGET", Message: "bad target"}},
	}

	for _, in := range cases {
		in.V, in.Node, in.Task, in.Seq, in.TsMs = scanstream.Version, "node-a", "task-1", 7, 1730000000000

		t.Run(in.Type, func(t *testing.T) {
			out := FromProtoEvent(ToProtoEvent(in))
			if out == nil {
				t.Fatalf("%s: reverse conversion returned nil", in.Type)
			}
			got, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("marshal reversed: %v", err)
			}
			want, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal original: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s round-trip mismatch:\n got: %s\nwant: %s", in.Type, got, want)
			}
		})
	}
}

// 老控制面收到新节点的事件、或节点写坏了 native_json 时，不能整条证据丢空。
func TestFromProtoEvidenceFallsBackWhenNativeJSONIsBroken(t *testing.T) {
	ev := &scanstream.Event{
		Type: scanstream.TypeResult,
		Result: &scanstream.ResultEvent{
			PocID: "poc-x",
			Evidence: &scanstream.Evidence{
				Exchanges: []scanstream.Exchange{{Request: "GET /", Response: "200", Matched: true}},
				Native:    &evidence.Evidence{ID: "evd_x"},
			},
		},
	}

	proto := ToProtoEvent(ev)
	proto.GetResult().GetEvidence().NativeJson = "{not json"

	out := FromProtoEvent(proto)
	if out == nil || out.Result == nil || out.Result.Evidence == nil {
		t.Fatalf("evidence lost: %+v", out)
	}
	if out.Result.Evidence.Native != nil {
		t.Fatalf("broken native_json should be dropped, got %+v", out.Result.Evidence.Native)
	}
	if len(out.Result.Evidence.Exchanges) != 1 || !out.Result.Evidence.Exchanges[0].Matched {
		t.Fatalf("exchanges not preserved: %+v", out.Result.Evidence.Exchanges)
	}
}

// 空载荷无法判定类型，必须明确返回 nil，而不是造一个 Type 为空的事件。
func TestFromProtoEventWithoutBodyReturnsNil(t *testing.T) {
	if got := FromProtoEvent(&afrogv1.ScanEvent{V: "1", Task: "t"}); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
	if got := FromProtoEvent(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %+v", got)
	}
}
