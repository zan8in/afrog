package runner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

func withObservationDB(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)
}

// 一次 https 探测要同时留下 tech 与 tls 两条观测：证书独立于技术栈变化。
func TestRecordTechObservationWritesTechAndTLS(t *testing.T) {
	withObservationDB(t)

	recordTechObservation(WebMeta{
		URL: "https://a.example/login", Status: 200, Server: "nginx",
		Technologies: []WebTech{{Name: "Nginx", Version: "1.25"}},
		TLS: &TLSInfo{
			Subject:  "CN=a.example",
			Issuer:   "CN=R3",
			NotAfter: "2027-01-01T00:00:00Z",
			DNSNames: []string{"a.example", "www.a.example"},
		},
	})
	sqlite.FlushObservations()

	page, err := sqlite.SelectObservations(sqlite.ObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("select observations: %v", err)
	}
	kinds := map[string]observation.Observation{}
	for _, item := range page.Items {
		kinds[item.Kind] = item
	}
	if _, ok := kinds[observation.KindTech]; !ok {
		t.Fatalf("缺少 tech 观测：%+v", page.Items)
	}
	tlsObs, ok := kinds[observation.KindTLS]
	if !ok {
		t.Fatalf("缺少 tls 观测：%+v", page.Items)
	}
	if tlsObs.Source != observation.SourceWebscan {
		t.Fatalf("tls source = %q, want webscan", tlsObs.Source)
	}
	// 两条观测共用同一个归一化端点作为 subject，Agent 才能按端点对齐。
	if tlsObs.Subject != "https://a.example/login" {
		t.Fatalf("tls subject = %q", tlsObs.Subject)
	}
	var payload observation.TLSCert
	if err := json.Unmarshal(tlsObs.Payload, &payload); err != nil {
		t.Fatalf("decode tls payload: %v", err)
	}
	if payload.Issuer != "CN=R3" || len(payload.DNSNames) != 2 {
		t.Fatalf("tls payload = %+v", payload)
	}
}

// 主机名解析观测：IP 字面量没有 DNS 事实、不记录；localhost 解析成功则落一条 dns 观测。
func TestRecordDNSObservation(t *testing.T) {
	withObservationDB(t)

	recordDNSObservation("http://127.0.0.1/x")
	recordDNSObservation("http://localhost/x")
	sqlite.FlushObservations()

	page, err := sqlite.SelectObservations(sqlite.ObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("select observations: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want 1（IP 字面量不产生 DNS 观测）", len(page.Items))
	}
	obs := page.Items[0]
	if obs.Kind != observation.KindDNS || obs.Source != observation.SourceWebscan {
		t.Fatalf("kind/source = %s/%s, want dns/webscan", obs.Kind, obs.Source)
	}
	if obs.Subject != "localhost" {
		t.Fatalf("subject = %q, want localhost", obs.Subject)
	}
	var payload observation.DNS
	if err := json.Unmarshal(obs.Payload, &payload); err != nil {
		t.Fatalf("decode dns payload: %v", err)
	}
	if payload.Host != "localhost" || len(payload.Addresses) == 0 {
		t.Fatalf("dns payload = %+v", payload)
	}
}

// 带外回连即使摘要抖动也只留一行，且摘要按上限截断。
func TestRecordOOBObservation(t *testing.T) {
	withObservationDB(t)

	ent := &oobPendingEntry{
		filter: "abc.oob.example", filterType: "dns", token: "t1",
		target: "https://a.example/x", poc: poc.Poc{Id: "CVE-2024-1"},
	}
	long := strings.Repeat("a", observation.ExcerptLimit()+32)
	recordOOBObservation(ent, long)
	recordOOBObservation(ent, "1.2.3.4 at 11:00")
	sqlite.FlushObservations()

	page, err := sqlite.SelectObservations(sqlite.ObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("select observations: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want 1（回连摘要抖动必须去重）", len(page.Items))
	}
	obs := page.Items[0]
	if obs.Source != observation.SourceOOB || obs.Kind != observation.KindOOBHit {
		t.Fatalf("source/kind = %s/%s, want oob/oob_hit", obs.Source, obs.Kind)
	}
	if obs.Subject != "https://a.example/x" {
		t.Fatalf("subject = %q", obs.Subject)
	}
	var payload observation.OOBHit
	if err := json.Unmarshal(obs.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.PocID != "CVE-2024-1" || payload.FilterType != "dns" {
		t.Fatalf("payload = %+v", payload)
	}
	if !strings.HasSuffix(payload.Evidence, "…[truncated]") {
		t.Fatalf("超长摘要必须截断：%q", payload.Evidence)
	}
}
