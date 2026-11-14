package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/agentapi"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/observation"
)

// probe.http 发出的请求必须落成 http_transaction，并能被 observe.observations 按游标拉回。
func TestProbeHTTPRecordsObservation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Lab", "obs")
		_, _ = w.Write([]byte("hello observation"))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := s.tools["probe.http"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": srv.URL + "/probe?x=1",
	})); err != nil {
		t.Fatalf("probe.http: %v", err)
	}
	sqlite.FlushObservations()

	out, err := s.tools["observe.observations"].Handler(context.Background(), mustJSON(t, map[string]any{
		"kinds": []string{observation.KindHTTPTransaction},
	}))
	if err != nil {
		t.Fatalf("observe.observations: %v", err)
	}
	page, ok := out.(*sqlite.ObservationPage)
	if !ok || page == nil || len(page.Items) != 1 {
		t.Fatalf("page = %#v, want exactly one http_transaction", out)
	}

	item := page.Items[0]
	if item.Kind != observation.KindHTTPTransaction || item.Source != observation.SourceHTTP {
		t.Fatalf("unexpected item: %+v", item)
	}
	if item.Subject != srv.URL+"/probe" {
		t.Fatalf("subject = %q, want the normalized endpoint", item.Subject)
	}
	if page.NextSeq != item.Seq || page.HasMore {
		t.Fatalf("cursor = %+v, want next_seq=%d and no more pages", page, item.Seq)
	}

	payload := string(item.Payload)
	if !strings.Contains(payload, `"method":"GET"`) || !strings.Contains(payload, `"status":200`) {
		t.Fatalf("payload missing transaction facts: %s", payload)
	}
	if !strings.Contains(payload, "X-Lab") {
		t.Fatalf("payload missing response excerpt: %s", payload)
	}
}

// Agent 主动探测过的端点要能出现在 observe.state 的子图里，否则「看过什么」只留在观测流。
func TestObserveStateShowsProbedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := s.tools["probe.http"].Handler(context.Background(), mustJSON(t, map[string]any{
		"url": srv.URL + "/login?x=1",
	})); err != nil {
		t.Fatalf("probe.http: %v", err)
	}

	out, err := s.tools["observe.state"].Handler(context.Background(), mustJSON(t, map[string]any{
		"subject":   strings.TrimPrefix(srv.URL, "http://"),
		"depth":     1,
		"direction": "down",
	}))
	if err != nil {
		t.Fatalf("observe.state: %v", err)
	}
	state, ok := out.(*agentapi.StateResult)
	if !ok || state == nil || state.Graph == nil {
		t.Fatalf("unexpected graph: %#v", out)
	}
	graph := state.Graph

	want := srv.URL + "/login"
	for _, n := range graph.Nodes {
		if n.ID == want {
			if n.Type != "endpoint" {
				t.Fatalf("端点类型 = %q, want endpoint", n.Type)
			}
			return
		}
	}
	t.Fatalf("子图中没有探测过的端点 %s: %+v", want, graph.Nodes)
}

// 观测流是只读查询，在只读策略下也必须可用，且不消耗请求预算。
func TestObserveObservationsAllowedInReadOnly(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	before := s.gate.Budget().Remaining()
	out, err := s.tools["observe.observations"].Handler(context.Background(), mustJSON(t, map[string]any{
		"since_seq": 0,
	}))
	if err != nil {
		t.Fatalf("observe.observations: %v", err)
	}
	if page, ok := out.(*sqlite.ObservationPage); !ok || page == nil {
		t.Fatalf("unexpected result: %#v", out)
	}
	if got := s.gate.Budget().Remaining(); got != before {
		t.Fatalf("zero-cost tool consumed budget: %d -> %d", before, got)
	}
}
