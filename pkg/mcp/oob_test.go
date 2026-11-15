package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

// fakeOOB 是 OOBSource 的脚本化替身：单测因此不必起真实反连平台，也能断言
// 工具到底把什么参数交给了后端。
type fakeOOB struct {
	payload    OOBPayload
	payloadErr error
	hit        OOBHit
	waitHit    bool

	waited         bool
	lastFilter     string
	lastFilterType string
	lastTimeout    time.Duration

	closed bool
}

func (f *fakeOOB) Payload() (OOBPayload, error) {
	if f.payloadErr != nil {
		return OOBPayload{}, f.payloadErr
	}
	return f.payload, nil
}

func (f *fakeOOB) Wait(filter, filterType string, timeout time.Duration) bool {
	f.waited = true
	f.lastFilter, f.lastFilterType, f.lastTimeout = filter, filterType, timeout
	return f.waitHit
}

func (f *fakeOOB) Hit(filter, filterType string) (OOBHit, bool) {
	if !f.waitHit {
		return OOBHit{}, false
	}
	return f.hit, true
}

func (f *fakeOOB) Close() { f.closed = true }

// newOOBTestServer 用 full 策略装配工具面，使 act.oob_* 的门控能过——本文件测的是
// OOB 行为本身，策略放行与否由 server_test.go 覆盖。
//
// HOME 指向临时目录：观测落的是 ~/.config/afrog/afrog.db，不隔离就会与其它用例
// （乃至开发机真实库）互相污染。
func newOOBTestServer(t *testing.T, oob OOBSource) *Server {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return New(Options{Policy: &policy.Policy{Mode: policy.ModeFull, Destructive: true}, OOB: oob})
}

func TestOOBToolsRegisteredAndDeniedByDefault(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	for _, name := range []string{"act.oob_payload", "act.oob_wait"} {
		if s.tools[name] == nil {
			t.Fatalf("%s must be registered", name)
		}
	}
	// 默认只读策略：铸地址属于发包动作，必须在任何后端调用前就被拒。
	_, err := s.Call(context.Background(), "act.oob_payload", nil)
	if err == nil || !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("readonly policy must deny act.oob_payload, got %v", err)
	}
}

// 未配置反连后端时 fail-closed：明确报缺配置，而不是静默等一个不会来的回连。
func TestOOBNotConfiguredFailsClosed(t *testing.T) {
	s := newOOBTestServer(t, nil)
	if _, err := s.Call(context.Background(), "act.oob_payload", nil); !errors.Is(err, errOOBUnavailable) {
		t.Fatalf("act.oob_payload err = %v, want errOOBUnavailable", err)
	}
	_, err := s.Call(context.Background(), "act.oob_wait", json.RawMessage(`{"filter":"f1"}`))
	if !errors.Is(err, errOOBUnavailable) {
		t.Fatalf("act.oob_wait err = %v, want errOOBUnavailable", err)
	}
}

func TestOOBPayloadReturnsAdapterPayload(t *testing.T) {
	f := &fakeOOB{payload: OOBPayload{Filter: "f1", DNS: "f1.dns.example", HTTP: "http://f1.http.example"}}
	s := newOOBTestServer(t, f)

	out, err := s.Call(context.Background(), "act.oob_payload", nil)
	if err != nil {
		t.Fatalf("act.oob_payload: %v", err)
	}
	got, ok := out.(OOBPayload)
	if !ok {
		t.Fatalf("result = %#v, want OOBPayload", out)
	}
	if got.Filter != "f1" || got.DNS != "f1.dns.example" {
		t.Fatalf("payload = %+v, want the adapter's payload verbatim", got)
	}
}

// 命中：返回 hit=true 与证据，并把这次回连写进观测流（oob_hit）。
func TestOOBWaitHitRecordsObservation(t *testing.T) {
	f := &fakeOOB{
		waitHit: true,
		hit:     OOBHit{Filter: "f1", FilterType: oobadapter.OOBDNS, Count: 2, Evidence: "A? f1.dns.example"},
	}
	s := newOOBTestServer(t, f)

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	const target = "http://victim.example/login?x=1"
	out, err := s.Call(context.Background(), "act.oob_wait", mustJSON(t, map[string]any{
		"filter":      "f1",
		"target":      target,
		"timeout_sec": 5,
	}))
	if err != nil {
		t.Fatalf("act.oob_wait: %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok || m["hit"] != true || m["count"] != uint64(2) {
		t.Fatalf("result = %#v, want hit=true count=2", out)
	}
	if f.lastFilterType != oobadapter.OOBDNS {
		t.Fatalf("filter_type = %q, want default dns", f.lastFilterType)
	}
	if f.lastTimeout != 5*time.Second {
		t.Fatalf("timeout = %v, want 5s", f.lastTimeout)
	}

	sqlite.FlushObservations()
	page := queryOOBObservations(t, s)
	if len(page.Items) != 1 {
		t.Fatalf("observations = %d (%+v), want exactly one oob_hit", len(page.Items), page.Items)
	}
	item := page.Items[0]
	if item.Kind != observation.KindOOBHit || item.Source != observation.SourceOOB {
		t.Fatalf("unexpected observation: %+v", item)
	}
	if item.Subject != observation.EndpointSubject(target) {
		t.Fatalf("subject = %q, want the normalized target", item.Subject)
	}
}

// 超时：hit=false，且不写观测——没回连就没有事实可记。
func TestOOBWaitTimeoutRecordsNothing(t *testing.T) {
	f := &fakeOOB{waitHit: false}
	s := newOOBTestServer(t, f)

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	out, err := s.Call(context.Background(), "act.oob_wait", json.RawMessage(`{"filter":"f1"}`))
	if err != nil {
		t.Fatalf("act.oob_wait: %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok || m["hit"] != false {
		t.Fatalf("result = %#v, want hit=false", out)
	}
	sqlite.FlushObservations()
	if page := queryOOBObservations(t, s); len(page.Items) != 0 {
		t.Fatalf("timeout wrote %d observation(s), want 0", len(page.Items))
	}
}

// 非法 filter_type 在调用后端前就被拒。
func TestOOBWaitRejectsUnknownFilterType(t *testing.T) {
	f := &fakeOOB{waitHit: true}
	s := newOOBTestServer(t, f)

	if _, err := s.Call(context.Background(), "act.oob_wait", json.RawMessage(`{"filter":"f1","filter_type":"ftp"}`)); err == nil {
		t.Fatal("filter_type=ftp must be rejected")
	}
	if f.waited {
		t.Fatal("backend must not be called for an invalid filter_type")
	}
}

// filter 必填：缺失/空白都不该去等一个无意义的回连。
func TestOOBWaitRequiresFilter(t *testing.T) {
	s := newOOBTestServer(t, &fakeOOB{})
	for _, args := range []string{`{}`, `{"filter":"   "}`} {
		if _, err := s.Call(context.Background(), "act.oob_wait", json.RawMessage(args)); err == nil {
			t.Fatalf("args %s: expected an error", args)
		}
	}
}

// 等待上限：缺省 30 秒，越界钳到 5 分钟——不能让调用方把工具挂死。
func TestOOBWaitClampsTimeout(t *testing.T) {
	cases := []struct {
		args string
		want time.Duration
	}{
		{`{"filter":"f1"}`, defaultOOBWaitSec * time.Second},
		{`{"filter":"f1","timeout_sec":0}`, defaultOOBWaitSec * time.Second},
		{`{"filter":"f1","timeout_sec":100000}`, maxOOBWaitSec * time.Second},
	}
	for _, tc := range cases {
		f := &fakeOOB{waitHit: false}
		s := newOOBTestServer(t, f)
		if _, err := s.Call(context.Background(), "act.oob_wait", json.RawMessage(tc.args)); err != nil {
			t.Fatalf("args %s: %v", tc.args, err)
		}
		if f.lastTimeout != tc.want {
			t.Fatalf("args %s: timeout = %v, want %v", tc.args, f.lastTimeout, tc.want)
		}
	}
}

func queryOOBObservations(t *testing.T, s *Server) *sqlite.ObservationPage {
	t.Helper()
	out, err := s.Call(context.Background(), "observe.observations", mustJSON(t, map[string]any{
		"kinds": []string{observation.KindOOBHit},
	}))
	if err != nil {
		t.Fatalf("observe.observations: %v", err)
	}
	page, ok := out.(*sqlite.ObservationPage)
	if !ok || page == nil {
		t.Fatalf("result = %#v, want an ObservationPage", out)
	}
	return page
}
