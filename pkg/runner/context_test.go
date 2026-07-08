package runner

import (
	"testing"
)

func TestRunnerGetScanCtx_LazyInit(t *testing.T) {
	r := &Runner{}
	sc := r.getScanCtx()
	if sc == nil {
		t.Fatal("getScanCtx() returned nil")
	}
	// Second call should return the same instance
	sc2 := r.getScanCtx()
	if sc != sc2 {
		t.Error("getScanCtx() returned different instances")
	}
}

func TestEngineGetScanCtx_LazyInit(t *testing.T) {
	e := &Engine{}
	sc := e.getScanCtx()
	if sc == nil {
		t.Fatal("getScanCtx() returned nil")
	}
	// Second call should return the same instance
	sc2 := e.getScanCtx()
	if sc != sc2 {
		t.Error("getScanCtx() returned different instances")
	}
}

func TestScanContext_ZeroValueCallbacks(t *testing.T) {
	sc := &ScanContext{}
	if sc.OnPhaseProgress != nil {
		t.Error("OnPhaseProgress should be nil in zero value")
	}
	if sc.OnPortScanResult != nil {
		t.Error("OnPortScanResult should be nil in zero value")
	}
	if sc.OnHostDiscovered != nil {
		t.Error("OnHostDiscovered should be nil in zero value")
	}
	if sc.OnPedmLog != nil {
		t.Error("OnPedmLog should be nil in zero value")
	}
}
