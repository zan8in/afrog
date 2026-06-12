package runner

import (
	"context"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestInitOOB_NoReversePocs(t *testing.T) {
	r := &Runner{
		options: &config.Options{},
		engine:  NewEngine(&config.Options{}),
		ctx:     context.Background(),
	}
	r.initOOB(nil)
	if r.engine.oobAlive {
		t.Error("oobAlive should be false when no reverse PoCs")
	}
	if r.engine.oobAdapter != nil {
		t.Error("oobAdapter should be nil when no reverse PoCs")
	}
}

func TestInitOOB_EmptyReversePocs(t *testing.T) {
	r := &Runner{
		options: &config.Options{},
		engine:  NewEngine(&config.Options{}),
		ctx:     context.Background(),
	}
	r.initOOB([]poc.Poc{})
	if r.engine.oobAlive {
		t.Error("oobAlive should be false for empty reverse PoCs")
	}
}

func TestInitOOB_SDKModeNoOOB(t *testing.T) {
	r := &Runner{
		options: &config.Options{SDKMode: true, EnableOOB: false},
		engine:  NewEngine(&config.Options{}),
		ctx:     context.Background(),
	}
	r.initOOB([]poc.Poc{{Id: "test"}})
	if r.engine.oobAlive {
		t.Error("oobAlive should be false in SDK mode without explicit OOB enable")
	}
}

func TestInitOOB_NilEngine(t *testing.T) {
	r := &Runner{
		options: &config.Options{},
		ctx:     context.Background(),
	}
	// Should not panic
	r.initOOB([]poc.Poc{{Id: "test"}})
}

func TestGetOOBStatus_NoReversePocs(t *testing.T) {
	r := &Runner{
		options: &config.Options{},
		engine:  NewEngine(&config.Options{}),
	}
	ok, msg := r.getOOBStatus(nil)
	if !ok {
		t.Errorf("should return ok=true for nil reversePocs, got ok=%v msg=%s", ok, msg)
	}
}
