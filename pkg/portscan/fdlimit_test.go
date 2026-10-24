package portscan

import (
	"sync/atomic"
	"testing"

	"github.com/panjf2000/ants/v2"
)

func TestShrinkPoolHalvesAndFloors(t *testing.T) {
	pool, err := ants.NewPoolWithFunc(100, func(interface{}) {})
	if err != nil {
		t.Fatalf("NewPoolWithFunc: %v", err)
	}
	defer pool.Release()

	s := &Scanner{options: &Options{Quiet: true}, pool: pool}

	s.shrinkPool()
	if got := pool.Cap(); got != 50 {
		t.Fatalf("after first shrink Cap = %d, want 50", got)
	}
	s.shrinkPool()
	if got := pool.Cap(); got != 25 {
		t.Fatalf("after second shrink Cap = %d, want 25", got)
	}
}

func TestShrinkPoolStopsAtFloor(t *testing.T) {
	pool, err := ants.NewPoolWithFunc(30, func(interface{}) {})
	if err != nil {
		t.Fatalf("NewPoolWithFunc: %v", err)
	}
	defer pool.Release()

	s := &Scanner{options: &Options{Quiet: true}, pool: pool}
	for i := 0; i < 5; i++ {
		s.shrinkPool()
	}
	if got := pool.Cap(); got != poolShrinkFloor {
		t.Fatalf("Cap = %d, want floor %d", got, poolShrinkFloor)
	}
}

// TestShrinkPoolNilPool 覆盖未初始化 pool 的路径：Scanner 也可能被直接构造，
// shrinkPool 必须能安全空转。
func TestShrinkPoolNilPool(t *testing.T) {
	s := &Scanner{options: &Options{Quiet: true}}
	s.shrinkPool()
}

// TestHandleFDExhaustedCountsAndWarnsOnce 验证 fd 失败只记一次告警：
// 计数持续累加，但 fdWarned 只置位一次，避免刷屏。
func TestHandleFDExhaustedCountsAndWarnsOnce(t *testing.T) {
	s := &Scanner{options: &Options{Quiet: true}}

	s.handleFDExhausted()
	if got := atomic.LoadUint64(&s.fdErrors); got != 1 {
		t.Fatalf("fdErrors = %d, want 1", got)
	}
	if got := atomic.LoadUint32(&s.fdWarned); got != 1 {
		t.Fatalf("fdWarned = %d, want 1", got)
	}

	s.handleFDExhausted()
	if got := atomic.LoadUint64(&s.fdErrors); got != 2 {
		t.Fatalf("fdErrors = %d, want 2", got)
	}
}
