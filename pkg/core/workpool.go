package core

import (
	"github.com/remeh/sizedwaitgroup"
)

const PocConcurrencyType string = "PocConcurrencyType"
const TargetConcurrencyType string = "TargetConcurrencyType"

type WorkPool struct {
	PocSwg     *sizedwaitgroup.SizedWaitGroup
	TargetsSwg *sizedwaitgroup.SizedWaitGroup
	config     WorkPoolConfig
}

type WorkPoolConfig struct {
	PocConcurrency        int
	TargetConcurrency     int
	PocConcurrencyType    string
	TargetConcurrencyType string
}

func NewWorkPool(config WorkPoolConfig) *WorkPool {
	pocSwg := sizedwaitgroup.New(config.PocConcurrency)
	targetsSwg := sizedwaitgroup.New(config.PocConcurrency)

	return &WorkPool{
		config:     config,
		PocSwg:     &pocSwg,
		TargetsSwg: &targetsSwg,
	}
}

func (w *WorkPool) Wait() {
	w.PocSwg.Wait()
}

func (w *WorkPool) TargetWait() {
	w.TargetsSwg.Wait()
}

type WaitPool struct {
	WaitGroup *sizedwaitgroup.SizedWaitGroup
}

func (w *WorkPool) NewPool(concurrencyType string) *WaitPool {
	var count int
	if concurrencyType == PocConcurrencyType {
		count = w.config.PocConcurrency
	} else {
		count = w.config.TargetConcurrency
	}
	swg := sizedwaitgroup.New(count)
	return &WaitPool{WaitGroup: &swg}
}
