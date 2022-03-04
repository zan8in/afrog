package core

import (
	"github.com/zan8in/afrog/pkg/config"
)

type Engine struct {
	workPool *WorkPool
	options  *config.Options
}

func New(options *config.Options) *Engine {
	workPool := NewWorkPool(WorkPoolConfig{
		PocConcurrency:        int(options.Config.PocSizeWaitGroup),
		TargetConcurrency:     int(options.Config.TargetSizeWaitGroup),
		PocConcurrencyType:    PocConcurrencyType,
		TargetConcurrencyType: TargetConcurrencyType,
	})
	engine := &Engine{
		options:  options,
		workPool: workPool,
	}
	return engine
}
