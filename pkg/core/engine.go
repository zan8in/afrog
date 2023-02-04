package core

import (
	"net/http"
	"sync"

	"github.com/zan8in/afrog/pkg/config"
)

var CheckerPool = sync.Pool{
	New: func() any {
		return &Checker{
			Options:         &config.Options{},
			OriginalRequest: &http.Request{},
			VariableMap:     make(map[string]any),
			Result:          &Result{},
			CustomLib:       NewCustomLib(),
		}
	},
}

func (e *Engine) AcquireChecker() *Checker {
	c := CheckerPool.Get().(*Checker)
	c.Options = e.options
	c.Result.Output = e.options.Output
	return c
}

func (e *Engine) ReleaseChecker(c *Checker) {
	*c.OriginalRequest = http.Request{}
	c.VariableMap = make(map[string]any)
	c.Result = &Result{}
	c.CustomLib = NewCustomLib()
	CheckerPool.Put(c)
}

type Engine struct {
	workPool *WorkPool
	options  *config.Options
}

func New(options *config.Options) *Engine {
	workPool := NewWorkPool(WorkPoolConfig{
		PocConcurrency:        int(options.Concurrency),
		TargetConcurrency:     int(options.Concurrency),
		PocConcurrencyType:    PocConcurrencyType,
		TargetConcurrencyType: TargetConcurrencyType,
	})
	engine := &Engine{
		options:  options,
		workPool: workPool,
	}
	return engine
}
