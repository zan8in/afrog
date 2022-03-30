package core

import (
	"net/http"
	"sync"

	"github.com/zan8in/afrog/pkg/config"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

var CheckerPool = sync.Pool{
	New: func() interface{} {
		return &Checker{
			Options:         &config.Options{},
			OriginalRequest: &http.Request{},
			VariableMap:     make(map[string]interface{}),
			Result:          &Result{},
			CustomLib:       NewCustomLib(),
			FastClient:      &http2.FastClient{},
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
	c.VariableMap = make(map[string]interface{})
	c.Result = &Result{}
	c.CustomLib = NewCustomLib()
	c.FastClient = &http2.FastClient{}
	CheckerPool.Put(c)
}

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
