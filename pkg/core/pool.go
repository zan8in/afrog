package core

import (
	"sync"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/gologger"
)

var MAX_QUEUE_SIZE = 25
var MAX_PQUEUE_SIZE = 250

type TargetPoc struct {
	target string
	poc    poc.Poc
}

type Pool struct {
	targets []string
	pocs    []poc.Poc
	// poc queue
	queue chan poc.Poc
	// target queue
	tqueue chan TargetPoc
	stop   bool
}

func NewPool(targets []string, pocs []poc.Poc) *Pool {
	return &Pool{targets: targets, pocs: pocs, queue: make(chan poc.Poc, MAX_QUEUE_SIZE), tqueue: make(chan TargetPoc, MAX_PQUEUE_SIZE)}
}

func (pool *Pool) Producer() {
	if len(pool.pocs) == 0 {
		return
	}

	for _, p := range pool.pocs {
		pool.queue <- p
		// gologger.Print().Msgf("produce a poc: %s", p.Id)
	}
}

func (pool *Pool) PocConsumer(wg *sync.WaitGroup) {

	defer wg.Done()
	for {
		if len(pool.queue) == 0 && pool.stop {
			gologger.Warning().Msg("PocConsumer stop")
			break
		}

		poc := <-pool.queue
		if len(poc.Id) == 0 && pool.stop {
			gologger.Debug().Msg("PocConsumer stop")
			break
		}

		for _, t := range pool.targets {
			pool.tqueue <- TargetPoc{target: t, poc: poc}
			// gologger.Warning().Msgf("PocConsumer target %s a poc %s", t, poc.Id)
		}
	}
}

func (pool *Pool) TargetConsumer(wg *sync.WaitGroup, e *Engine) {
	defer wg.Done()
	for {
		if len(pool.tqueue) == 0 && pool.stop {
			gologger.Warning().Msg("TargetConsumer stop")
			break
		}

		// targetPoc := <-pool.tqueue
		// ExecuteExp(targetPoc.target, targetPoc.poc, e)

		// utils.RandSleep(200)

		// gologger.Error().Msgf("TargetConsumer target %s a poc %s", targetPoc.target, targetPoc.poc.Id)
	}
}

func (pool *Pool) Stop() {
	pool.stop = true
}

func (pool *Pool) ReleaseAll() {
	close(pool.tqueue)
	close(pool.queue)
}
