package sdk

import (
	"context"
	"sync"
)

// stream is a lazily created, single-close broadcast channel.
//
// Two properties matter here:
//
//   - Nothing is allocated and nothing is sent until a caller subscribes, so an
//     unsubscribed stream can never block the scan or leak a goroutine.
//   - send holds a read lock and close holds the write lock, so close waits for
//     in-flight sends instead of racing them into a send-on-closed panic.
//
// Sends are blocking by design. Silently discarding a vulnerability is not an
// acceptable failure mode for a scanner, so a subscriber that stops consuming
// applies backpressure to the scan rather than losing findings. The ctx guard
// keeps that from becoming a permanent stall: cancelling the scanner releases
// any blocked send.
type stream[T any] struct {
	buf int

	mu     sync.RWMutex
	ch     chan T
	closed bool
}

func newStream[T any](buf int) *stream[T] {
	if buf <= 0 {
		buf = DefaultStreamBuffer
	}
	return &stream[T]{buf: buf}
}

// subscribe returns the receive side of the stream, creating it on first use.
// Subscribing after the stream closed yields an already-closed channel so that
// a range loop terminates immediately instead of blocking forever.
func (s *stream[T]) subscribe() <-chan T {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch == nil {
		s.ch = make(chan T, s.buf)
		if s.closed {
			close(s.ch)
		}
	}
	return s.ch
}

// send delivers a value to the subscriber, if any.
func (s *stream[T]) send(ctx context.Context, v T) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ch == nil || s.closed {
		return
	}
	select {
	case s.ch <- v:
	case <-ctx.Done():
	}
}

// close closes the stream. It is safe to call more than once.
func (s *stream[T]) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.ch != nil {
		close(s.ch)
	}
}

// emitter fans one event out to the registered handlers and the subscription
// stream. Handlers run before the stream send: a handler is the reliable
// delivery path and must not be delayed by a slow (or absent) stream consumer.
type emitter[T any] struct {
	stream   *stream[T]
	handlers []func(T)
}

func newEmitter[T any](buf int, handlers []func(T)) *emitter[T] {
	return &emitter[T]{stream: newStream[T](buf), handlers: handlers}
}

func (e *emitter[T]) emit(ctx context.Context, v T) {
	for _, fn := range e.handlers {
		fn(v)
	}
	e.stream.send(ctx, v)
}

func (e *emitter[T]) subscribe() <-chan T { return e.stream.subscribe() }

func (e *emitter[T]) close() { e.stream.close() }
