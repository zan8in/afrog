package web

import (
	"sync"
	"testing"
	"time"
)

// Cancelling a scan reaches finalizeTask from two directions at once: the stop
// handler calls it directly, and the drain goroutine calls it when the scanner
// closes its streams. Releasing the manager slot twice would let the queue
// admit more concurrent scans than maxRunning allows.
func TestFinalizeTask_ReleasesTheSlotExactlyOnce(t *testing.T) {
	m := newTaskManager()
	m.running = 3

	task := &Task{ID: "t1", status: TaskRunning}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			finalizeTask(m, task, TaskCancelled)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	running := m.running
	m.mu.Unlock()

	if running != 2 {
		t.Fatalf("running = %d after 16 concurrent finalize calls, want 2", running)
	}
	if got := task.Status(); got != TaskCancelled {
		t.Fatalf("Status() = %q, want %q", got, TaskCancelled)
	}
}

// A second finalize for the same task must not pull another task off the
// queue: that would start it while the first promotion is still running.
func TestFinalizeTask_DuplicateCallDoesNotDrainTheQueue(t *testing.T) {
	m := newTaskManager()
	m.running = 2

	queued := &Task{ID: "queued", status: TaskStarting}
	m.tasks[queued.ID] = queued
	m.queue = []string{queued.ID}

	done := &Task{ID: "done", status: TaskRunning}
	done.finalized.Store(true) // stands in for an earlier finalize
	finalizeTask(m, done, TaskCompleted)

	m.mu.Lock()
	queueLen := len(m.queue)
	m.mu.Unlock()
	if queueLen != 1 {
		t.Fatalf("queue length = %d after a duplicate finalize, want 1", queueLen)
	}
}

// The task fields are read and written from HTTP handlers and the drain
// goroutine at the same time. This test is meaningful under -race.
func TestTask_ConcurrentFieldAccessIsRaceFree(t *testing.T) {
	task := &Task{ID: "t1", status: TaskStarting}
	sub := addSubscriber(task)
	go func() {
		for range sub {
		}
	}()

	statuses := []TaskStatus{TaskRunning, TaskPaused, TaskCancelled, TaskCompleted}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(4)
		go func() { defer wg.Done(); task.setStatus(statuses[i%len(statuses)]) }()
		go func() { defer wg.Done(); _ = isActive(task.Status()) }()
		go func() { defer wg.Done(); task.setStarted(time.Now()); _ = task.started() }()
		go func() {
			defer wg.Done()
			publish(task, ScanEvent{Type: "status", Data: map[string]string{"status": "running"}})
		}()
	}

	waited := make(chan struct{})
	go func() { defer close(waited); wg.Wait() }()

	select {
	case <-waited:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent task field access deadlocked")
	}
	removeSubscriber(task, sub)
}
