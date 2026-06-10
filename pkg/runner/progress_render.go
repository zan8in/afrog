package runner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/progress"
)

// ProgressRenderer manages CLI progress bar rendering.
// It is decoupled from the runner package to keep CLI display logic separate.
type ProgressRenderer struct {
	mu              sync.Mutex
	oobFinalize     atomic.Value
	progressEnabled bool
	startTime       time.Time
	progressDone    chan struct{}
	runner          *Runner
}

type oobFinalizeProgress struct {
	Active   bool
	Status   string
	Finished int64
	Total    int64
	Percent  int
}

// NewProgressRenderer creates a progress renderer attached to a runner.
func NewProgressRenderer(r *Runner, startTime time.Time, progressEnabled bool) *ProgressRenderer {
	pr := &ProgressRenderer{
		runner:          r,
		startTime:       startTime,
		progressEnabled: progressEnabled,
	}
	pr.oobFinalize.Store(oobFinalizeProgress{})
	return pr
}

// Line builds the current progress status bar string.
func (pr *ProgressRenderer) Line() string {
	if pr.runner == nil || pr.runner.options == nil {
		return ""
	}
	total := pr.runner.options.Count
	if total <= 0 {
		return ""
	}
	current := atomic.LoadUint32(&pr.runner.options.CurrentCount)
	pgress := 0
	if total > 0 {
		pgress = int(current) * 100 / total
	}
	elapsed := strings.Split(time.Since(pr.startTime).String(), ".")[0] + "s"

	suffix := ""
	if pr.runner.options.LiveStats {
		suffix = pr.runner.LiveStatsSuffix()
	} else {
		if pedm := pr.runner.PedmStatusSuffix(); pedm != "" {
			suffix += pedm
		}
		if v, ok := pr.oobFinalize.Load().(oobFinalizeProgress); ok && strings.TrimSpace(v.Status) != "" {
			remain := v.Total - v.Finished
			if remain < 0 {
				remain = 0
			}
			if v.Total < 0 {
				v.Total = 0
			}
			suffix = fmt.Sprintf(" oobf=%d/%d %s", remain, v.Total, v.Status)
		}
	}
	return fmt.Sprintf("[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(pgress, 0), pgress, current, total, elapsed, suffix)
}

// Render clears the current line and redraws the progress bar.
func (pr *ProgressRenderer) Render() {
	line := pr.Line()
	if line == "" {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[2K")
	fmt.Fprintf(os.Stderr, "\r%s", line)
}

// PrintAwareLog clears the progress bar, prints a log line, and restores the bar.
func (pr *ProgressRenderer) PrintAwareLog(line string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if pr.progressEnabled && pr.Line() != "" {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
	fmt.Fprintln(os.Stderr, line)
	if pr.progressEnabled && !pr.runner.options.LiveStats {
		pr.Render()
	}
}

// StartTicker launches a background goroutine that redraws the progress bar every second.
func (pr *ProgressRenderer) StartTicker() chan struct{} {
	if !pr.progressEnabled {
		return nil
	}
	pr.progressDone = make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pr.progressDone:
				return
			case <-ticker.C:
				pr.mu.Lock()
				pr.Render()
				pr.mu.Unlock()
			}
		}
	}()
	return pr.progressDone
}

// StopTicker stops the background progress ticker.
func (pr *ProgressRenderer) StopTicker() {
	if pr.progressDone != nil {
		close(pr.progressDone)
		pr.progressDone = nil
	}
}

// clearLine writes the ANSI escape to clear the current terminal line.
func (pr *ProgressRenderer) clearLine() {
	fmt.Fprint(os.Stderr, "\r\033[2K\r")
}

// ClearLineForResult clears the line before printing a scan result.
func (pr *ProgressRenderer) ClearLineForResult() {
	pr.clearLine()
}

// WrapOnPhaseProgress returns a callback that intercepts OOB finalize updates
// for progress display, chaining to the previous handler.
func (pr *ProgressRenderer) WrapOnPhaseProgress(prev func(string, string, int64, int64, int)) func(string, string, int64, int64, int) {
	return func(phase string, status string, finished int64, total int64, percent int) {
		if prev != nil {
			prev(phase, status, finished, total, percent)
		}
		phase = strings.ToLower(strings.TrimSpace(phase))
		if phase != "oob_finalize" {
			return
		}
		status = strings.ToLower(strings.TrimSpace(status))
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		next := oobFinalizeProgress{
			Active:   status == "running",
			Status:   status,
			Finished: finished,
			Total:    total,
			Percent:  percent,
		}
		cur, _ := pr.oobFinalize.Load().(oobFinalizeProgress)
		if cur.Status == next.Status && cur.Finished == next.Finished &&
			cur.Total == next.Total && cur.Percent == next.Percent && cur.Active == next.Active {
			return
		}
		pr.oobFinalize.Store(next)
		pr.mu.Lock()
		pr.Render()
		pr.mu.Unlock()
	}
}
