package runner

import (
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zan8in/gologger"
)

// GracefulShutdown handles OS signals and periodic auto-save during a scan.
type GracefulShutdown struct {
	runner       *Runner
	autoSaveFile string
	once         sync.Once
}

// NewGracefulShutdown creates a shutdown handler for a running scan.
func NewGracefulShutdown(r *Runner, autoSaveFile string) *GracefulShutdown {
	return &GracefulShutdown{runner: r, autoSaveFile: autoSaveFile}
}

// HandleSignals starts a goroutine that listens for SIGINT/SIGTERM/SIGQUIT.
// It returns an *atomic.Bool that is set to true when interrupted.
// The first signal triggers a graceful Stop; subsequent signals force os.Exit(1).
func (gs *GracefulShutdown) HandleSignals(currentCount *uint32, totalCount int) *atomic.Bool {
	interrupted := &atomic.Bool{}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		defer close(c)
		for range c {
			handled := false
			gs.once.Do(func() { handled = true })
			if !handled {
				os.Exit(1)
			}

			gologger.Print().Msg("")
			gologger.Info().Msg("Scan termination signal received")
			interrupted.Store(true)
			gs.runner.Stop()

			if gs.autoSaveFile != "" {
				if err := gs.runner.ScanProgress.AtomicSave(
					gs.autoSaveFile,
					atomic.LoadUint32(currentCount),
					uint32(totalCount),
				); err != nil {
					gologger.Error().Msgf("Could not preserve scan state: %s", err)
				} else {
					gologger.Info().Msgf("Scan state archived: %s", gs.autoSaveFile)
				}
			}
		}
	}()

	return interrupted
}

// StartAutoSave launches a background goroutine that saves scan progress
// every 10 seconds. It exits when the runner completes.
func (gs *GracefulShutdown) StartAutoSave(currentCount *uint32, totalCount int) {
	if gs.autoSaveFile == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-gs.runner.Done():
				return
			case <-ticker.C:
				if err := gs.runner.ScanProgress.AtomicSave(
					gs.autoSaveFile,
					atomic.LoadUint32(currentCount),
					uint32(totalCount),
				); err != nil {
					gologger.Debug().Msgf("auto save file failed: %s", err)
				}
			}
		}
	}()
}
