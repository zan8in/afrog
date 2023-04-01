package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/remeh/sizedwaitgroup"
)

var (
	targetsTemp = "afrog-target-temp-*"
)

func (r *Runner) PreprocessTargets() error {
	temp, err := os.CreateTemp("", targetsTemp)
	if err != nil {
		return err
	}
	defer temp.Close()

	if len(r.options.Target) > 0 {
		for _, t := range r.options.Target {
			if _, err := fmt.Fprintf(temp, "%s\n", t); err != nil {
				continue
			}
		}
	}

	if len(r.options.TargetsFilePath) > 0 {
		f, err := os.Open(r.options.TargetsFilePath)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(temp, f); err != nil {
			return err
		}
	}

	r.targetsTemp = temp.Name()

	f, err := os.Open(r.targetsTemp)
	if err != nil {
		return err
	}
	defer f.Close()

	defer close(r.ChanTargets)

	wg := sizedwaitgroup.New(r.options.RateLimit)
	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			atomic.AddUint32(&r.options.TargetsTotal, 1)
			r.ChanTargets <- target
		}(s.Text())
	}
	wg.Wait()

	return err
}
