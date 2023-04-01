package runner

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
)

var (
	targetsTemp = "afrog-target-temp-*"

	HTTP_PREFIX  = "http://"
	HTTPS_PREFIX = "https://"
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
	defer close(r.ChanBadTargets)

	wg := sizedwaitgroup.New(r.options.RateLimit)
	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			if t, err := r.checkTarget(target); err == nil {
				atomic.AddUint32(&r.options.TargetsTotal, 1)
				r.ChanTargets <- t
			} else {
				atomic.AddUint32(&r.options.BadTargetsTotal, 1)
				r.ChanBadTargets <- target
			}
		}(s.Text())
	}
	wg.Wait()

	return err
}

func (r *Runner) checkTarget(host string) (string, error) {
	var (
		err       error
		result    string
		parsePort string
	)

	if len(strings.TrimSpace(host)) == 0 {
		return result, fmt.Errorf("host %q is empty", host)
	}

	if strings.HasPrefix(host, HTTPS_PREFIX) {
		_, err := retryhttpclient.CheckTarget(host)
		if err != nil {
			return result, err
		}

		return host, nil
	}

	if strings.HasPrefix(host, HTTP_PREFIX) {
		_, err := retryhttpclient.CheckTarget(host)
		if err != nil {
			return result, err
		}

		return host, nil
	}

	u, err := url.Parse(HTTP_PREFIX + host)
	if err != nil {
		return result, err
	}
	parsePort = u.Port()

	switch {
	case parsePort == "80":
		_, err := retryhttpclient.CheckTarget(HTTP_PREFIX + host)
		if err != nil {
			return result, err
		}

		return HTTP_PREFIX + host, nil

	case parsePort == "443":
		_, err := retryhttpclient.CheckTarget(HTTPS_PREFIX + host)
		if err != nil {
			return result, err
		}

		return HTTPS_PREFIX + host, nil

	default:
		_, err := retryhttpclient.CheckTarget(HTTPS_PREFIX + host)
		if err == nil {
			return HTTPS_PREFIX + host, err
		}

		body, err := retryhttpclient.CheckTarget(HTTP_PREFIX + host)
		if err == nil {
			if strings.Contains(body, "<title>400 The plain HTTP request was sent to HTTPS port</title>") {
				return HTTPS_PREFIX + host, nil
			}
			return HTTP_PREFIX + host, nil
		}

	}

	return "", nil
}
