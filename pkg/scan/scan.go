package scan

import (
	"errors"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/pkg/config"
)

var pTitle = regexp.MustCompile(`(?i:)<title>(.*?)</title>`)

type Scan struct {
	Options   *config.Options
	IpSlice   []string
	PortSlice []int
}

func New(options *config.Options) (*Scan, error) {
	ipSlice := []string{}
	targets := options.Targets

	if targets.Len() == 0 {
		return nil, errors.New("targets is empty")
	}

	// url to ip
	for _, v := range targets.List() {
		ip, err := Target2ip(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		exits := false
		if len(ipSlice) > 0 {
			for _, vv := range ipSlice {
				if vv == ip {
					exits = true
					break
				}
			}
		}
		if !exits {
			ipSlice = append(ipSlice, ip)
		}
	}

	if len(ipSlice) == 0 {
		return nil, errors.New("target to ip error, no found ip")
	}

	return &Scan{
		Options: options,
		IpSlice: ipSlice,
	}, nil
}
