package scan

import (
	"errors"
	"fmt"
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
	port := options.Port

	if targets.Len() == 0 {
		return nil, errors.New("targets is empty")
	}

	if len(port) == 0 {
		port = NmapTop1000
	}

	// url to ip
	for _, v := range targets.List() {
		ip, err := Target2ip(strings.TrimSpace(v.(string)))
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

	// port
	portSlice, err := ParsePorts(port)
	if err != nil {
		return nil, errors.New("parse port error, no found port")
	}

	for _, v := range ipSlice {
		fmt.Println(v)
	}
	fmt.Println("port len", len(portSlice))

	return &Scan{
		Options:   options,
		IpSlice:   ipSlice,
		PortSlice: portSlice,
	}, nil
}
