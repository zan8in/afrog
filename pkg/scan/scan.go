package scan

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/config"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
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

	if len(targets) == 0 {
		return nil, errors.New("targets is empty")
	}

	if len(port) == 0 {
		port = NmapTop1000
	}

	// url to ip
	for _, v := range targets {
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

	// port
	portSlice, err := ParsePorts(port)
	if err != nil {
		return nil, errors.New("parse port error, no found port")
	}

	// for _, v := range ipSlice {
	// 	fmt.Println(v)
	// }

	return &Scan{
		Options:   options,
		IpSlice:   ipSlice,
		PortSlice: portSlice,
	}, nil
}

func (s *Scan) Execute() {
	s.scan()
}

func (s *Scan) scan() {
	size := 100
	swg := sizedwaitgroup.New(size)
	for _, port := range s.PortSlice {
		swg.Add()
		go func(port int) {
			defer swg.Done()
			s.portscan(port)
			// fmt.Println("the number of goroutines: ", runtime.NumGoroutine())

		}(port)
	}
	swg.Wait()
}

func (s *Scan) portscan(port int) {
	size := 10
	swg := sizedwaitgroup.New(size)
	for _, ip := range s.IpSlice {
		swg.Add()
		go func(ip string) {
			defer swg.Done()
			err := s.ipscan(ip, port, false)
			if err != nil {
				s.ipscan(ip, port, true)
			}
		}(ip)
	}
	swg.Wait()
}

func (s *Scan) ipscan(ip string, port int, https bool) error {
	url := getHttpSURL(ip, port, https)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	_, status, err := http2.GetTitleRedirect(req, 3)
	if err != nil {
		return err
	}

	if status < 200 || (status >= 300 && status < 400) || status >= 600 {
		return err
	}

	exists := false
	for _, v := range s.Options.Targets {
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			v = "http://" + v
		}
		v = strings.TrimRight(v, "/")
		if v == url {
			exists = true
			break
		}
	}
	if !exists {
		s.Options.Targets = append(s.Options.Targets, url)
	}

	// titleArr := pTitle.FindStringSubmatch(string(resp))
	// if titleArr != nil {
	// 	if len(titleArr) == 2 {
	// 		sTitle := titleArr[1]
	// 		if !utf8.ValidString(sTitle) {
	// 			sTitle = mahonia.NewDecoder("gb18030").ConvertString(sTitle)
	// 		}
	// 		fmt.Println(url, status, sTitle)
	// 	}
	// } else {
	// 	fmt.Println(url, status)
	// }

	return nil
}

func getHttpSURL(ip string, port int, tls bool) string {
	url := ""
	if port == 443 {
		url = "https://" + ip + ":" + strconv.Itoa(port)
	} else if port == 80 || port == 0 {
		url = "http://" + ip + ":" + strconv.Itoa(port)
	} else {
		if !tls {
			url = "http://" + ip + ":" + strconv.Itoa(port)
		} else {
			url = "https://" + ip + ":" + strconv.Itoa(port)
		}
	}
	return url
}
