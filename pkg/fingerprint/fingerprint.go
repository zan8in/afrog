package fingerprint

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	_ "embed"

	"github.com/axgle/mahonia"
	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

type Service struct {
	Options     *config.Options
	fpSlice     []FingerPrint
	ResultSlice []Result
}

type Result struct {
	Url        string // 网址
	StatusCode string // 状态码
	Title      string // 标题
	Name       string // 指纹
}

type FingerPrint struct {
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestData    string            `json:"request_data"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Keyword        []string          `json:"keyword"`
	FaviconHash    []string          `json:"favicon_hash"`
	Priority       int               `json:"priority"`
}

var pTitle = regexp.MustCompile(`(?i:)<title>(.*?)</title>`)

//go:embed web_fingerprint_v3.json
var content []byte

func New(options *config.Options) (*Service, error) {
	var fpSlice []FingerPrint
	if err := json.Unmarshal(content, &fpSlice); err != nil {
		return nil, err
	}

	options.Count += len(options.Targets)

	return &Service{
		fpSlice: fpSlice,
		Options: options,
	}, nil
}

func (s *Service) Execute() {
	s.executeFingerPrintDetection()
}

func (s *Service) executeFingerPrintDetection() {
	if len(s.Options.Targets) > 0 {
		size := 100
		if s.Options.Config.FingerprintSizeWaitGroup > 0 {
			size = int(s.Options.Config.FingerprintSizeWaitGroup)
		}

		swg := sizedwaitgroup.New(size)
		for _, url := range s.Options.Targets {
			swg.Add()
			go func(url string) {
				defer swg.Done()
				s.processFingerPrintInputPair(url)
				// fmt.Println("the number of goroutines: ", runtime.NumGoroutine())

			}(url)
		}
		swg.Wait()
	}
}

func (s *Service) processFingerPrintInputPair(url string) error {
	if len(s.fpSlice) == 0 {
		s.PrintColorResultInfoConsole(Result{})
		return nil
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		s.PrintColorResultInfoConsole(Result{})
		return nil
	}

	data, headers, statuscode, err := http2.GetFingerprintRedirect(req)
	if err != nil {
		s.PrintColorResultInfoConsole(Result{})
		return nil
	}

	fpName := ""
	for _, v := range s.fpSlice {
		flag := false

		hflag := true
		if len(v.Headers) > 0 {
			hflag = false
			for k, h := range v.Headers {
				if len(headers[strings.ToLower(k)]) == 0 {
					hflag = false
					break
				}
				if len(headers[strings.ToLower(k)]) > 0 {
					if !strings.Contains(headers[strings.ToLower(k)][0], h) {
						hflag = false
						break
					}
					hflag = true
				}
			}
		}
		if len(v.Headers) > 0 && hflag {
			flag = true
		}

		kflag := true
		if len(v.Keyword) > 0 {
			kflag = false
			for _, k := range v.Keyword {
				if !strings.Contains(string(data), k) {
					kflag = false
					break
				}
				kflag = true
			}
		}
		if len(v.Keyword) > 0 && kflag {
			flag = true
		}

		if flag {
			fpName = v.Name
			break
		}
	}

	titleArr := pTitle.FindStringSubmatch(string(data))
	sTitle := ""
	if titleArr != nil {
		if len(titleArr) == 2 {
			sTitle = titleArr[1]
			if !utf8.ValidString(sTitle) {
				sTitle = mahonia.NewDecoder("gb18030").ConvertString(sTitle)
			}
		}
	}

	s.PrintColorResultInfoConsole(Result{Url: url, StatusCode: strconv.Itoa(statuscode), Title: sTitle, Name: fpName})

	return nil

}

func (s *Service) PrintColorResultInfoConsole(result Result) {
	r := &core.Result{}

	r.IsVul = false
	if len(result.StatusCode) != 0 {
		s.ResultSlice = append(s.ResultSlice, result)
		r.FingerResult = result
	}
	s.Options.ApiCallBack(r)
}
