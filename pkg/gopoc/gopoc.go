package gopoc

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/scan"
)

type GoPocArgs struct {
	Target  string
	Host    string
	Port    string
	Schema  string
	IsHTTPS bool
	Poc     *poc.Poc
}

type Result struct {
	IsVul        bool
	Gpa          *GoPocArgs
	AllPocResult []*GoPocResult
}

type GoPocResult struct {
	ResultRequest  *proto.Request
	ResultResponse *proto.Response
	IsVul          bool
}

type GoPocScanFunc func(args *GoPocArgs) (Result, error)

var goPocHandles = map[string]GoPocScanFunc{}

func New(target string) *GoPocArgs {
	gpa := GoPocArgs{}
	gpa.SetTarget(target)

	schema, _ := scan.URL2schema(gpa.Target)
	gpa.Schema = schema

	ip, _ := scan.Target2ip(gpa.Target)
	gpa.Host = ip

	port, _ := scan.URL2port(gpa.Target)
	if len(port) == 0 && gpa.Schema == "http" {
		port = "80"
	} else if len(port) == 0 && gpa.Schema == "https" {
		port = "443"
	}
	gpa.Port = port

	if len(gpa.Schema) > 0 && gpa.Schema == "https" {
		gpa.IsHTTPS = true
	}

	return &gpa
}

func GetGoPocFunc(pocName string) GoPocScanFunc {
	if g, err := goPocHandles[pocName]; err {
		return g
	}
	return nil
}

func GoPocRegister(pocName string, handler GoPocScanFunc) {
	if GetGoPocFunc(pocName) != nil {
		fmt.Println(pocName + " 已存在")
		return
	}
	goPocHandles[pocName] = handler
}

func Size() int {
	return len(goPocHandles)
}

func (gpa *GoPocArgs) SetPocInfo(pocinfo poc.Poc) {
	gpa.Poc = &pocinfo
}

func (gpa *GoPocArgs) SetTarget(target string) {
	if len(target) > 0 {
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "http://" + target
		}
		gpa.Target = target
	}
}

func (r *Result) SetAllPocResult(isvul bool, url *proto.UrlType, reqRaw, respRaw []byte) {
	pocResult := GoPocResult{
		IsVul:          isvul,
		ResultRequest:  &proto.Request{Raw: reqRaw, Url: url},
		ResultResponse: &proto.Response{Raw: respRaw},
	}
	r.AllPocResult = append(r.AllPocResult, &pocResult)
}

func MapGoPocName() []string {
	result := []string{}
	if len(goPocHandles) > 0 {
		for k, _ := range goPocHandles {
			result = append(result, k)
		}
	}
	return result
}
