package gopoc

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
)

type GoPocArgs struct {
	Target  string
	Host    string
	Port    int16
	IsHTTPS bool
	PoInfo  *poc.Info
}

type Result struct {
	IsVul        bool
	Gpa          *GoPocArgs
	AllPocResult []*core.PocResult
}

type GoPocScanFunc func(args *GoPocArgs) (Result, error)

var goPocHandles = map[string]GoPocScanFunc{}

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

func (gpa *GoPocArgs) SetPocInfo(pocinfo poc.Info) {
	gpa.PoInfo = &pocinfo
}

func (r *Result) SetAllPocResult(reqRaw, respRaw []byte) {
	pocResult := core.PocResult{}
	pocResult.ResultRequest = &proto.Request{Raw: reqRaw}
	pocResult.ResultResponse = &proto.Response{Raw: respRaw}
	r.AllPocResult = append(r.AllPocResult, &pocResult)
}
