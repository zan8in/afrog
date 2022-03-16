package core

import (
	"fmt"
	"strconv"

	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

type Result struct {
	IsVul        bool
	Target       string
	PocInfo      *poc.Poc
	AllPocResult []PocResult
}

type PocResult struct {
	ResultRequest  *proto.Request
	ResultResponse *proto.Response
	IsVul          bool
}

func (pr *PocResult) ReadFullResultRequestInfo() string {
	result := "\r\n" + pr.ResultRequest.Url.GetScheme() + "://" + pr.ResultRequest.Url.GetHost() + pr.ResultRequest.Url.GetPath()
	if len(pr.ResultRequest.Url.GetQuery()) > 0 {
		result += "?" + pr.ResultRequest.Url.GetQuery()
	} else if len(pr.ResultRequest.Url.Fragment) > 0 {
		result += "#" + pr.ResultRequest.Url.Fragment
	}
	result += "\r\n"

	for k, v := range pr.ResultRequest.Headers {
		result += k + ":" + v + "\r\n"
	}
	result += "\r\n\r\n" + string(pr.ResultRequest.GetBody())
	return result
}

func (pr *PocResult) ReadFullResultResponseInfo() string {
	return string(pr.ResultResponse.GetRaw())
}

func (r *Result) ReadPocInfo() string {
	result := "VulID: " + r.PocInfo.Id + "\r\n"
	result += "Name: " + r.PocInfo.Info.Name + "\r\n"
	result += "Author: " + r.PocInfo.Info.Author + "\r\n"
	result += "Severity: " + r.PocInfo.Info.Severity + "\r\n"
	if len(r.PocInfo.Info.Description) > 0 {
		result += "Description: " + r.PocInfo.Info.Description + "\r\n"
	}
	if len(r.PocInfo.Info.Reference) > 0 {
		result += "Reference: \r\n"
		for _, v := range r.PocInfo.Info.Reference {
			result += "    - " + v + "\r\n"
		}
	}
	if len(r.PocInfo.Info.Tags) > 0 {
		result += "Tags: " + r.PocInfo.Info.Tags + "\r\n"
	}
	if len(r.PocInfo.Info.Classification.CveId) > 0 {
		result += "Classification: \r\n"
		result += "    CveId: " + r.PocInfo.Info.Classification.CveId + "\r\n"
		result += "    CvssMetrics: " + r.PocInfo.Info.Classification.CvssMetrics + "\r\n"
		result += "    CweId: " + r.PocInfo.Info.Classification.CweId + "\r\n"
		result += "    CvssScore: " + strconv.FormatFloat(r.PocInfo.Info.Classification.CvssScore, 'f', 1, 64) + "\r\n"
	}
	return result
}

func (r *Result) PrintResultInfo() string {
	return "[" + utils.GetNowDateTime() + "] [" + r.PocInfo.Id + "] [" + r.PocInfo.Info.Severity + "] " + r.Target
}

func (r *Result) PrintResultInfoConsole() string {
	colorTime := log.GetColor("time", "["+utils.GetNowDateTime()+"]")
	colorPocId := log.GetColor("", "["+r.PocInfo.Id+"]")
	colorSecruity := log.GetColor(r.PocInfo.Info.Severity, "["+r.PocInfo.Info.Severity+"]")
	fmt.Printf("\r" + colorTime + " " + colorPocId + " " + colorSecruity + " " + r.Target + "\r\n")
	return colorPocId + colorSecruity + r.Target
}
