package result

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"gopkg.in/yaml.v2"
)

type Result struct {
	IsVul        bool
	Target       string
	FullTarget   string
	PocInfo      *poc.Poc
	AllPocResult []*PocResult
	Output       string
	FingerResult any
	Extractor    yaml.MapSlice
}

type PocResult struct {
	FullTarget     string
	ResultRequest  *proto.Request
	ResultResponse *proto.Response
	IsVul          bool
	BruteTruncated bool
	BruteRequests  int
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
	return utils.Str2UTF8(string(pr.ResultResponse.GetRaw()))
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

func (r *Result) WriteOutput() {
	utils.BufferWriteAppend(r.Output, "["+utils.GetNowDateTime()+"] ["+r.PocInfo.Id+"] ["+r.PocInfo.Info.Severity+"] "+r.Target) // output save to file
}

func (r *Result) PrintResultInfo() string {
	return "[" + utils.GetNowDateTime() + "] [" + r.PocInfo.Id + "] [" + r.PocInfo.Info.Severity + "] " + r.Target
}

func (r *Result) PrintColorResultInfoConsole(number string) {
	extinfo := ""
	if len(r.Extractor) > 0 {
		for _, v := range r.Extractor {
			switch value := v.Value.(type) {
			case map[string]string:
			case string:
				extinfo += "," + log.LogColor.Extractor(v.Key.(string)) + "=\"" + log.LogColor.Extractor(utils.Str2UTF8(value)) + "\""
			}
		}
		extinfo = "[" + strings.TrimLeft(extinfo, ",") + "]"
	}

	fmt.Printf("\r%v %v %v %v\r\n", log.LogColor.Time(number+" "+utils.GetNowDateTime()),
		log.LogColor.Vulner(""+r.PocInfo.Id+"")+" "+log.LogColor.GetColor(r.PocInfo.Info.Severity, strings.ToUpper(r.PocInfo.Info.Severity)+""), r.FullTarget, extinfo)

}

func (r *Result) Debug() {

	for k, v := range r.AllPocResult {
		k++
		gologger.Info().Msgf("\r\n[%d][%s] Dumped Request\n", k, r.PocInfo.Id)
		gologger.Print().Msgf("%s\n", v.ResultRequest.GetRaw())

		gologger.Info().Msgf("\r\n[%d][%s] Dumped Response\n", k, r.PocInfo.Id)
		gologger.Print().Msgf("%s\n", utils.Str2UTF8(string(v.ResultResponse.GetRaw())))
	}

}

func (r *Result) Reset() {
	r.IsVul = false
	r.Target = ""
	*r.PocInfo = poc.Poc{}
	r.AllPocResult = nil
	r.Output = ""
}

func (pr *PocResult) Reset() {
	pr.IsVul = false
	pr.ResultRequest = &proto.Request{}
	pr.ResultResponse = &proto.Response{}
	pr.BruteTruncated = false
	pr.BruteRequests = 0
}
