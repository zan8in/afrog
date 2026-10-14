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
	gproto "google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

type Result struct {
	IsVul        bool
	SkipCount    bool
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
	// BodyTruncated 表示响应体在 MaxRespBodySize 上限处被截断，
	// 此时 ResultResponse.Body 不是完整的服务端响应。
	BodyTruncated bool
}

func DebugDumpRequestText(pr *PocResult) string {
	if pr == nil {
		return "[debug] request dump unavailable: step result is empty."
	}
	if pr.ResultRequest == nil {
		return "[debug] request dump unavailable: request execution failed before the raw request was captured; see the [ERR] log above for details."
	}
	if len(pr.ResultRequest.GetRaw()) == 0 {
		return "[debug] request dump unavailable: raw request is empty; the request may have failed before serialization."
	}
	return utils.Str2UTF8(string(pr.ResultRequest.GetRaw()))
}

func DebugDumpResponseText(pr *PocResult) string {
	if pr == nil {
		return "[debug] response dump unavailable: step result is empty."
	}
	if pr.ResultResponse == nil {
		return "[debug] response dump unavailable: no response was captured; the request may have failed before the server returned data."
	}
	if len(pr.ResultResponse.GetRaw()) == 0 {
		return "[debug] response dump unavailable: raw response is empty; the connection may have been reset or closed before data was captured."
	}
	return utils.Str2UTF8(string(pr.ResultResponse.GetRaw()))
}

func (r *Result) Snapshot() *Result {
	if r == nil {
		return nil
	}

	out := &Result{
		IsVul:        r.IsVul,
		SkipCount:    r.SkipCount,
		Target:       r.Target,
		FullTarget:   r.FullTarget,
		Output:       r.Output,
		FingerResult: r.FingerResult,
	}
	if r.PocInfo != nil {
		pi := *r.PocInfo
		out.PocInfo = &pi
	}
	if len(r.AllPocResult) > 0 {
		out.AllPocResult = make([]*PocResult, 0, len(r.AllPocResult))
		for _, pr := range r.AllPocResult {
			out.AllPocResult = append(out.AllPocResult, pr.Snapshot())
		}
	}
	if len(r.Extractor) > 0 {
		out.Extractor = append(yaml.MapSlice(nil), r.Extractor...)
	}
	return out
}

func (pr *PocResult) Snapshot() *PocResult {
	if pr == nil {
		return nil
	}

	return &PocResult{
		FullTarget:     pr.FullTarget,
		ResultRequest:  cloneRequest(pr.ResultRequest),
		ResultResponse: cloneResponse(pr.ResultResponse),
		IsVul:          pr.IsVul,
		BruteTruncated: pr.BruteTruncated,
		BruteRequests:  pr.BruteRequests,
		BodyTruncated:  pr.BodyTruncated,
	}
}

func cloneRequest(in *proto.Request) *proto.Request {
	if in == nil {
		return nil
	}
	if out, ok := gproto.Clone(in).(*proto.Request); ok {
		return out
	}
	return nil
}

func cloneResponse(in *proto.Response) *proto.Response {
	if in == nil {
		return nil
	}
	if out, ok := gproto.Clone(in).(*proto.Response); ok {
		return out
	}
	return nil
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
	fmt.Printf("\r%v %v %v %v\r\n", log.LogColor.Time(number+" "+utils.GetNowDateTime()),
		log.LogColor.Vulner(""+r.PocInfo.Id+"")+" "+log.LogColor.GetColor(r.PocInfo.Info.Severity, strings.ToUpper(r.PocInfo.Info.Severity)+""), r.FullTarget, formatExtractorInline(r.Extractor))

}

// formatExtractorInline 把提取结果渲染成控制台内联片段：`[key=value,key=value]`。
// 只在必要时给值加引号（空值、或含空白/逗号/引号），并支持字符串以外的常见类型，
// 让类型化提取器（数字、布尔、字符串列表）也能正常展示。无可用值时返回空串。
func formatExtractorInline(extractor yaml.MapSlice) string {
	if len(extractor) == 0 {
		return ""
	}
	parts := make([]string, 0, len(extractor))
	for _, v := range extractor {
		key, ok := v.Key.(string)
		if !ok || key == "" {
			continue
		}
		val, ok := extractorValueText(v.Value)
		if !ok {
			continue
		}
		parts = append(parts, log.LogColor.Extractor(key)+"="+log.LogColor.Extractor(val))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// extractorValueText 把提取值渲染成文本；不支持的复杂类型返回 false（跳过）。
func extractorValueText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return quoteExtractorValue(utils.Str2UTF8(t)), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case []string:
		items := make([]string, 0, len(t))
		for _, it := range t {
			items = append(items, quoteExtractorValue(it))
		}
		return strings.Join(items, ","), true
	default:
		return "", false
	}
}

// quoteExtractorValue 仅在必要时加引号：空值用 "" 明确表示，含空白/逗号/引号时转义。
func quoteExtractorValue(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t,\"") {
		return strconv.Quote(s)
	}
	return s
}

func (r *Result) Debug() {

	for k, v := range r.AllPocResult {
		k++
		gologger.Info().Msgf("\r\n[%d][%s] Dumped Request\n", k, r.PocInfo.Id)
		gologger.Print().Msgf("%s\n", DebugDumpRequestText(v))

		gologger.Info().Msgf("\r\n[%d][%s] Dumped Response\n", k, r.PocInfo.Id)
		gologger.Print().Msgf("%s\n", DebugDumpResponseText(v))
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
