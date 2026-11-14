package runner

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"gopkg.in/yaml.v2"
)

// 证据只需要「能复核」的关键片段。原始报文在 result 表里已经完整保留一份，
// 这里不再重复存整包，避免大响应把证据表撑爆。
const (
	evidenceBodyLimit   = 32 * 1024
	evidenceHeaderLimit = 8 * 1024
)

// buildEvidence 把 checker 已经采集到的请求/响应组装成统一证据对象。
//
// 它只做「翻译」，不重新发包、不改判定：所有数据都来自本次执行的 AllPocResult。
// 没有有效步骤（例如纯指纹命中）时返回 nil，避免产生无法复核的空证据。
func buildEvidence(r *result.Result) *evidence.Evidence {
	if r == nil || r.PocInfo == nil || len(r.AllPocResult) == 0 {
		return nil
	}

	target := strings.TrimSpace(r.FullTarget)
	if target == "" {
		target = strings.TrimSpace(r.Target)
	}

	steps := make([]evidence.Step, 0, len(r.AllPocResult))
	matchedIdx := -1
	for _, pr := range r.AllPocResult {
		if pr == nil {
			continue
		}
		step := evidence.Step{
			Role:    evidence.RoleProbe,
			Matched: pr.IsVul,
			Request: evidence.Request{
				Method:  strings.ToUpper(strings.TrimSpace(pr.ResultRequest.GetMethod())),
				URL:     requestURL(pr, target),
				Headers: clampText(utils.Str2UTF8(string(pr.ResultRequest.GetRawHeader())), evidenceHeaderLimit),
				Body:    clampText(utils.Str2UTF8(string(pr.ResultRequest.GetBody())), evidenceBodyLimit),
			},
			Response: evidence.Response{
				Status:    int(pr.ResultResponse.GetStatus()),
				Headers:   clampText(utils.Str2UTF8(string(pr.ResultResponse.GetRawHeader())), evidenceHeaderLimit),
				Body:      clampText(utils.Str2UTF8(string(pr.ResultResponse.GetBody())), evidenceBodyLimit),
				LatencyMs: pr.ResultResponse.GetLatency(),
			},
		}
		if pr.IsVul {
			step.Role = evidence.RoleConfirm
			matchedIdx = len(steps)
		}
		steps = append(steps, step)
	}
	if len(steps) == 0 {
		return nil
	}

	// 提取值就是「证明力」本身，挂在确认步骤上；没有确认步骤时退到最后一个
	// 有内容的步骤，避免证据链里出现「有结论、无凭据」。
	if extracted := extractorMap(r.Extractor); len(extracted) > 0 {
		idx := matchedIdx
		if idx < 0 {
			idx = len(steps) - 1
		}
		steps[idx].Extracted = extracted
	}

	b := evidence.NewBuilder(r.PocInfo.Id, target).WithConfidence(evidence.Certain)
	for _, s := range steps {
		b.AddStep(s)
	}
	return b.Build()
}

// requestURL 取本次步骤实际请求的地址；步骤没带全目标时回落到整体目标。
func requestURL(pr *result.PocResult, fallback string) string {
	if pr != nil {
		if v := strings.TrimSpace(pr.FullTarget); v != "" {
			return v
		}
	}
	return fallback
}

// extractorMap 把 PoC 的 yaml.MapSlice 提取结果转成字符串映射。
// 非字符串键、空值与复合值统一跳过：证据里只保留能直接复核的键值对。
func extractorMap(in yaml.MapSlice) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for _, item := range in {
		key, ok := item.Key.(string)
		if !ok || strings.TrimSpace(key) == "" || item.Value == nil {
			continue
		}
		value := strings.TrimSpace(toString(item.Value))
		if value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return utils.Str2UTF8(string(t))
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

// clampText 按字节上限截断文本，并把截断点回退到合法 UTF-8 字符边界，
// 避免把中文或多字节符号切成乱码。
func clampText(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n...[truncated]"
}
