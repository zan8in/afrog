package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/policy"
)

// completionOf 调一次 completion/complete 并取回 completion 对象；期望成功。
func completionOf(t *testing.T, s *Server, params string) map[string]any {
	t.Helper()
	resp, _ := s.handle(context.Background(), &request{
		ID:     json.RawMessage(`1`),
		Method: "completion/complete",
		Params: json.RawMessage(params),
	}, nil)
	if resp.Error != nil {
		t.Fatalf("completion/complete: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T, want map", resp.Result)
	}
	c, ok := result["completion"].(map[string]any)
	if !ok {
		t.Fatalf("completion = %v, want object", result["completion"])
	}
	return c
}

// completionValues 取回建议值列表。
func completionValues(t *testing.T, s *Server, params string) []string {
	t.Helper()
	values, _ := completionOf(t, s, params)["values"].([]string)
	return values
}

func assertValues(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("values = %v, want %v", got, want)
		}
	}
}

// 补全按已输入的值做前缀过滤：静态枚举这一路不碰任何存储或执行器，纯本地判断。
func TestCompletionFiltersStaticCandidates(t *testing.T) {
	s := New(Options{Policy: policy.Default()})
	const promptRef = `"ref":{"type":"ref/prompt","name":"triage-findings"}`

	// 空值 = 还没输入，给出全部候选。
	assertValues(t, completionValues(t, s,
		`{`+promptRef+`,"argument":{"name":"severity","value":""}}`),
		"info", "low", "medium", "high", "critical")

	// 前缀匹配，且不区分大小写。
	assertValues(t, completionValues(t, s,
		`{`+promptRef+`,"argument":{"name":"severity","value":"h"}}`), "high")
	assertValues(t, completionValues(t, s,
		`{`+promptRef+`,"argument":{"name":"severity","value":"ME"}}`), "medium")

	// 没匹配上就是空列表，而不是报错。
	assertValues(t, completionValues(t, s,
		`{`+promptRef+`,"argument":{"name":"severity","value":"zzz"}}`))

	// total/hasMore 如实反映命中情况：候选只有 5 条，一次就发完了。
	c := completionOf(t, s, `{`+promptRef+`,"argument":{"name":"severity","value":"h"}}`)
	if c["total"] != 1 || c["hasMore"] != false {
		t.Fatalf("total/hasMore = %v/%v, want 1/false", c["total"], c["hasMore"])
	}
}

// 补不出来就返回空列表：自由文本参数（target）与不认识的参数名都不该编候选，
// 也不该把「没有建议」当成错误——那会让客户端的下拉框直接变成报错提示。
func TestCompletionReturnsEmptyInsteadOfGuessing(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	assertValues(t, completionValues(t, s,
		`{"ref":{"type":"ref/prompt","name":"scan-target"},"argument":{"name":"target","value":"http://"}}`))

	// 参数名没在这条 prompt 里声明过。
	assertValues(t, completionValues(t, s,
		`{"ref":{"type":"ref/prompt","name":"scan-target"},"argument":{"name":"severity","value":""}}`))

	// 资源模板不认识（afrog://status 没有变量，不是模板）。
	assertValues(t, completionValues(t, s,
		`{"ref":{"type":"ref/resource","uri":"afrog://status"},"argument":{"name":"task_id","value":""}}`))
}

// 参数写错才报错：prompt 名不存在与 ref 类型不支持都属 -32602（协议对前者有明确要求）。
func TestCompletionRejectsBadParams(t *testing.T) {
	s := New(Options{Policy: policy.Default()})

	for name, params := range map[string]string{
		"unknown prompt":   `{"ref":{"type":"ref/prompt","name":"nope"},"argument":{"name":"severity","value":""}}`,
		"bad ref type":     `{"ref":{"type":"ref/tool","name":"scan.start"},"argument":{"name":"severity","value":""}}`,
		"missing arg name": `{"ref":{"type":"ref/prompt","name":"triage-findings"},"argument":{"value":""}}`,
		"malformed params": `123`,
	} {
		resp, _ := s.handle(context.Background(), &request{
			ID:     json.RawMessage(`1`),
			Method: "completion/complete",
			Params: json.RawMessage(params),
		}, nil)
		if resp.Error == nil || resp.Error.Code != codeInvalidParams {
			t.Fatalf("%s: resp = %+v, want codeInvalidParams", name, resp)
		}
	}
}
