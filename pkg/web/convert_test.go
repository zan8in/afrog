package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// convertReq 直接调用处理器（绕开 JWT 中间件），返回状态码与解析后的响应。
func convertReq(t *testing.T, content string) (int, map[string]any) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{"yaml_content": content})
	if err != nil {
		t.Fatalf("marshal 请求: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/pocs/convert-nuclei", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	pocsConvertNucleiHandler(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	return rec.Code, resp
}

func TestPocsConvertNucleiHandlerSuccess(t *testing.T) {
	src := `id: sample-template
info:
  name: Sample Template
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words:
          - "dashboard"
`

	code, resp := convertReq(t, src)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (resp=%v)", code, resp)
	}
	if ok, _ := resp["success"].(bool); !ok {
		t.Fatalf("success = %v, want true", resp["success"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("data 类型 = %T, want object", resp["data"])
	}
	if data["class"] != "A" {
		t.Errorf("class = %v, want A", data["class"])
	}
	if conv, _ := data["convertible"].(bool); !conv {
		t.Errorf("convertible = %v, want true", data["convertible"])
	}
	if yamlOut, _ := data["yaml"].(string); !strings.Contains(yamlOut, "id: sample-template") {
		t.Errorf("yaml 未包含原 id, got: %q", yamlOut)
	}
	if gaps, _ := data["gaps"].([]any); len(gaps) != 0 {
		t.Errorf("gaps = %v, want 空数组", gaps)
	}
}

// TestPocsConvertNucleiHandlerDowngrade C 类必须回 200 但 convertible=false，
// 且既要有缺口原因、又不得产出 YAML（否则前端会误以为自己可以保存）。
func TestPocsConvertNucleiHandlerDowngrade(t *testing.T) {
	src := `id: sample-flow
info:
  name: Sample Flow
  severity: info
flow: http(1)
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

	code, resp := convertReq(t, src)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (resp=%v)", code, resp)
	}
	data, _ := resp["data"].(map[string]any)
	if data["class"] != "C" {
		t.Errorf("class = %v, want C", data["class"])
	}
	if conv, _ := data["convertible"].(bool); conv {
		t.Errorf("convertible = %v, want false", data["convertible"])
	}
	if yamlOut, _ := data["yaml"].(string); yamlOut != "" {
		t.Errorf("C 类不应产出 YAML, got: %q", yamlOut)
	}
	if gaps, _ := data["gaps"].([]any); len(gaps) == 0 {
		t.Errorf("gaps 为空，应给出降级原因")
	}
}

// TestPocsConvertNucleiHandlerRejectsInvalid 非法输入必须是 400 且 success=false。
func TestPocsConvertNucleiHandlerRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"空内容", "   "},
		{"非 nuclei 模板", "id: afrog-poc\ninfo:\n  name: x\nrules:\n  r0:\n    request:\n      path: /\n"},
	}

	for _, c := range cases {
		code, resp := convertReq(t, c.content)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, code)
		}
		if ok, _ := resp["success"].(bool); ok {
			t.Errorf("%s: success = true, want false", c.name)
		}
	}
}
