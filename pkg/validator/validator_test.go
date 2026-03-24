package validator

import (
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

func TestParseYamlStrictErrors_UnknownFieldRequests(t *testing.T) {
	content := strings.TrimSpace(`
id: test
info:
  name: test
  author: test
  severity: low
requests:
  - method: GET
    path: /
expression: true
`) + "\n"

	var p poc.Poc
	err := yaml.UnmarshalStrict([]byte(content), &p)
	if err == nil {
		t.Fatalf("expected strict unmarshal error, got nil")
	}

	errs := parseYamlStrictErrors("test.yaml", content, err)
	if len(errs) == 0 {
		t.Fatalf("expected parsed errors, got 0")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "unsupported field 'requests'") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected unsupported field 'requests' error, got: %#v", errs)
	}
}
