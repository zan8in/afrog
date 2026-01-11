package poc

import (
	"testing"

	"gopkg.in/yaml.v2"
)

func TestRuleRequestStepsUnmarshal(t *testing.T) {
	raw := `
type: tcp
host: 127.0.0.1
port: 1234
steps:
  - read:
      read-size: 10
      read-timeout: 1
      read-until: "\r\n"
      read-type: string
      save-as: banner
  - write:
      data: "PING\r\n"
      data-type: string
`
	var req RuleRequest
	if err := yaml.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Type != "tcp" {
		t.Fatalf("expected type tcp, got %q", req.Type)
	}
	if len(req.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(req.Steps))
	}

	if req.Steps[0].Read == nil {
		t.Fatalf("expected first step read")
	}
	if req.Steps[0].Read.ReadUntil != "\r\n" {
		t.Fatalf("expected read-until CRLF, got %q", req.Steps[0].Read.ReadUntil)
	}
	if req.Steps[0].Read.ReadType != "string" {
		t.Fatalf("expected read-type string, got %q", req.Steps[0].Read.ReadType)
	}
	if req.Steps[0].Read.SaveAs != "banner" {
		t.Fatalf("expected save-as banner, got %q", req.Steps[0].Read.SaveAs)
	}
}
