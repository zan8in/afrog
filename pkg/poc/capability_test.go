package poc

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/capability"
)

func TestCapabilityDeclarative(t *testing.T) {
	p := Poc{Rules: RuleMapSlice{
		{Value: Rule{Request: RuleRequest{Type: TCP_Type}}},
	}}
	if got := p.Capability(); got != capability.Declarative {
		t.Fatalf("capability = %v, want declarative", got)
	}
}

func TestCapabilityJSNetwork(t *testing.T) {
	p := Poc{Rules: RuleMapSlice{
		{Value: Rule{Request: RuleRequest{
			Type: JS_Type,
			Code: `var net = require("afrog/net");`,
		}}},
	}}
	if got := p.Capability(); got != capability.Network {
		t.Fatalf("capability = %v, want network", got)
	}
}

func TestCapabilityJSWithPrivilegedModule(t *testing.T) {
	// 用测试专用的特权模块名，验证 require 扫描会提升 PoC 的能力等级
	capability.RegisterModule("afrog/test-exec", capability.Exec)

	p := Poc{Rules: RuleMapSlice{
		{Value: Rule{Request: RuleRequest{
			Type: JS_Type,
			Code: `var e = require('afrog/test-exec');`,
		}}},
	}}
	if got := p.Capability(); got != capability.Exec {
		t.Fatalf("capability = %v, want exec", got)
	}
}

func TestCapabilityIgnoresNonJSRules(t *testing.T) {
	// 非 js 规则里的 require 文本不应影响能力等级
	p := Poc{Rules: RuleMapSlice{
		{Value: Rule{Request: RuleRequest{
			Type: HTTP_Type,
			Body: `require("afrog/test-exec")`,
		}}},
	}}
	if got := p.Capability(); got != capability.Declarative {
		t.Fatalf("capability = %v, want declarative", got)
	}
}
