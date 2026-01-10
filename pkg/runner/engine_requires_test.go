package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestShouldSkipRequires_Strict_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, nil) {
		t.Fatalf("expected skip when strict and no fingerprint tags")
	}
}

func TestShouldSkipRequires_Opportunistic_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}, RequiresMode: "opportunistic"}}
	if shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, nil) {
		t.Fatalf("expected not skip when opportunistic and no fingerprint tags")
	}
}

func TestShouldSkipRequires_Strict_Match(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]struct{}{
		"127.0.0.1:3306": {"mysql": {}},
	}
	if shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, fingerTagsByKey) {
		t.Fatalf("expected not skip when requires matches target fingerprint tags")
	}
}

func TestShouldSkipRequires_Strict_Mismatch(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]struct{}{
		"127.0.0.1:3306": {"redis": {}},
	}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(s string) string { return s }, fingerTagsByKey) {
		t.Fatalf("expected skip when requires does not match target fingerprint tags")
	}
}

func TestShouldSkipRequires_Strict_EmptyKey(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	fingerTagsByKey := map[string]map[string]struct{}{
		"127.0.0.1:3306": {"mysql": {}},
	}
	if !shouldSkipRequires("127.0.0.1:3306", p, func(string) string { return "" }, fingerTagsByKey) {
		t.Fatalf("expected skip when strict and target key cannot be resolved")
	}
}

