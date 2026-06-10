package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func TestShouldSkipFingerprintFilteredByMode(t *testing.T) {
	tests := []struct {
		name             string
		mode             string
		globalFingerTags map[string]struct{}
		targetTags       map[string]struct{}
		pocTags          map[string]struct{}
		want             bool
	}{
		{
			name:             "empty global tags — never skip",
			mode:             "strict",
			globalFingerTags: nil,
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             false,
		},
		{
			name:             "empty poc tags — never skip",
			mode:             "strict",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			pocTags:          nil,
			want:             false,
		},
		{
			name:             "strict mode: no target tags — skip",
			mode:             "strict",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			targetTags:       nil,
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             true,
		},
		{
			name:             "strict mode: target has tag — don't skip",
			mode:             "strict",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			targetTags:       map[string]struct{}{"tomcat": {}},
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             false,
		},
		{
			name:             "opportunistic mode: no target tags — don't skip",
			mode:             "opportunistic",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			targetTags:       nil,
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             false,
		},
		{
			name:             "opportunistic mode: target has tag — don't skip",
			mode:             "opportunistic",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			targetTags:       map[string]struct{}{"tomcat": {}},
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             false,
		},
		{
			name:             "default mode (empty) — treated as strict",
			mode:             "",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			targetTags:       nil,
			pocTags:          map[string]struct{}{"tomcat": {}},
			want:             true,
		},
		{
			name:             "non-app-specific poc — never skip",
			mode:             "strict",
			globalFingerTags: map[string]struct{}{"tomcat": {}},
			pocTags:          map[string]struct{}{"nginx": {}},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldSkipFingerprintFilteredByMode(tt.mode, tt.globalFingerTags, tt.targetTags, tt.pocTags)
			if got != tt.want {
				t.Errorf("shouldSkipFingerprintFilteredByMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldSkipRequires(t *testing.T) {
	tests := []struct {
		name            string
		target          string
		p               poc.Poc
		fingerTagsByKey map[string]map[string]struct{}
		testMode        bool
		want            bool
	}{
		{
			name:     "test mode — never skip",
			testMode: true,
			want:     false,
		},
		{
			name: "no requires — never skip",
			p: poc.Poc{
				Info: poc.Info{Requires: nil},
			},
			want: false,
		},
		{
			name: "strict mode: require tag not present — skip",
			p: poc.Poc{
				Id: "test-poc",
				Info: poc.Info{
					Requires:     []string{"tomcat"},
					RequiresMode: "strict",
				},
			},
			fingerTagsByKey: map[string]map[string]struct{}{},
			want:            true,
		},
		{
			name: "strict mode: require tag present — don't skip",
			p: poc.Poc{
				Id: "test-poc",
				Info: poc.Info{
					Requires:     []string{"tomcat"},
					RequiresMode: "strict",
				},
			},
			fingerTagsByKey: map[string]map[string]struct{}{
				"host:80": {"tomcat": {}},
			},
			want: false,
		},
		{
			name: "opportunistic mode: tag not present — don't skip",
			p: poc.Poc{
				Id: "test-poc",
				Info: poc.Info{
					Requires:     []string{"tomcat"},
					RequiresMode: "opportunistic",
				},
			},
			fingerTagsByKey: map[string]map[string]struct{}{},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyForTarget := func(t string) string { return "host:80" }
			got := shouldSkipRequires(tt.target, tt.p, keyForTarget, tt.fingerTagsByKey, tt.testMode)
			if got != tt.want {
				t.Errorf("shouldSkipRequires() = %v, want %v", got, tt.want)
			}
		})
	}
}
