package poc

import "testing"

func TestIsNetOnly(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		want  bool
	}{
		{
			name:  "empty rules — not net-only",
			rules: nil,
			want:  false,
		},
		{
			name: "http only",
			rules: []Rule{
				{Request: RuleRequest{Type: HTTP_Type}},
			},
			want: false,
		},
		{
			name: "https only",
			rules: []Rule{
				{Request: RuleRequest{Type: HTTPS_Type}},
			},
			want: false,
		},
		{
			name: "tcp only",
			rules: []Rule{
				{Request: RuleRequest{Type: TCP_Type}},
			},
			want: true,
		},
		{
			name: "udp only",
			rules: []Rule{
				{Request: RuleRequest{Type: UDP_Type}},
			},
			want: true,
		},
		{
			name: "ssl only",
			rules: []Rule{
				{Request: RuleRequest{Type: SSL_Type}},
			},
			want: true,
		},
		{
			name: "go type — not net-only",
			rules: []Rule{
				{Request: RuleRequest{Type: GO_Type}},
			},
			want: false,
		},
		{
			name: "tcp + go — not net-only (go overrides)",
			rules: []Rule{
				{Request: RuleRequest{Type: TCP_Type}},
				{Request: RuleRequest{Type: GO_Type}},
			},
			want: false,
		},
		{
			name: "http + tcp — not net-only (has http)",
			rules: []Rule{
				{Request: RuleRequest{Type: HTTP_Type}},
				{Request: RuleRequest{Type: TCP_Type}},
			},
			want: false,
		},
		{
			name: "empty type — treated as http",
			rules: []Rule{
				{Request: RuleRequest{Type: ""}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Poc{Rules: makeRuleMapSlice(tt.rules)}
			got := p.IsNetOnly()
			if got != tt.want {
				t.Errorf("IsNetOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func makeRuleMapSlice(rules []Rule) RuleMapSlice {
	out := make(RuleMapSlice, len(rules))
	for i, r := range rules {
		out[i] = RuleMap{Key: "rule", Value: r}
	}
	return out
}
