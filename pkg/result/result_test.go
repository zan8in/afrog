package result

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/log"
	"gopkg.in/yaml.v2"
)

func TestFormatExtractorInline(t *testing.T) {
	old := log.EnableColor
	log.EnableColor = false
	defer func() { log.EnableColor = old }()

	tests := []struct {
		name string
		in   yaml.MapSlice
		want string
	}{
		{"nil", nil, ""},
		{"empty slice", yaml.MapSlice{}, ""},
		{
			name: "plain strings",
			in:   yaml.MapSlice{{Key: "username", Value: "root"}, {Key: "password", Value: "root"}},
			want: "username=root,password=root",
		},
		{
			name: "empty value keeps quotes",
			in:   yaml.MapSlice{{Key: "password", Value: ""}},
			want: `password=""`,
		},
		{
			name: "value with space and comma gets quoted",
			in:   yaml.MapSlice{{Key: "banner", Value: "a b,c"}},
			want: `banner="a b,c"`,
		},
		{
			name: "numbers and bool",
			in:   yaml.MapSlice{{Key: "port", Value: 3306}, {Key: "ok", Value: true}},
			want: "port=3306,ok=true",
		},
		{
			name: "string list",
			in:   yaml.MapSlice{{Key: "ids", Value: []string{"a", "b"}}},
			want: "ids=a,b",
		},
		{
			name: "unsupported map is skipped",
			in:   yaml.MapSlice{{Key: "m", Value: map[string]string{"a": "b"}}},
			want: "",
		},
		{
			name: "non-string key is skipped",
			in:   yaml.MapSlice{{Key: 1, Value: "x"}},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatExtractorInline(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
