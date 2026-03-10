package config

import "testing"

func TestDetectLegacyOOBReasons(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "legacy oobCheck signature",
			in: `
id: a
rules:
  r0:
    request:
      method: GET
      path: /
    expression: oobCheck(oob, oob.ProtocolDNS, 5)
expression: r0()
`,
			want: true,
		},
		{
			name: "legacy placeholders",
			in: `
id: b
rules:
  r0:
    request:
      method: GET
      path: /?x={{oobDNS}}
    expression: oobCheck("dns", 5)
expression: r0()
`,
			want: true,
		},
		{
			name: "new syntax should not match",
			in: `
id: c
rules:
  r0:
    request:
      method: GET
      path: /?x={{oob.DNS}}
    expression: oobCheck("dns", 5)
expression: r0()
`,
			want: false,
		},
		{
			name: "comment should not match",
			in: `
id: d
rules:
  r0:
    request:
      method: GET
      path: /
    expression: true # oobCheck(oob, oob.ProtocolDNS, 5)
expression: r0()
`,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := len(detectLegacyOOBReasons(tc.in)) > 0
			if got != tc.want {
				t.Fatalf("mismatch: got=%v want=%v reasons=%v", got, tc.want, detectLegacyOOBReasons(tc.in))
			}
		})
	}
}

