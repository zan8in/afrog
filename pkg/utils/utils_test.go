package utils

import (
	"bytes"
	"testing"
)

// HexDecode used to call log.Fatal on malformed input, which terminates the
// whole process. A library function must not kill its host just because one
// PoC carried a bad hex string, so it now returns nil instead.
func TestHexDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{"empty", "", []byte{}},
		{"lowercase", "48656c6c6f", []byte("Hello")},
		{"uppercase", "48656C6C6F", []byte("Hello")},
		{"zero byte", "00", []byte{0x00}},

		// Every case below terminated the process before the fix.
		{"odd length", "abc", nil},
		{"non-hex character", "zz", nil},
		{"trailing garbage", "48656c6c6fzz", nil},
		{"whitespace", "48 65", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HexDecode(tt.input)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("HexDecode(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("HexDecode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// A malformed string reaching HexDecode must leave the caller running so the
// scan can continue with the remaining PoCs.
func TestHexDecode_MalformedInputDoesNotAbort(t *testing.T) {
	for _, s := range []string{"nothex", "1", "%%%%"} {
		if got := HexDecode(s); got != nil {
			t.Errorf("HexDecode(%q) = %v, want nil", s, got)
		}
	}
	// Reaching this line at all is the assertion: the old implementation
	// exited the test binary before it.
	if got := HexDecode("41"); !bytes.Equal(got, []byte("A")) {
		t.Fatalf("HexDecode still works after malformed input: got %v", got)
	}
}
