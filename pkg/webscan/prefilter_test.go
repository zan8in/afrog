package webscan

import (
	"math/rand"
	"strings"
	"testing"
)

// TestLiteralIndexMatchesContains 用随机语料把自动机的判定和 strings.Contains 对齐。
//
// 预筛器一旦漏判，对应规则就会被静默跳过——表现为「某些技术识别不到」，而且极难复现。
// 因此不能只靠几个手写用例，要用随机语料做等价性校验。
func TestLiteralIndexMatchesContains(t *testing.T) {
	r := rand.New(rand.NewSource(20261104))
	alphabet := []byte("abc.-_/")

	randString := func(minLen, maxLen int) string {
		n := minLen + r.Intn(maxLen-minLen+1)
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		return string(b)
	}

	for round := 0; round < 200; round++ {
		literals := make([]string, 0, 12)
		for i := 0; i < 12; i++ {
			literals = append(literals, randString(1, 6))
		}
		idx := buildLiteralIndex(literals)

		for probe := 0; probe < 20; probe++ {
			text := randString(0, 60)
			hits := make([]bool, len(literals))
			idx.scan(text, hits)
			for i, lit := range literals {
				want := strings.Contains(text, lit)
				if hits[i] != want {
					t.Fatalf("scan(%q) literal %q = %v, want %v", text, lit, hits[i], want)
				}
			}
		}
	}
}
