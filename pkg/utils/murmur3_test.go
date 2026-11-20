package utils

import (
	"bytes"
	"testing"
)

// 固定向量取自上游 github.com/spaolacci/murmur3 v1.1.0 的 Sum32 输出：
// 本实现必须与之按位一致，否则 favicon 的 mmh3 值会与公开指纹库对不上。
func TestMmh3Sum32Vectors(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint32
	}{
		{nil, 0},
		{[]byte("a"), 1009084850},
		{[]byte("abc"), 3017643002},
		{[]byte("hello world"), 1586663183},
		{bytes.Repeat([]byte("\n"), 76), 2948686319},
	}
	for _, c := range cases {
		if got := mmh3Sum32(c.in); got != c.want {
			t.Fatalf("mmh3Sum32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
