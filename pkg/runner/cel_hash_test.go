package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/proto"
)

func TestCelSHA256AndSHA512(t *testing.T) {
	lib := NewCustomLib()

	vars := map[string]any{
		"response": &proto.Response{Body: []byte("abc")},
	}

	cases := []struct {
		expr string
		want any
	}{
		// sha256("abc") / sha512("abc") 为公认标准值，用于锚定实现正确性
		{`sha256("abc")`, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{`sha512("abc")`, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		// bytes 重载：response.body 为 []byte
		{`sha256(response.body)`, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{`sha512(response.body)`, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		// 与 "abc" 的 sha256 比对，验证可在表达式中直接参与判定
		{`sha256(toUtf8(response.body)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`, true},
	}

	for _, c := range cases {
		out, err := lib.RunEval(c.expr, vars)
		if err != nil {
			t.Fatalf("eval %s: %v", c.expr, err)
		}
		if got := out.Value(); got != c.want {
			t.Errorf("eval %s: got %v, want %v", c.expr, got, c.want)
		}
	}
}
