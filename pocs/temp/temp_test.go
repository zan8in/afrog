package temp

import "testing"

func TestPrintPocs(t *testing.T) {
	c, _ := PrintPocs()
	println("cout", len(c))
}
