package report

import (
	"testing"

	"github.com/zan8in/afrog/pkg/core"
)

func TestCheckFile(t *testing.T) {
	filename := "xxx.htm"
	report, err := NewReport(filename, DefaultTemplate)
	if err != nil {
		t.Fatalf("newReprot err: %v", err)
	}
	report.Result = &core.Result{IsVul: true, Target: "http://localhost"}
	err = report.Append("1")
	if err != nil {
		t.Fatalf("Append err: %v", err)
	}
}
