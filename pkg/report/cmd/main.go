package main

import (
	"log"

	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/report"
)

func main() {
	filename := "xxx.htm"
	report, err := report.NewReport(filename, report.DefaultTemplate)
	if err != nil {
		log.Fatalf("newReprot err: %v", err)
	}
	report.Result = &core.Result{IsVul: true, Target: "http://localhost"}
	err = report.Append("1")
	if err != nil {
		log.Fatalf("Append err: %v", err)
	}
}
