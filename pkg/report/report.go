package report

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
	fileutil "github.com/zan8in/pins/file"
	timeutil "github.com/zan8in/pins/time"
)

type Report struct {
	sync.RWMutex
	Result     *result.Result
	of         *os.File
	ReportFile string
	Template   TemplateStyle
}

type TemplateStyle int

const (
	DefaultTemplate TemplateStyle = iota
	MinimalTemplate
)

const OutputDirectory = "./reports"

// fileName: the name of the report file
// template: the name of the template
func NewReport(fileName string, template TemplateStyle) (*Report, error) {
	r := &Report{
		Result:   &result.Result{},
		Template: template,
	}

	if err := r.check(fileName); err != nil {
		return nil, err
	}

	return r, nil
}

func (report *Report) check(fileName string) error {
	if len(fileName) == 0 {
		if !fileutil.FolderExists(OutputDirectory) {
			fileutil.CreateFolder(OutputDirectory)
		}
		fileName = filepath.Join(OutputDirectory, timeutil.Format(timeutil.Format_1)+".html")
		report.ReportFile = fileName
	}

	suffix := path.Ext(fileName)
	if suffix != ".html" && suffix != ".htm" {
		return fmt.Errorf("please change the file extension of the output to .html or .htm. Unable to create output file")
	}

	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		file, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("unable to create output file: %v", err)
		}
		file.Close()
		time.Sleep(100 * time.Millisecond)

		report.ReportFile = fileName

		return os.Remove(fileName)

	}

	report.ReportFile = fileName

	return nil
}

func (report *Report) SetResult(result *result.Result) {
	report.Lock()
	defer report.Unlock()

	report.Result = result
}

func (report *Report) Append(number string) error {
	return report.Write(report.html(number))
}

func (report *Report) Write(data string) error {
	if len(data) == 0 {
		return nil
	}

	report.Lock()

	var f *os.File
	if report.of == nil {
		f, err := os.OpenFile(report.ReportFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
		if err != nil {
			report.Unlock()
			return err
		}

		report.of = f

		header := report.header()
		wbuf := bufio.NewWriterSize(report.of, len(header))
		wbuf.WriteString(header)
		wbuf.Flush()
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(f *os.File) {
		defer report.Unlock()
		defer f.Close()
		defer wg.Done()

		wbuf := bufio.NewWriterSize(report.of, len(data))
		wbuf.WriteString(data)
		wbuf.Flush()
	}(f)
	wg.Wait()

	return nil
}

func (report *Report) header() string {
	switch report.Template {
	case DefaultTemplate:
		return defaultHeader()
	case MinimalTemplate:
		return minimalHeader()
	}
	return ""
}

func (report *Report) html(number string) string {
	switch report.Template {
	case DefaultTemplate:
		return report.defaultHmtl(number)
	case MinimalTemplate:
		return report.minimalHtml(number)
	}
	return ""
}
