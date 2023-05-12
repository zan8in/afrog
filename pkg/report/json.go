package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/zan8in/afrog/pkg/result"
	fileutil "github.com/zan8in/pins/file"
	timeutil "github.com/zan8in/pins/time"
)

type JsonReport struct {
	sync.RWMutex
	Result     *result.Result
	of         *os.File
	ReportFile string
	JsonAll    bool
}

type JsonResult struct {
	IsVul      bool          `json:"isvul,omitempty"`
	Target     string        `json:"target`
	FullTarget string        `json:"fulltarget,omitempty"`
	PocInfo    JsonPocInfo   `json:"pocinfo,omitempty"`
	PocResult  []JsonReqResp `json:"pocresult,omitempty"`
}

type JsonPocInfo struct {
	Id              string   `json:"id,omitempty"`
	InfoName        string   `json:"infoname,omitempty"`
	InfoAuthor      string   `json:"infoauthor,omitempty"`
	InfoSeverity    string   `json:"infoseg,omitempty"`
	InfoDescription string   `json:"infodescription,omitempty"`
	InfoReference   []string `json:"inforeference,omitempty"`
}

type JsonReqResp struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

func NewJsonReport(json, JsonAll string) (*JsonReport, error) {
	jr := &JsonReport{
		Result: &result.Result{},
	}

	fileName := ""

	if len(json) > 0 {
		fileName = json
	}

	if len(JsonAll) > 0 {
		fileName = JsonAll
		jr.JsonAll = true
	}

	if err := jr.checkJson(fileName); err != nil {
		return nil, err
	}

	return jr, nil
}

func (report *JsonReport) checkJson(fileName string) error {
	if len(fileName) == 0 {
		if !fileutil.FolderExists(OutputDirectory) {
			fileutil.CreateFolder(OutputDirectory)
		}
		fileName = filepath.Join(OutputDirectory, timeutil.Format(timeutil.Format_1)+".json")
		report.ReportFile = fileName
	}

	suffix := path.Ext(fileName)
	if suffix != ".json" {
		return fmt.Errorf("please change the file extension of the output to .json. Unable to create output file")
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

func (jr *JsonReport) SetResult(result *result.Result) {
	jr.Lock()
	defer jr.Unlock()

	jr.Result = result
}

func (jr *JsonReport) Append() error {
	jr.Lock()

	var err error

	if jr.of == nil {
		jr.of, err = os.OpenFile(jr.ReportFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
		if err != nil {
			jr.Unlock()
			return err
		}

		header := "["

		wbuf := bufio.NewWriterSize(jr.of, len(header))
		wbuf.WriteString(header)
		wbuf.Flush()
	}

	go func() {
		defer jr.Unlock()

		jresult := jr.JsonContent()

		ja, err := json.Marshal(jresult)
		if err != nil {
			return
		}

		content := string(ja) + ","

		wbuf := bufio.NewWriterSize(jr.of, len(content))
		wbuf.WriteString(content)
		wbuf.Flush()

	}()

	return nil
}

func (jr *JsonReport) JsonContent() *JsonResult {
	rst := jr.Result
	if rst == nil {
		return nil
	}

	jresult := JsonResult{
		IsVul:      rst.IsVul,
		Target:     rst.Target,
		FullTarget: rst.FullTarget,
		PocInfo: JsonPocInfo{
			Id:              rst.PocInfo.Id,
			InfoName:        rst.PocInfo.Info.Name,
			InfoAuthor:      rst.PocInfo.Info.Author,
			InfoSeverity:    rst.PocInfo.Info.Severity,
			InfoDescription: rst.PocInfo.Info.Description,
			InfoReference:   rst.PocInfo.Info.Reference,
		},
		PocResult: []JsonReqResp{},
	}

	if len(rst.AllPocResult) > 0 && jr.JsonAll {
		for _, pocResult := range rst.AllPocResult {
			jresult.PocResult = append(jresult.PocResult, JsonReqResp{
				Request:  string(pocResult.ResultRequest.Raw),
				Response: string(pocResult.ResultResponse.Raw),
			})
		}
	}

	return &jresult
}

func (jr *JsonReport) AppendEndOfFile() error {

	if !fileutil.FileExists(jr.ReportFile) {
		return nil
	}

	file, err := os.OpenFile(jr.ReportFile, os.O_RDWR, 0755)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	var content []byte
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			break
		}
		content = append(content, line...)
	}

	content = content[:len(content)-1]

	content = append(content, []byte("]")...)

	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}
	_, err = file.Write(content)
	if err != nil {
		return err
	}

	return nil
}
