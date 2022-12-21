package output

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"

	"github.com/zan8in/gologger"
)

type OutputJson struct {
	Filename   string
	JsonSlices []JsonInfo
	mutex      sync.Mutex
}

type JsonInfo struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Url      string `json:"url"`
}

func NewOutputJson(filename string) *OutputJson {
	return &OutputJson{
		Filename:   "reports/" + filename,
		JsonSlices: make([]JsonInfo, 0),
		mutex:      sync.Mutex{},
	}
}

func (o *OutputJson) AddJson(name, severity, url string) {
	o.JsonSlices = append(o.JsonSlices, JsonInfo{Name: name, Severity: severity, Url: url})

	if len(o.JsonSlices) > 0 {

		o.mutex.Lock()
		defer o.mutex.Unlock()

		content := "["

		for _, j := range o.JsonSlices {
			v, _ := json.Marshal(&j)
			content += string(v) + ","
		}

		content = strings.TrimSuffix(content, ",")

		content += "]"

		f, err := os.OpenFile(o.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			gologger.Fatal().Msgf("OutputJson to file %s failed, %s", o.Filename, err.Error())
		}

		wbuf := bufio.NewWriterSize(f, len(content))
		wbuf.WriteString(content)
		wbuf.Flush()

	}

}
