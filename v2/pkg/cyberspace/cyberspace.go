package cyberspace

import (
	"fmt"

	"github.com/zan8in/afrog/v2/pkg/config"
	zoom_eyes "github.com/zan8in/zoomeye/pkg/runner"
)

type Cyberspace struct {
	Config     *config.Config
	Engine     string
	Query      string
	QueryCount int
}

func New(config *config.Config, engine, query string, queryCount int) (*Cyberspace, error) {
	if len(engine) == 0 || len(query) == 0 {
		return nil, fmt.Errorf("engine or query is empty")
	}
	c := &Cyberspace{
		Config:     config,
		Engine:     engine,
		Query:      query,
		QueryCount: queryCount,
	}

	if len(c.GetApiKey(engine)) == 0 {
		return nil, fmt.Errorf("engine %s api key is empty", engine)
	}

	return c, nil
}

func (c *Cyberspace) GetApiKey(engine string) string {
	switch engine {
	case "zoomeye":
		if len(c.Config.Cyberspace.ZoomEyes) > 0 {
			return c.Config.Cyberspace.ZoomEyes[0]
		}
		return ""
	}

	return ""
}

func (c *Cyberspace) GetTargets() ([]string, error) {
	results := []string{}

	opt := zoom_eyes.Options{
		Search: c.Query,
		ApiKey: c.GetApiKey(c.Engine),
		Count:  c.QueryCount,
	}

	runner, err := zoom_eyes.New(&opt)
	if err != nil {
		return results, err
	}

	resultChan, err := runner.RunChan()
	if err != nil {
		return results, err
	}

	var currentTotal, total int
	for r := range resultChan {
		if total == 0 {
			total = r.Total
		}
		for _, v := range r.Results {
			var ip, service string
			var port float64
			ip = v["ip"].(string)
			portinfo := v["portinfo"].(map[string]any)
			if portinfo != nil {
				port = portinfo["port"].(float64)
				service = portinfo["service"].(string)
			}

			url := ""
			strPort := ""
			if int(port) != 0 {
				strPort = fmt.Sprintf(":%d", int(port))
			}
			if service == "http" || service == "https" {
				url = fmt.Sprintf("%s://%s%s", service, ip, strPort)
			} else {
				url = fmt.Sprintf("%s%s", ip, strPort)
			}
			results = append(results, url)
			currentTotal++
			if currentTotal == c.QueryCount {
				break
			}
		}
		fmt.Printf("\rZoomEye Searching... Total: %d, Count: %d, Current: %d", total, c.QueryCount, currentTotal)
	}

	fmt.Println("")

	return results, nil
}
