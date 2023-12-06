package cyberspace

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v2/pkg/config"
	"github.com/zan8in/gologger"
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

	apikey := c.GetApiKey(c.Engine)
	if len(apikey) == 0 {
		return results, fmt.Errorf("engine %s api key is empty", c.Engine)
	}

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
			var ip, port, service string
			ip = v["ip"].(string)
			portinfo := v["portinfo"].(map[string]any)
			if portinfo != nil {
				switch portinfo["port"].(type) {
				case float64:
					port = fmt.Sprintf("%f", portinfo["port"].(float64))
				case string:
					port = portinfo["port"].(string)
				default:
					port = fmt.Sprintf("%v", portinfo["port"])
				}
				service = portinfo["service"].(string)
			}

			url := ""
			port = strings.TrimSuffix(port, ".000000")
			if len(port) != 0 {
				port = fmt.Sprintf(":%s", port)
			}
			if service == "http" || service == "https" {
				url = fmt.Sprintf("%s://%s%s", service, ip, port)
			} else {
				url = fmt.Sprintf("%s%s", ip, port)
			}
			results = append(results, url)
			currentTotal++
			if currentTotal == c.QueryCount {
				break
			}
		}
		fmt.Printf("\rZoomEye Searching... Total: %d, Query Count: %d, Current: %d", total, c.QueryCount, currentTotal)
	}

	fmt.Println("")

	if currentTotal == 0 {
		gologger.Info().Msg("no result found")
	}

	return results, nil
}
