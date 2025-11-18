package runner

import (
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/protocols/gox"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/protocols/netxclient"
	"github.com/zan8in/afrog/v3/pkg/protocols/raw"
)

type Executor interface {
	Execute(target string, rule poc.Rule, opt *config.Options, vars map[string]any) error
}

type HTTPExecutor struct{}

func (e HTTPExecutor) Execute(target string, rule poc.Rule, opt *config.Options, vars map[string]any) error {
	targetTmp := target
	reqType := strings.ToLower(rule.Request.Type)
	if len(reqType) > 0 {
		if reqType == poc.HTTPS_Type {
			if strings.HasPrefix(targetTmp, "http://") {
				targetTmp = strings.Replace(targetTmp, "http://", "https://", 1)
			}
		}
		if reqType == poc.HTTP_Type {
			if strings.HasPrefix(targetTmp, "https://") {
				targetTmp = strings.Replace(targetTmp, "https://", "http://", 1)
			}
		}
	}
	return retryhttpclient.Request(targetTmp, opt.Header, rule, vars)
}

type RawHTTPExecutor struct{}

func (e RawHTTPExecutor) Execute(target string, rule poc.Rule, opt *config.Options, vars map[string]any) error {
	rt := raw.RawHttp{
		RawhttpClient:   raw.GetRawHTTP(opt.Proxy, int(opt.Timeout)),
		MaxRespBodySize: opt.MaxRespBodySize,
	}
	return rt.RawHttpRequest(rule.Request.Raw, target, opt.Header, vars)
}

type NetExecutor struct{}

func (e NetExecutor) Execute(target string, rule poc.Rule, opt *config.Options, vars map[string]any) error {
	network := strings.ToLower(rule.Request.Type)
	nc, err := netxclient.NewNetClient(rule.Request.Host, netxclient.Config{
		Network:     network,
		ReadTimeout: getDuration(rule.Request.ReadTimeout),
		ReadSize:    rule.Request.ReadSize,
		MaxRetries:  1,
	})
	if err != nil {
		return err
	}
	defer nc.Close()
	return nc.Request(rule.Request.Data, rule.Request.DataType, vars)
}

type GoExecutor struct{}

func (e GoExecutor) Execute(target string, rule poc.Rule, opt *config.Options, vars map[string]any) error {
	return gox.Request(target, rule.Request.Data, vars)
}

func getDuration(sec int) (d time.Duration) {
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}

// executor registry
var executors = map[string]Executor{
	"":             HTTPExecutor{},
	poc.HTTP_Type:  HTTPExecutor{},
	poc.HTTPS_Type: HTTPExecutor{},
	poc.TCP_Type:   NetExecutor{},
	poc.UDP_Type:   NetExecutor{},
	poc.SSL_Type:   NetExecutor{},
	poc.GO_Type:    GoExecutor{},
}
