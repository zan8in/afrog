package runner

import (
	"net"
	"net/url"
	"strconv"
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
	address := resolveNetAddress(rule.Request.Host, rule.Request.Port)
	nc, err := netxclient.NewNetClient(address, netxclient.Config{
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
	vars["request"] = nil
	vars["response"] = nil
	vars["target"] = target
	vars["fulltarget"] = target
	if opt != nil && len(opt.Header) > 0 {
		headerLines := make([]string, 0, len(opt.Header))
		for _, h := range opt.Header {
			headerLines = append(headerLines, h)
		}
		vars["__global_headers"] = headerLines
	}
	gox.InjectDefaultHTTPSender(vars)
	return gox.Request(target, rule.Request.Data, vars)
}

func getDuration(sec int) (d time.Duration) {
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}

func resolveNetAddress(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return host
	}

	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			if u.Port() != "" {
				return u.Host
			}
			hn := u.Hostname()
			if hn != "" {
				return net.JoinHostPort(hn, strconv.Itoa(port))
			}
		}
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return net.JoinHostPort(host, strconv.Itoa(port))
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
