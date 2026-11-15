package config

import "strings"

var (
	OOBCeyeio     = "ceyeio"
	OOBDnslogcn   = "dnslogcn"
	OOBAlphalog   = "alphalog"
	OOBXray       = "xray"
	OOBRevsuit    = "revsuit"
	OOBInteractsh = "interactsh"
)

func IsOOBAdapter(oob string) bool {
	switch oob {
	case OOBCeyeio:
		return true
	case OOBDnslogcn:
		return true
	case OOBAlphalog:
		return true
	case OOBXray:
		return true
	case OOBRevsuit:
		return true
	case OOBInteractsh:
		return true
	default:
		return false
	}
}

func (opt *Options) SetOOBAdapter() {
	reverse := opt.Config.Reverse
	switch opt.OOB {
	case OOBCeyeio:
		// ceyeio setting
		opt.OOB = OOBCeyeio
		opt.OOBKey = reverse.Ceye.ApiKey
		opt.OOBDomain = reverse.Ceye.Domain
		if len(opt.OOBKey) == 0 && len(opt.OOBDomain) == 0 {
			// gologger.Info().Msg("Ceyeio is not configured")
			return
		}
	case OOBDnslogcn:
		// dnslog.cn setting
		opt.OOB = OOBDnslogcn
		opt.OOBDomain = reverse.Dnslogcn.Domain
		if len(opt.OOBDomain) == 0 {
			// gologger.Info().Msg("Dnslogcn is not configured")
			return
		}
	case OOBAlphalog:
		// alphalog setting
		opt.OOB = OOBAlphalog
		opt.OOBDomain = reverse.Alphalog.Domain
		opt.OOBApiUrl = reverse.Alphalog.ApiUrl
		if len(opt.OOBDomain) == 0 && len(opt.OOBApiUrl) == 0 {
			// gologger.Info().Msg("Alphalog is not configured")
			return
		}
	case OOBXray:
		// xray setting
		opt.OOB = OOBXray
		opt.OOBDomain = reverse.Xray.Domain
		opt.OOBApiUrl = reverse.Xray.ApiUrl
		opt.OOBKey = reverse.Xray.XToken
		if len(opt.OOBDomain) == 0 && len(opt.OOBApiUrl) == 0 && len(opt.OOBKey) == 0 {
			// gologger.Info().Msg("Xray is not configured")
			return
		}
	case OOBRevsuit:
		// revsuit setting
		opt.OOB = OOBRevsuit
		opt.OOBKey = reverse.Revsuit.Token
		opt.OOBDomain = reverse.Revsuit.DnsDomain
		opt.OOBHttpUrl = reverse.Revsuit.HttpUrl
		opt.OOBApiUrl = reverse.Revsuit.ApiUrl
		if len(opt.OOBKey) == 0 && len(opt.OOBDomain) == 0 && len(opt.OOBHttpUrl) == 0 && len(opt.OOBApiUrl) == 0 {
			// gologger.Info().Msg("Revsuit is not configured")
			return
		}
	case OOBInteractsh:
		opt.OOB = OOBInteractsh
		opt.OOBDomain = reverse.Interactsh.Server
		opt.OOBKey = reverse.Interactsh.Token
		if len(opt.OOBDomain) == 0 {
			opt.OOBDomain = "oast.pro"
		}
	default:
		// default ceyeio
		opt.OOB = OOBCeyeio
		opt.OOBKey = reverse.Ceye.ApiKey
		opt.OOBDomain = reverse.Ceye.Domain
		if len(opt.OOBKey) == 0 && len(opt.OOBDomain) == 0 {
			// gologger.Info().Msg("Ceyeio is not configured")
			return
		}
	}
	// gologger.Info().Msg("Using OOB Server: " + opt.OOB)

}

// OOBConnectorParams 是构造一个反连适配器所需的连接参数。
type OOBConnectorParams struct {
	Adapter string
	Key     string
	Domain  string
	HTTPURL string
	APIURL  string
}

// ResolveOOBConnector 把「适配器名 + reverse 配置」解析成连接参数。
//
// 与 Options.SetOOBAdapter 同一份映射语义，供非 CLI 场景（长驻的工具面服务）复用，
// 避免同一套「适配器名 → 凭据字段」的对照表出现第三份。adapter 为空、取值未识别、
// 或该适配器的凭据全为空时 ok 为假——调用方据此 fail-closed，而不是拿一份空凭据去连。
func ResolveOOBConnector(adapter string, r Reverse) (OOBConnectorParams, bool) {
	name := strings.ToLower(strings.TrimSpace(adapter))
	if name == "" {
		return OOBConnectorParams{}, false
	}
	p := OOBConnectorParams{Adapter: name}
	switch name {
	case OOBCeyeio:
		p.Key, p.Domain = r.Ceye.ApiKey, r.Ceye.Domain
	case OOBDnslogcn:
		p.Domain = r.Dnslogcn.Domain
	case OOBAlphalog:
		p.Domain, p.APIURL = r.Alphalog.Domain, r.Alphalog.ApiUrl
	case OOBXray:
		p.Domain, p.APIURL, p.Key = r.Xray.Domain, r.Xray.ApiUrl, r.Xray.XToken
	case OOBRevsuit:
		p.Key, p.Domain = r.Revsuit.Token, r.Revsuit.DnsDomain
		p.HTTPURL, p.APIURL = r.Revsuit.HttpUrl, r.Revsuit.ApiUrl
	case OOBInteractsh:
		p.Domain, p.Key = r.Interactsh.Server, r.Interactsh.Token
		if p.Domain == "" {
			p.Domain = "oast.pro"
		}
	default:
		return OOBConnectorParams{}, false
	}
	if p.Key == "" && p.Domain == "" && p.HTTPURL == "" && p.APIURL == "" {
		return OOBConnectorParams{}, false
	}
	return p, true
}
