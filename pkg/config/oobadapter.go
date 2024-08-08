package config

import (
	"github.com/zan8in/gologger"
)

var (
	OOBCeyeio   = "ceyeio"
	OOBDnslogcn = "dnslogcn"
	OOBAlphalog = "alphalog"
	OOBXray     = "xray"
	OOBRevsuit  = "revsuit"
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
			gologger.Info().Msg("Ceyeio is not configured")
			return
		}
	case OOBDnslogcn:
		// dnslog.cn setting
		opt.OOB = OOBDnslogcn
		opt.OOBDomain = reverse.Dnslogcn.Domain
		if len(opt.OOBDomain) == 0 {
			gologger.Info().Msg("Dnslogcn is not configured")
			return
		}
	case OOBAlphalog:
		// alphalog setting
		opt.OOB = OOBAlphalog
		opt.OOBDomain = reverse.Alphalog.Domain
		opt.OOBApiUrl = reverse.Alphalog.ApiUrl
		if len(opt.OOBDomain) == 0 && len(opt.OOBApiUrl) == 0 {
			gologger.Info().Msg("Alphalog is not configured")
			return
		}
	case OOBXray:
		// xray setting
		opt.OOB = OOBXray
		opt.OOBDomain = reverse.Xray.Domain
		opt.OOBApiUrl = reverse.Xray.ApiUrl
		opt.OOBKey = reverse.Xray.XToken
		if len(opt.OOBDomain) == 0 && len(opt.OOBApiUrl) == 0 && len(opt.OOBKey) == 0 {
			gologger.Info().Msg("Xray is not configured")
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
			gologger.Info().Msg("Revsuit is not configured")
			return
		}
	default:
		// default ceyeio
		opt.OOB = OOBCeyeio
		opt.OOBKey = reverse.Ceye.ApiKey
		opt.OOBDomain = reverse.Ceye.Domain
		if len(opt.OOBKey) == 0 && len(opt.OOBDomain) == 0 {
			gologger.Info().Msg("Ceyeio is not configured")
			return
		}
	}
	gologger.Info().Msg("Using OOB Server: " + opt.OOB)

}
