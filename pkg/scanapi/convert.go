package scanapi

import (
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
)

// ToProtoEvent 把控制面的内部事件转成协议事件。
//
// 这是「事件语言单一来源」原则的落点（协议文档 §4.3）：NDJSON、proto 与 SSE 三种
// 形态共用同一份载荷定义，任何一方加字段都必须同时改另外两处。
func ToProtoEvent(ev *scanstream.Event) *afrogv1.ScanEvent {
	if ev == nil {
		return nil
	}
	out := &afrogv1.ScanEvent{
		V:    ev.V,
		Node: ev.Node,
		Task: ev.Task,
		Seq:  ev.Seq,
		TsMs: ev.TsMs,
	}

	switch ev.Type {
	case scanstream.TypeStatus:
		if ev.Status != nil {
			out.Body = &afrogv1.ScanEvent_Status{Status: &afrogv1.StatusEvent{Status: ev.Status.Status}}
		}
	case scanstream.TypeScanInfo:
		if ev.ScanInfo != nil {
			out.Body = &afrogv1.ScanEvent_ScanInfo{ScanInfo: &afrogv1.ScanInfoEvent{
				TotalTargets: int32(ev.ScanInfo.TotalTargets),
				TotalPocs:    int32(ev.ScanInfo.TotalPocs),
				TotalScans:   int32(ev.ScanInfo.TotalScans),
				OobEnabled:   ev.ScanInfo.OOBEnabled,
				OobStatus:    ev.ScanInfo.OOBStatus,
			}}
		}
	case scanstream.TypeProgress:
		if ev.Progress != nil {
			out.Body = &afrogv1.ScanEvent_Progress{Progress: &afrogv1.ProgressEvent{
				Percent:   int32(ev.Progress.Percent),
				Finished:  ev.Progress.Finished,
				Total:     ev.Progress.Total,
				Rate:      int32(ev.Progress.Rate),
				ElapsedMs: ev.Progress.ElapsedMs,
			}}
		}
	case scanstream.TypePhase:
		if ev.Phase != nil {
			out.Body = &afrogv1.ScanEvent_Phase{Phase: &afrogv1.PhaseEvent{
				Phase:    ev.Phase.Phase,
				Status:   ev.Phase.Status,
				Finished: ev.Phase.Finished,
				Total:    ev.Phase.Total,
				Percent:  int32(ev.Phase.Percent),
			}}
		}
	case scanstream.TypeResult:
		if ev.Result != nil {
			out.Body = &afrogv1.ScanEvent_Result{Result: &afrogv1.ResultEvent{
				Severity: ev.Result.Severity,
				PocId:    ev.Result.PocID,
				PocName:  ev.Result.PocName,
				Target:   ev.Result.Target,
				Evidence: toProtoEvidence(ev.Result.Evidence),
			}}
		}
	case scanstream.TypePort:
		if ev.Port != nil {
			out.Body = &afrogv1.ScanEvent_Port{Port: &afrogv1.PortEvent{
				Host:       ev.Port.Host,
				Port:       int32(ev.Port.Port),
				Service:    ev.Port.Service,
				Product:    ev.Port.Product,
				Version:    ev.Port.Version,
				Device:     ev.Port.Device,
				Hostname:   ev.Port.Hostname,
				Os:         ev.Port.OS,
				Cpe:        ev.Port.CPE,
				Info:       ev.Port.Info,
				Tls:        ev.Port.TLS,
				Confidence: ev.Port.Confidence,
				Banner:     ev.Port.Banner,
				Extras:     ev.Port.Extras,
			}}
		}
	case scanstream.TypeWebProbe:
		if ev.WebProbe != nil {
			wp := &afrogv1.WebProbeEvent{
				Url:         ev.WebProbe.URL,
				Status:      int32(ev.WebProbe.Status),
				Title:       ev.WebProbe.Title,
				Fingerprint: ev.WebProbe.Fingerprint,
				Server:      ev.WebProbe.Server,
				PoweredBy:   ev.WebProbe.PoweredBy,
				Confidence:  ev.WebProbe.Confidence,
				Redirects:   ev.WebProbe.Redirects,
				FaviconHash: ev.WebProbe.FaviconHash,
				Waf:         ev.WebProbe.WAF,
			}
			if ev.WebProbe.TLS != nil {
				wp.Tls = &afrogv1.WebTLSInfo{
					Subject:  ev.WebProbe.TLS.Subject,
					Issuer:   ev.WebProbe.TLS.Issuer,
					NotAfter: ev.WebProbe.TLS.NotAfter,
					DnsNames: ev.WebProbe.TLS.DNSNames,
				}
			}
			if len(ev.WebProbe.Technologies) > 0 {
				wp.Technologies = make([]*afrogv1.WebTechnology, 0, len(ev.WebProbe.Technologies))
				for _, t := range ev.WebProbe.Technologies {
					wp.Technologies = append(wp.Technologies, &afrogv1.WebTechnology{
						Name:       t.Name,
						Version:    t.Version,
						Category:   t.Category,
						Cpe:        t.CPE,
						Confidence: t.Confidence,
					})
				}
			}
			out.Body = &afrogv1.ScanEvent_Webprobe{Webprobe: wp}
		}
	case scanstream.TypeHost:
		if ev.Host != nil {
			out.Body = &afrogv1.ScanEvent_Host{Host: &afrogv1.HostEvent{Host: ev.Host.Host, Proto: ev.Host.Proto}}
		}
	case scanstream.TypeLog:
		if ev.Log != nil {
			out.Body = &afrogv1.ScanEvent_Log{Log: &afrogv1.LogEvent{Level: ev.Log.Level, Text: ev.Log.Text}}
		}
	case scanstream.TypeDone:
		if ev.Done != nil {
			out.Body = &afrogv1.ScanEvent_Done{Done: &afrogv1.DoneEvent{
				Status:  ev.Done.Status,
				Summary: toProtoSummary(ev.Done.Summary),
			}}
		}
	case scanstream.TypeError:
		if ev.Error != nil {
			out.Body = &afrogv1.ScanEvent_Error{Error: &afrogv1.ErrorEvent{Code: ev.Error.Code, Message: ev.Error.Message}}
		}
	}

	return out
}

func toProtoEvidence(ev *scanstream.Evidence) *afrogv1.Evidence {
	if ev == nil {
		return nil
	}
	out := &afrogv1.Evidence{Extractors: ev.Extractors}
	for _, ex := range ev.Exchanges {
		out.Exchanges = append(out.Exchanges, &afrogv1.Exchange{
			Request:  ex.Request,
			Response: ex.Response,
			Matched:  ex.Matched,
		})
	}
	return out
}

func toProtoSummary(s *scanstream.Summary) *afrogv1.Summary {
	if s == nil {
		return nil
	}
	return &afrogv1.Summary{
		Executed:   s.Executed,
		Found:      s.Found,
		BySeverity: s.BySeverity,
		ElapsedMs:  s.ElapsedMs,
	}
}
