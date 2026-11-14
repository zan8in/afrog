package scanapi

import (
	"encoding/json"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/evidence"
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

// FromProtoEvent 把协议事件还原成控制面的内部事件。
//
// 与 ToProtoEvent 配对：gRPC 消费端（agent / 集群回传）拿到的仍是 scanstream 事件，
// 下游的落库、NDJSON 输出、证据读取都只有一套消费者实现。
// 无法表示的载荷返回 nil，而不是返回一个类型不明的半成品事件。
func FromProtoEvent(in *afrogv1.ScanEvent) *scanstream.Event {
	if in == nil {
		return nil
	}
	out := &scanstream.Event{
		V:    in.GetV(),
		Node: in.GetNode(),
		Task: in.GetTask(),
		Seq:  in.GetSeq(),
		TsMs: in.GetTsMs(),
	}

	switch body := in.GetBody().(type) {
	case *afrogv1.ScanEvent_Status:
		out.Type = scanstream.TypeStatus
		out.Status = &scanstream.StatusEvent{Status: body.Status.GetStatus()}
	case *afrogv1.ScanEvent_ScanInfo:
		out.Type = scanstream.TypeScanInfo
		out.ScanInfo = &scanstream.ScanInfoEvent{
			TotalTargets: int(body.ScanInfo.GetTotalTargets()),
			TotalPocs:    int(body.ScanInfo.GetTotalPocs()),
			TotalScans:   int(body.ScanInfo.GetTotalScans()),
			OOBEnabled:   body.ScanInfo.GetOobEnabled(),
			OOBStatus:    body.ScanInfo.GetOobStatus(),
		}
	case *afrogv1.ScanEvent_Progress:
		out.Type = scanstream.TypeProgress
		out.Progress = &scanstream.ProgressEvent{
			Percent:   int(body.Progress.GetPercent()),
			Finished:  body.Progress.GetFinished(),
			Total:     body.Progress.GetTotal(),
			Rate:      int(body.Progress.GetRate()),
			ElapsedMs: body.Progress.GetElapsedMs(),
		}
	case *afrogv1.ScanEvent_Phase:
		out.Type = scanstream.TypePhase
		out.Phase = &scanstream.PhaseEvent{
			Phase:    body.Phase.GetPhase(),
			Status:   body.Phase.GetStatus(),
			Finished: body.Phase.GetFinished(),
			Total:    body.Phase.GetTotal(),
			Percent:  int(body.Phase.GetPercent()),
		}
	case *afrogv1.ScanEvent_Result:
		out.Type = scanstream.TypeResult
		out.Result = &scanstream.ResultEvent{
			Severity: body.Result.GetSeverity(),
			PocID:    body.Result.GetPocId(),
			PocName:  body.Result.GetPocName(),
			Target:   body.Result.GetTarget(),
			Evidence: fromProtoEvidence(body.Result.GetEvidence()),
		}
	case *afrogv1.ScanEvent_Port:
		out.Type = scanstream.TypePort
		out.Port = &scanstream.PortEvent{
			Host:       body.Port.GetHost(),
			Port:       int(body.Port.GetPort()),
			Service:    body.Port.GetService(),
			Product:    body.Port.GetProduct(),
			Version:    body.Port.GetVersion(),
			Device:     body.Port.GetDevice(),
			Hostname:   body.Port.GetHostname(),
			OS:         body.Port.GetOs(),
			CPE:        body.Port.GetCpe(),
			Info:       body.Port.GetInfo(),
			TLS:        body.Port.GetTls(),
			Confidence: body.Port.GetConfidence(),
			Banner:     body.Port.GetBanner(),
			Extras:     copyStringMap(body.Port.GetExtras()),
		}
	case *afrogv1.ScanEvent_Webprobe:
		out.Type = scanstream.TypeWebProbe
		wp := &scanstream.WebProbeEvent{
			URL:         body.Webprobe.GetUrl(),
			Status:      int(body.Webprobe.GetStatus()),
			Title:       body.Webprobe.GetTitle(),
			Server:      body.Webprobe.GetServer(),
			PoweredBy:   body.Webprobe.GetPoweredBy(),
			Fingerprint: body.Webprobe.GetFingerprint(),
			Confidence:  body.Webprobe.GetConfidence(),
			Redirects:   body.Webprobe.GetRedirects(),
			FaviconHash: body.Webprobe.GetFaviconHash(),
			WAF:         body.Webprobe.GetWaf(),
		}
		if tls := body.Webprobe.GetTls(); tls != nil {
			wp.TLS = &scanstream.WebTLSEvent{
				Subject:  tls.GetSubject(),
				Issuer:   tls.GetIssuer(),
				NotAfter: tls.GetNotAfter(),
				DNSNames: tls.GetDnsNames(),
			}
		}
		if techs := body.Webprobe.GetTechnologies(); len(techs) > 0 {
			wp.Technologies = make([]scanstream.WebTechnologyEvent, 0, len(techs))
			for _, t := range techs {
				wp.Technologies = append(wp.Technologies, scanstream.WebTechnologyEvent{
					Name:       t.GetName(),
					Version:    t.GetVersion(),
					Category:   t.GetCategory(),
					CPE:        t.GetCpe(),
					Confidence: t.GetConfidence(),
				})
			}
		}
		out.WebProbe = wp
	case *afrogv1.ScanEvent_Host:
		out.Type = scanstream.TypeHost
		out.Host = &scanstream.HostEvent{Host: body.Host.GetHost(), Proto: body.Host.GetProto()}
	case *afrogv1.ScanEvent_Log:
		out.Type = scanstream.TypeLog
		out.Log = &scanstream.LogEvent{Level: body.Log.GetLevel(), Text: body.Log.GetText()}
	case *afrogv1.ScanEvent_Done:
		out.Type = scanstream.TypeDone
		out.Done = &scanstream.DoneEvent{
			Status:  body.Done.GetStatus(),
			Summary: fromProtoSummary(body.Done.GetSummary()),
		}
	case *afrogv1.ScanEvent_Error:
		out.Type = scanstream.TypeError
		out.Error = &scanstream.ErrorEvent{Code: body.Error.GetCode(), Message: body.Error.GetMessage()}
	default:
		// 空载荷或本版本不认识的新载荷：调用方无法按类型分发，返回 nil 更明确。
		return nil
	}

	return out
}

// fromProtoEvidence 还原证据。native_json 解析失败时退回 exchanges/extractors：
// 老控制面拿到新节点的事件时仍能展示原始报文，不会整条丢掉。
func fromProtoEvidence(in *afrogv1.Evidence) *scanstream.Evidence {
	if in == nil {
		return nil
	}
	out := &scanstream.Evidence{}
	if exchanges := in.GetExchanges(); len(exchanges) > 0 {
		out.Exchanges = make([]scanstream.Exchange, 0, len(exchanges))
		for _, ex := range exchanges {
			out.Exchanges = append(out.Exchanges, scanstream.Exchange{
				Request:  ex.GetRequest(),
				Response: ex.GetResponse(),
				Matched:  ex.GetMatched(),
			})
		}
	}
	out.Extractors = copyStringMap(in.GetExtractors())
	if raw := strings.TrimSpace(in.GetNativeJson()); raw != "" {
		var native evidence.Evidence
		if err := json.Unmarshal([]byte(raw), &native); err == nil {
			out.Native = &native
		}
	}
	return out
}

func fromProtoSummary(s *afrogv1.Summary) *scanstream.Summary {
	if s == nil {
		return nil
	}
	return &scanstream.Summary{
		Executed:   s.GetExecuted(),
		Found:      s.GetFound(),
		BySeverity: s.GetBySeverity(),
		ElapsedMs:  s.GetElapsedMs(),
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
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
	// 原生证据以 JSON 透传：契约只在 pkg/evidence 维护一份，proto 不再镜像。
	if ev.Native != nil {
		if b, err := json.Marshal(ev.Native); err == nil {
			out.NativeJson = string(b)
		}
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
