package web

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/gologger"
)

var (
	execOnce sync.Once
	execInst executor.Executor
	execErr  error
)

// getExecutor 返回全局扫描执行器。
//
// 每个扫描任务都会拉起一个独立的 afrog 子进程：sdk 的 HTTP 客户端、限速器与协议
// 探测缓存都是进程级全局状态，同进程内并发 scanner 会互相覆盖代理/超时/限速等参数。
// 进程隔离是这里唯一的正确做法，也是 Web 端并发扫描不再互相串扰的前提。
func getExecutor() (executor.Executor, error) {
	execOnce.Do(func() {
		lp, err := executor.NewLocalProcess()
		if err != nil {
			execErr = err
			return
		}
		// 子进程的 stderr 只进服务端日志：它的 stdout 已经被 NDJSON 事件流占用。
		lp.OnStderr = func(line string) {
			if strings.TrimSpace(line) != "" {
				gologger.Debug().Str("source", "scan-child").Msg(line)
			}
		}
		execInst = lp
	})
	return execInst, execErr
}

// buildScanSpec 把 Web 扫描请求映射为执行器规格。
//
// PoC 范围语义与 pkg/sdk 的映射保持一致：显式指定 poc_file/poc_ids、或 poc_source
// 明确指向某个来源时为「独占」（-P），未指定来源时把 curated/my 目录追加到内置
// PoC 之上（-ap）。
func buildScanSpec(req ScanCreateRequest, targets []string, pocPath string, appendPocs []string, useIDs bool) *executor.Spec {
	spec := &executor.Spec{
		Targets:           targets,
		AppendPocs:        appendPocs,
		Concurrency:       req.Concurrency,
		RateLimit:         req.RateLimit,
		TimeoutSeconds:    req.Timeout,
		Retries:           req.Retries,
		MaxHostError:      req.MaxHostError,
		Proxy:             strings.TrimSpace(req.Proxy),
		Smart:             req.Smart,
		PortScan:          req.PortScan || req.PortScanCompat,
		Ports:             strings.TrimSpace(req.Ports),
		SkipHostDiscovery: req.SkipHostDisc,
		WebFingerprint:    req.WebProbe || req.WebFingerprint,
		EnableOOB:         req.EnableOOB,
		OOBAdapter:        strings.TrimSpace(req.OOB),
		TaskName:          strings.TrimSpace(req.TaskName),
		Labels:            req.Labels,
	}

	exclusive := useIDs || strings.TrimSpace(pocPath) != ""
	switch strings.ToLower(strings.TrimSpace(req.PocSource)) {
	case "curated", "my":
		// 单一来源选择意味着「只扫这个来源」，而不是把它追加到内置 PoC 之上。
		exclusive = true
	}
	if exclusive {
		spec.AppendPocs = nil
		if v := strings.TrimSpace(pocPath); v != "" {
			spec.PocFile = v
		} else if len(appendPocs) > 0 {
			// -P 是独占语义且只接受一个路径。单一来源（curated/my）场景下调用方
			// 只会给出一个来源目录，直接把它当作 PocFile 交出去。
			spec.PocFile = appendPocs[0]
		}
	}

	// poc_ids 已经逐个落成文件并交给 -P，再叠加 -s/-S 只会缩窄范围，与旧行为一致地跳过。
	if !useIDs {
		spec.Search = strings.TrimSpace(req.Search)
		spec.Severity = strings.TrimSpace(req.Severity)
	}

	return spec
}

// runScanTask 拉起子进程、把 NDJSON 事件流翻译成前端既有的事件类型，最后收尾。
func runScanTask(m *TaskManager, t *Task) {
	ex, err := getExecutor()
	if err != nil {
		failScanStart(m, t, err)
		return
	}

	t.setStarted(time.Now())
	h, err := ex.Start(context.Background(), t.ID, t.spec)
	if err != nil {
		failScanStart(m, t, err)
		return
	}
	t.setHandle(h)

	for ev := range h.Events() {
		translateScanEvent(t, ev)
	}

	finalizeTask(m, t, t.terminalStatus(h.Err()))
}

// failScanStart 处理子进程拉不起来的情况：记下原因并通过 status 事件告知前端。
func failScanStart(m *TaskManager, t *Task, err error) {
	gologger.Warning().Str("taskId", t.ID).Str("error", err.Error()).Msg("scan task failed to start")
	t.setErrText(err.Error())
	finalizeTask(m, t, TaskFailed)
}

// translateScanEvent 把引擎的 NDJSON 事件翻译成前端既有的事件类型。
// 事件名与字段刻意保持不变，前端无需任何改动即可继续消费。
func translateScanEvent(t *Task, ev *scanstream.Event) {
	ts := time.Now().UnixMilli()
	switch ev.Type {
	case scanstream.TypeStatus:
		if ev.Status == nil {
			return
		}
		publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": ev.Status.Status}})

	case scanstream.TypeScanInfo:
		if ev.ScanInfo == nil {
			return
		}
		t.setScanInfo(ev.ScanInfo)
		publish(t, ScanEvent{Type: "scan_info", Data: scanInfoPayload(t, ev.ScanInfo)})

	case scanstream.TypeProgress:
		if ev.Progress == nil {
			return
		}
		t.setProgress(ev.Progress)
		publish(t, ScanEvent{Type: "progress", Data: progressPayload(t, ev.Progress)})

	case scanstream.TypePhase:
		if ev.Phase == nil {
			return
		}
		publish(t, ScanEvent{Type: "phase_progress", Data: map[string]interface{}{
			"phase":    ev.Phase.Phase,
			"status":   ev.Phase.Status,
			"finished": ev.Phase.Finished,
			"total":    ev.Phase.Total,
			"percent":  ev.Phase.Percent,
			"ts":       ts,
		}})

	case scanstream.TypeResult:
		if ev.Result == nil {
			return
		}
		t.addHit(strings.ToLower(ev.Result.Severity))
		publish(t, ScanEvent{Type: "result", Data: map[string]interface{}{
			"target":   ev.Result.Target,
			"severity": ev.Result.Severity,
			"poc": map[string]string{
				"id":   ev.Result.PocID,
				"name": ev.Result.PocName,
			},
			"message": fmt.Sprintf("命中 %s", ev.Result.Severity),
			"ts":      ts,
		}})

	case scanstream.TypePort:
		if ev.Port == nil {
			return
		}
		publish(t, ScanEvent{Type: "port", Data: map[string]interface{}{
			"host": ev.Port.Host,
			"port": ev.Port.Port,
			"ts":   ts,
		}})

	case scanstream.TypeHost:
		if ev.Host == nil {
			return
		}
		publish(t, ScanEvent{Type: "host", Data: map[string]interface{}{
			"host": ev.Host.Host,
			"ts":   ts,
		}})

	case scanstream.TypeWebProbe:
		if ev.WebProbe == nil {
			return
		}
		publish(t, ScanEvent{Type: "webprobe", Data: map[string]interface{}{
			"url":         ev.WebProbe.URL,
			"status":      ev.WebProbe.Status,
			"title":       ev.WebProbe.Title,
			"fingerprint": ev.WebProbe.Fingerprint,
			"ts":          ts,
		}})

	case scanstream.TypeLog:
		// 诊断日志只进服务端日志，前端不消费该事件类型。
		if ev.Log != nil {
			gologger.Debug().Str("taskId", t.ID).Str("level", ev.Log.Level).Msg(ev.Log.Text)
		}

	case scanstream.TypeDone:
		if ev.Done == nil {
			return
		}
		t.setDone(ev.Done.Status, ev.Done.Summary)

	case scanstream.TypeError:
		if ev.Error == nil {
			return
		}
		gologger.Warning().Str("taskId", t.ID).Str("code", ev.Error.Code).Msg(ev.Error.Message)
		t.setErrText(ev.Error.Message)
	}
}

// progressPayload 组装前端 progress 事件的载荷。
// 子进程不上报速率，这里用父进程的墙上时间计算，保持前端 req/s 展示可用。
func progressPayload(t *Task, p *scanstream.ProgressEvent) map[string]interface{} {
	return map[string]interface{}{
		"percent":   p.Percent,
		"finished":  p.Finished,
		"total":     p.Total,
		"rate":      calcRate(t.started(), p.Finished),
		"elapsedMs": p.ElapsedMs,
	}
}

// scanInfoPayload 组装前端 scan_info 事件的载荷，目标列表按既有约定只展示前 5 个。
func scanInfoPayload(t *Task, info *scanstream.ScanInfoEvent) map[string]interface{} {
	displayTargets := t.getTargets()
	if len(displayTargets) > 5 {
		displayTargets = displayTargets[:5]
	}
	return map[string]interface{}{
		"total_targets": info.TotalTargets,
		"total_pocs":    info.TotalPocs,
		"total_scans":   info.TotalScans,
		"targets":       displayTargets,
		"oob_enabled":   info.OOBEnabled,
		"oob_status":    info.OOBStatus,
		"ts":            time.Now().UnixMilli(),
	}
}
