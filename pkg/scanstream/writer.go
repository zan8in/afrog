package scanstream

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// flusher 覆盖 bufio.Writer 等带错误的刷新接口。
type flusher interface{ Flush() error }

// flusherNoErr 覆盖 http.Flusher 等无返回值的刷新接口。
type flusherNoErr interface{ Flush() }

// Writer 把事件以 NDJSON 逐行写入底层 io.Writer。
// 所有方法可并发调用：内部用互斥锁串行化，seq 在锁内自增，因此不会出现
// 交错行或 seq 重复。
type Writer struct {
	mu   sync.Mutex
	enc  *json.Encoder
	out  io.Writer
	node string
	task string
	seq  uint64
}

// NewWriter 创建事件流写入器。node 通常是 "local" 或节点 ID，task 为任务 ID。
func NewWriter(w io.Writer, node, task string) *Writer {
	enc := json.NewEncoder(w)
	// 目标与响应中常含 & < > 等字符，默认会被转义成 \u0026 造成消费方需要二次解码。
	enc.SetEscapeHTML(false)
	return &Writer{enc: enc, out: w, node: node, task: task}
}

// emit 在锁内组装信封、自增 seq 并写出单行 JSON。
func (w *Writer) emit(typ string, fill func(*Event)) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.seq++
	ev := Event{
		V:    Version,
		Node: w.node,
		Task: w.task,
		Seq:  w.seq,
		TsMs: time.Now().UnixMilli(),
		Type: typ,
	}
	if fill != nil {
		fill(&ev)
	}
	// json.Encoder.Encode 会在结尾补一个换行符，保证一条事件占一行。
	_ = w.enc.Encode(&ev)

	if f, ok := w.out.(flusher); ok {
		_ = f.Flush()
	} else if f, ok := w.out.(flusherNoErr); ok {
		f.Flush()
	}
}

// Status 发送状态变化事件。
func (w *Writer) Status(status string) {
	w.emit(TypeStatus, func(ev *Event) {
		ev.Status = &StatusEvent{Status: status}
	})
}

// ScanInfo 发送任务前置汇总事件。
func (w *Writer) ScanInfo(ev *ScanInfoEvent) {
	w.emit(TypeScanInfo, func(e *Event) {
		e.ScanInfo = ev
	})
}

// Progress 发送扫描级进度事件。
func (w *Writer) Progress(percent int, finished, total int64, rate int, elapsedMs int64) {
	w.emit(TypeProgress, func(ev *Event) {
		ev.Progress = &ProgressEvent{
			Percent:   percent,
			Finished:  finished,
			Total:     total,
			Rate:      rate,
			ElapsedMs: elapsedMs,
		}
	})
}

// Phase 发送阶段进度事件。
func (w *Writer) Phase(phase, status string, finished, total int64, percent int) {
	w.emit(TypePhase, func(ev *Event) {
		ev.Phase = &PhaseEvent{
			Phase:    phase,
			Status:   status,
			Finished: finished,
			Total:    total,
			Percent:  percent,
		}
	})
}

// Result 发送漏洞命中事件。
func (w *Writer) Result(ev *ResultEvent) {
	w.emit(TypeResult, func(e *Event) {
		e.Result = ev
	})
}

// Port 发送开放端口事件。
func (w *Writer) Port(host string, port int) {
	w.emit(TypePort, func(ev *Event) {
		ev.Port = &PortEvent{Host: host, Port: port}
	})
}

// WebProbe 发送 Web 探测事件。
func (w *Writer) WebProbe(ev *WebProbeEvent) {
	w.emit(TypeWebProbe, func(e *Event) {
		e.WebProbe = ev
	})
}

// Host 发送资产发现事件。
func (w *Writer) Host(host string) {
	w.emit(TypeHost, func(ev *Event) {
		ev.Host = &HostEvent{Host: host}
	})
}

// Log 发送诊断日志事件。
func (w *Writer) Log(level, text string) {
	w.emit(TypeLog, func(ev *Event) {
		ev.Log = &LogEvent{Level: level, Text: text}
	})
}

// Done 发送任务结束事件。
func (w *Writer) Done(status string, s *Summary) {
	w.emit(TypeDone, func(ev *Event) {
		ev.Done = &DoneEvent{Status: status, Summary: s}
	})
}

// Error 发送任务级错误事件。
func (w *Writer) Error(code, message string) {
	w.emit(TypeError, func(ev *Event) {
		ev.Error = &ErrorEvent{Code: code, Message: message}
	})
}

// Parse 解析一行 NDJSON 为事件，供本地进程执行器等消费方使用。
func Parse(line []byte) (Event, error) {
	var ev Event
	err := json.Unmarshal(line, &ev)
	return ev, err
}
