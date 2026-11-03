package passive

import (
	"sort"
	"time"
)

// ActiveJobState 描述一条事务在检测流水线中的当前位置。
type ActiveJobState string

const (
	// ActiveQueued 事务已通过门控，正排在检测队列里等待 worker 领取。
	ActiveQueued ActiveJobState = "queued"
	// ActiveDetecting 事务正被检测池执行（正在重放与判定）。
	ActiveDetecting ActiveJobState = "detecting"
)

// ActiveJob 是一条「已进入检测流水线但尚未完成」的事务摘要。
//
// 「检测积压 / 检测在途」两个瞬时数字背后究竟是哪些请求、各自等了多久，
// 只有这里能回答。这些请求还没有产出判定结论，因此不会出现在实时流量列表里。
type ActiveJob struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	URL    string         `json:"url"`
	Host   string         `json:"host"`
	State  ActiveJobState `json:"state"`
	// QueuedMs 是在检测队列里等待的毫秒数；已进入检测的则记录其实际等待时长。
	QueuedMs int64 `json:"queued_ms"`
	// DetectingMs 是正在检测已持续的毫秒数，仅 state=detecting 时非零。
	DetectingMs int64    `json:"detecting_ms"`
	Detectors   []string `json:"detectors,omitempty"`
}

// activeEntry 是登记表内部的记录：字段在入队时一次性抓取，读取时不再触碰事务。
type activeEntry struct {
	id          string
	method      string
	url         string
	host        string
	detectors   []string
	state       ActiveJobState
	queuedAt    time.Time
	detectingAt time.Time
}

// registerActive 登记一条已通过门控、准备进入检测队列的事务。
//
// 必须在投递到 detectJobs 之前调用：若先投递，检测池可能在登记前就跑完并注销，
// 留下一条永不释放的僵尸记录。
func (e *Engine) registerActive(job *detectJob) {
	if job == nil || job.tx == nil {
		return
	}
	entry := &activeEntry{
		id:       job.tx.ID,
		state:    ActiveQueued,
		queuedAt: time.Now(),
	}
	if req := job.tx.Request; req != nil {
		entry.method = req.Method
		if req.URL != nil {
			entry.url = req.URL.String()
			entry.host = req.URL.Host
		}
	}
	for _, d := range job.detectors {
		if d != nil {
			entry.detectors = append(entry.detectors, d.Name())
		}
	}

	e.activeMu.Lock()
	if e.active == nil {
		e.active = make(map[string]*activeEntry)
	}
	e.active[job.tx.ID] = entry
	e.activeMu.Unlock()
}

// markActiveDetecting 把已领取的事务从「排队」推进到「检测中」。
func (e *Engine) markActiveDetecting(id string) {
	e.activeMu.Lock()
	if entry, ok := e.active[id]; ok {
		entry.state = ActiveDetecting
		entry.detectingAt = time.Now()
	}
	e.activeMu.Unlock()
}

// unregisterActive 移除一条已结束（或未能入队）的事务。
func (e *Engine) unregisterActive(id string) {
	e.activeMu.Lock()
	delete(e.active, id)
	e.activeMu.Unlock()
}

// ActiveJobs 返回当前排队与正在检测的事务摘要。
//
// queued 按等待时长降序——等最久的排最前，最该被关注；
// detecting 按已检测时长降序，便于一眼看出哪条检测卡住了。
func (e *Engine) ActiveJobs() (queued, detecting []ActiveJob) {
	e.activeMu.Lock()
	defer e.activeMu.Unlock()

	now := time.Now()
	for _, entry := range e.active {
		job := ActiveJob{
			ID:        entry.id,
			Method:    entry.method,
			URL:       entry.url,
			Host:      entry.host,
			State:     entry.state,
			Detectors: entry.detectors,
		}
		if entry.state == ActiveDetecting {
			job.QueuedMs = entry.detectingAt.Sub(entry.queuedAt).Milliseconds()
			job.DetectingMs = now.Sub(entry.detectingAt).Milliseconds()
			detecting = append(detecting, job)
			continue
		}
		job.QueuedMs = now.Sub(entry.queuedAt).Milliseconds()
		queued = append(queued, job)
	}
	sort.Slice(queued, func(i, j int) bool { return queued[i].QueuedMs > queued[j].QueuedMs })
	sort.Slice(detecting, func(i, j int) bool { return detecting[i].DetectingMs > detecting[j].DetectingMs })
	return queued, detecting
}
