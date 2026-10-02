package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// 定时/计划扫描（Curated 会员能力）：按「频率预设」周期性地对某个项目（或一组
// 目标）重跑同一份扫描配置。
//
// 刻意不引入 cron：结构化字段足够表达「每 N 小时 / 每天 HH:MM / 每周几 HH:MM」，
// 前端据此渲染成自然语言，后端只做 next_run_at 的推算，避免多一份表达式解析器。
// 起跑复用 launchScan，与「手动起扫」共享全部行为（目标解析、资产沉淀、通知登记）。

const (
	freqHourly = "hourly"
	freqDaily  = "daily"
	freqWeekly = "weekly"

	// scheduleTimeLayout 与 result.created 等历史字段保持一致，便于人工比对。
	scheduleTimeLayout = "2006-01-02 15:04:05"

	// scheduleTickInterval 是调度器轮询间隔。频率预设的最小粒度是「小时」，
	// 半分钟一次足够精确，也不会带来可观测的额外开销。
	scheduleTickInterval = 30 * time.Second

	// maxSchedules 限制单实例的计划数量，防止界面与调度开销无限膨胀。
	maxSchedules = 100
)

// Schedule 是一条计划扫描。
//
// Scan 直接复用 ScanCreateRequest：起跑时原样交给 launchScan，保证「手动起扫」与
// 「计划起扫」的参数口径完全一致，也省掉一份并行字段表。
type Schedule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Freq          string `json:"freq"`                     // hourly | daily | weekly
	IntervalHours int    `json:"interval_hours,omitempty"` // hourly：每 N 小时
	AtTime        string `json:"at_time,omitempty"`        // daily / weekly：HH:MM
	Weekday       int    `json:"weekday,omitempty"`        // weekly：0=周日 .. 6=周六

	Scan ScanCreateRequest `json:"scan"`

	// NodeURL 是本次计划的执行节点；为空表示本机执行。非空时由发起端把扫描派发
	// 给该同伴（项目在派发前于本地解析成具体目标），属会员能力。
	NodeURL string `json:"node_url,omitempty"`

	// NextRunAt 是下一次计划执行时间（本地时间，scheduleTimeLayout）。
	NextRunAt  string `json:"next_run_at"`
	LastRunAt  string `json:"last_run_at,omitempty"`
	LastTaskID string `json:"last_task_id,omitempty"`
	// LastStatus 是最近一次调度的结果：started | failed | skipped。
	LastStatus string `json:"last_status,omitempty"`
	LastError  string `json:"last_error,omitempty"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// scheduleView 是返回给前端的计划视图：附带目标来源的展示信息。
type scheduleView struct {
	Schedule
	ProjectName string `json:"project_name,omitempty"`
	// NodeName 是执行节点的展示名（NodeURL 为空时也为空，界面显示「本机」）。
	NodeName    string   `json:"node_name,omitempty"`
	TargetCount int      `json:"target_count"`
	Preview     []string `json:"preview"`
}

type scheduleStore struct {
	Items []Schedule `json:"items"`
}

// scheduleMu 串行化配置读写与调度推进：调度器与 HTTP 处理器可能同时访问同一个文件。
var scheduleMu sync.Mutex

func schedulesFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "schedules.json"), nil
}

func loadSchedules() (*scheduleStore, error) {
	path, err := schedulesFilePath()
	if err != nil {
		return nil, err
	}
	store := &scheduleStore{Items: []Schedule{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, store); err != nil {
			return nil, err
		}
	}
	if store.Items == nil {
		store.Items = []Schedule{}
	}
	return store, nil
}

func saveSchedules(store *scheduleStore) error {
	path, err := schedulesFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// findScheduleIndex 返回指定计划的索引，找不到返回 -1。调用方需持有 scheduleMu。
func findScheduleIndex(store *scheduleStore, id string) int {
	id = strings.TrimSpace(id)
	for i := range store.Items {
		if store.Items[i].ID == id {
			return i
		}
	}
	return -1
}

// normalizeSchedule 收敛频率字段：丢弃与当前频率无关的值，避免脏数据在切换
// 频率后残留（例如从每周切到每小时，weekday 不该继续参与计算）。
func normalizeSchedule(s *Schedule) {
	s.Name = strings.TrimSpace(s.Name)
	s.NodeURL = normalizePeerURL(s.NodeURL)
	s.Freq = strings.ToLower(strings.TrimSpace(s.Freq))
	switch s.Freq {
	case freqHourly:
		if s.IntervalHours <= 0 {
			s.IntervalHours = 1
		}
		if s.IntervalHours > 168 {
			s.IntervalHours = 168
		}
		s.AtTime = ""
		s.Weekday = 0
	case freqDaily:
		s.AtTime = normalizeClock(s.AtTime)
		s.IntervalHours = 0
		s.Weekday = 0
	case freqWeekly:
		s.AtTime = normalizeClock(s.AtTime)
		s.IntervalHours = 0
		if s.Weekday < 0 || s.Weekday > 6 {
			s.Weekday = 0
		}
	}
	s.NextRunAt = computeNextRun(*s, time.Now()).Format(scheduleTimeLayout)
}

// normalizeClock 把 "H:M" / "HH:MM" 规范化成 "HH:MM"，非法值退回 09:00。
func normalizeClock(v string) string {
	h, m, ok := parseClock(v)
	if !ok {
		return "09:00"
	}
	return time.Date(2000, 1, 1, h, m, 0, 0, time.Local).Format("15:04")
}

// parseClock 解析 "HH:MM"；返回 ok=false 表示格式非法。
func parseClock(v string) (hour, minute int, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, false
	}
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := atoiStrict(parts[0])
	m, err2 := atoiStrict(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

func atoiStrict(s string) (int, error) {
	n := 0
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, os.ErrInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, os.ErrInvalid
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// computeNextRun 推算 from 之后的下一次执行时间。频率非法时保守地按「一天后」处理。
func computeNextRun(s Schedule, from time.Time) time.Time {
	switch s.Freq {
	case freqHourly:
		n := s.IntervalHours
		if n <= 0 {
			n = 1
		}
		return from.Add(time.Duration(n) * time.Hour).Truncate(time.Minute)
	case freqDaily:
		h, m, _ := parseClock(s.AtTime)
		next := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		if !next.After(from) {
			next = next.AddDate(0, 0, 1)
		}
		return next
	case freqWeekly:
		h, m, _ := parseClock(s.AtTime)
		next := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		days := (s.Weekday - int(from.Weekday()) + 7) % 7
		next = next.AddDate(0, 0, days)
		if !next.After(from) {
			next = next.AddDate(0, 0, 7)
		}
		return next
	default:
		return from.Add(24 * time.Hour).Truncate(time.Minute)
	}
}

// toScheduleView 组装计划视图：项目计划带项目名与资产数，临时目标计划带目标预览。
func toScheduleView(s Schedule) scheduleView {
	view := scheduleView{Schedule: s, Preview: []string{}}
	if nodeURL := strings.TrimSpace(s.NodeURL); nodeURL != "" {
		view.NodeName = nodeURL
		if p, ok := findClusterPeer(nodeURL); ok {
			view.NodeName = p.Name
		}
	}
	if pid := strings.TrimSpace(s.Scan.ProjectID); pid != "" {
		if p, ok := findProject(pid); ok {
			view.ProjectName = p.Name
		}
		if n, err := sqlite.CountProjectAssets(pid); err == nil {
			view.TargetCount = int(n)
		}
		if preview, err := sqlite.ProjectAssetPreview(pid, 3); err == nil {
			view.Preview = preview
		}
		return view
	}
	view.TargetCount = len(s.Scan.Targets)
	if len(s.Scan.Targets) > 3 {
		view.Preview = append([]string(nil), s.Scan.Targets[:3]...)
	} else {
		view.Preview = append([]string(nil), s.Scan.Targets...)
	}
	return view
}

// -----------------------
// 调度器
// -----------------------

type scheduleScheduler struct {
	stop chan struct{}
	once sync.Once
}

var globalScheduler *scheduleScheduler

// StartScheduler 启动计划扫描调度器。启动时会做一次立即检查，
// 用于补齐进程停机期间错过的计划（只补跑一次，随后按频率续排）。
func StartScheduler() {
	if globalScheduler != nil {
		return
	}
	s := &scheduleScheduler{stop: make(chan struct{})}
	globalScheduler = s
	go s.run()
}

// StopScheduler 停止调度器，可重复调用。
func StopScheduler() {
	if globalScheduler == nil {
		return
	}
	globalScheduler.once.Do(func() { close(globalScheduler.stop) })
	globalScheduler = nil
}

func (s *scheduleScheduler) run() {
	gologger.Info().Msg("计划扫描调度器已启动")
	ticker := time.NewTicker(scheduleTickInterval)
	defer ticker.Stop()

	s.tick()
	for {
		select {
		case <-s.stop:
			gologger.Info().Msg("计划扫描调度器已停止")
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

// tick 扫一遍到期的计划。任何一条计划的失败都不影响其余计划。
func (s *scheduleScheduler) tick() {
	now := time.Now()

	scheduleMu.Lock()
	store, err := loadSchedules()
	if err != nil {
		scheduleMu.Unlock()
		gologger.Warning().Msgf("调度器读取计划失败: %v", err)
		return
	}

	type dueItem struct {
		id      string
		name    string
		nodeURL string
		scan    ScanCreateRequest
	}
	dueCount := 0
	changed := false

	// 先把到期项挑出来，没有任何到期项时连会员状态都不必查（每 30s 一次的空转）。
	for i := range store.Items {
		sc := &store.Items[i]
		if !sc.Enabled {
			continue
		}

		next, parseErr := time.ParseInLocation(scheduleTimeLayout, sc.NextRunAt, time.Local)
		if parseErr != nil {
			// next_run_at 缺失/损坏时补一个，避免这条计划永远卡住。
			sc.NextRunAt = computeNextRun(*sc, now).Format(scheduleTimeLayout)
			sc.UpdatedAt = now.Format(scheduleTimeLayout)
			changed = true
			continue
		}
		if next.After(now) {
			continue
		}

		dueCount++
	}

	if dueCount == 0 {
		if changed {
			if err := saveSchedules(store); err != nil {
				gologger.Warning().Msgf("调度器保存计划失败: %v", err)
			}
		}
		scheduleMu.Unlock()
		return
	}

	curated := curatedRole() == "curated"

	var launch []dueItem
	for i := range store.Items {
		sc := &store.Items[i]
		if !sc.Enabled || !isDue(*sc, now) {
			continue
		}

		// 先推进下次时间（并落盘）再起跑，确保同一时刻只会触发一次。
		sc.NextRunAt = computeNextRun(*sc, now).Format(scheduleTimeLayout)
		sc.LastRunAt = now.Format(scheduleTimeLayout)
		sc.UpdatedAt = now.Format(scheduleTimeLayout)
		changed = true

		if !curated {
			// 会员到期后计划自动停摆：推进时间并如实记录原因，界面可见。
			sc.LastStatus = "skipped"
			sc.LastError = "定时扫描为 Curated 会员专属"
			continue
		}
		sc.LastStatus = "started"
		sc.LastError = ""
		launch = append(launch, dueItem{id: sc.ID, name: sc.Name, nodeURL: sc.NodeURL, scan: sc.Scan})
	}

	if changed {
		if err := saveSchedules(store); err != nil {
			gologger.Warning().Msgf("调度器保存计划失败: %v", err)
		}
	}
	scheduleMu.Unlock()

	for _, item := range launch {
		taskID, _, err := launchScheduledScan(item.id, item.name, item.nodeURL, item.scan)
		recordScheduleRun(item.id, taskID, err)
		if err != nil {
			gologger.Warning().Msgf("计划起扫失败: plan=%s name=%s err=%v", item.id, item.name, err)
			continue
		}
		gologger.Info().Msgf("计划起扫: plan=%s name=%s taskId=%s", item.id, item.name, taskID)
	}
}

// launchScheduledScan 以「计划」来源起扫：任务名缺失时用计划名兜底，
// 这样任务列表里能直接看出是哪条计划触发的。
//
// nodeURL 非空表示这条计划配置了执行节点：扫描交给该同伴执行，本机只留一条镜像
// 记录（来源为 remote，带 schedule_id 便于追溯）。
func launchScheduledScan(id, name, nodeURL string, scan ScanCreateRequest) (string, ScanInitInfo, error) {
	if strings.TrimSpace(scan.TaskName) == "" {
		scan.TaskName = name
	}
	if nodeURL = normalizePeerURL(nodeURL); nodeURL != "" {
		peer, ok := findClusterPeer(nodeURL)
		if !ok {
			return "", ScanInitInfo{}, fmt.Errorf("执行节点不在集群配置中，请先在概览页「编辑节点」里登记")
		}
		item, err := dispatchRemoteScan(peer, scan, scanOrigin{ScheduleID: id})
		if err != nil {
			return "", ScanInitInfo{}, err
		}
		return item.TaskID, ScanInitInfo{TotalTargets: len(item.Targets), Targets: item.Targets}, nil
	}
	return launchScan(scan, scanOrigin{Source: scanSourceSchedule, ScheduleID: id})
}

// isDue 判断计划是否已到执行时刻（next_run_at 缺失/损坏时视为不在执行窗口内）。
func isDue(s Schedule, now time.Time) bool {
	next, err := time.ParseInLocation(scheduleTimeLayout, s.NextRunAt, time.Local)
	if err != nil {
		return false
	}
	return !next.After(now)
}

// recordScheduleRun 回写最近一次调度结果。计划已不存在（用户刚删掉）时静默忽略。
func recordScheduleRun(id, taskID string, runErr error) {
	scheduleMu.Lock()
	defer scheduleMu.Unlock()

	store, err := loadSchedules()
	if err != nil {
		return
	}
	idx := findScheduleIndex(store, id)
	if idx < 0 {
		return
	}
	if runErr != nil {
		store.Items[idx].LastStatus = "failed"
		store.Items[idx].LastError = runErr.Error()
	} else {
		store.Items[idx].LastStatus = "started"
		store.Items[idx].LastError = ""
		store.Items[idx].LastTaskID = taskID
	}
	store.Items[idx].UpdatedAt = time.Now().Format(scheduleTimeLayout)
	if err := saveSchedules(store); err != nil {
		gologger.Warning().Msgf("回写计划状态失败: %v", err)
	}
}

// -----------------------
// HTTP API（仅在 Curated 下可访问，见路由上的 requireCurated）
// -----------------------

func writeScheduleJSON(w http.ResponseWriter, status int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// schedulesListHandler 返回全部计划，按更新时间倒序。
func schedulesListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeScheduleJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	scheduleMu.Lock()
	store, err := loadSchedules()
	scheduleMu.Unlock()
	if err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划读取失败"})
		return
	}

	items := append([]Schedule{}, store.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt > items[j].UpdatedAt })

	out := make([]scheduleView, 0, len(items))
	for _, s := range items {
		out = append(out, toScheduleView(s))
	}

	writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "ok", Data: map[string]interface{}{
		"items": out,
		"total": len(out),
	}})
}

type scheduleSaveRequest struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty"`

	Freq          string `json:"freq"`
	IntervalHours int    `json:"interval_hours,omitempty"`
	AtTime        string `json:"at_time,omitempty"`
	Weekday       int    `json:"weekday,omitempty"`

	// NodeURL 为空表示本机执行；非空时必须是已登记的同伴（见 validateScheduleNode）。
	NodeURL string `json:"node_url,omitempty"`

	Scan ScanCreateRequest `json:"scan"`
}

// validateScheduleNode 校验计划的执行节点。计划是无人值守执行的，配置错误不该
// 等到点才在日志里静默失败，保存时就拦下来。
func validateScheduleNode(nodeURL string) error {
	nodeURL = normalizePeerURL(nodeURL)
	if nodeURL == "" {
		return nil
	}
	if _, ok := findClusterPeer(nodeURL); !ok {
		return fmt.Errorf("执行节点不在集群配置中，请先在概览页「编辑节点」里登记")
	}
	if clusterToken() == "" {
		return fmt.Errorf("本实例未配置 cluster.token，无法把计划派发到其他节点")
	}
	return nil
}

// schedulesSaveHandler 新建或更新一条计划。
//
// 保存前用 resolveScanTargets 真解析一次目标：宁可在保存时报「项目没有目标」，
// 也不要留下一条每到点就静默失败的计划。
func schedulesSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeScheduleJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req scheduleSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "计划名称不能为空"})
		return
	}

	switch strings.ToLower(strings.TrimSpace(req.Freq)) {
	case freqHourly, freqDaily, freqWeekly:
	default:
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "无效的执行频率"})
		return
	}

	if _, err := resolveScanTargets(req.Scan); err != nil {
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}
	if err := validateScheduleNode(req.NodeURL); err != nil {
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	scheduleMu.Lock()
	defer scheduleMu.Unlock()

	store, err := loadSchedules()
	if err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划读取失败"})
		return
	}

	now := time.Now().Format(scheduleTimeLayout)

	if id := strings.TrimSpace(req.ID); id != "" {
		idx := findScheduleIndex(store, id)
		if idx < 0 {
			writeScheduleJSON(w, http.StatusNotFound, APIResponse{Success: false, Message: "计划不存在"})
			return
		}
		cur := &store.Items[idx]
		cur.Name = req.Name
		cur.Freq = req.Freq
		cur.IntervalHours = req.IntervalHours
		cur.AtTime = req.AtTime
		cur.Weekday = req.Weekday
		cur.NodeURL = req.NodeURL
		cur.Scan = req.Scan
		if req.Enabled != nil {
			cur.Enabled = *req.Enabled
		}
		cur.UpdatedAt = now
		normalizeSchedule(cur)
		if err := saveSchedules(store); err != nil {
			writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划保存失败"})
			return
		}
		writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "已保存", Data: toScheduleView(*cur)})
		return
	}

	if len(store.Items) >= maxSchedules {
		writeScheduleJSON(w, http.StatusForbidden, APIResponse{Success: false, Message: "计划数量已达上限"})
		return
	}

	s := Schedule{
		ID:            "s_" + utils.CreateRandomString(12),
		Name:          req.Name,
		Enabled:       true,
		Freq:          req.Freq,
		IntervalHours: req.IntervalHours,
		AtTime:        req.AtTime,
		Weekday:       req.Weekday,
		NodeURL:       req.NodeURL,
		Scan:          req.Scan,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if req.Enabled != nil {
		s.Enabled = *req.Enabled
	}
	normalizeSchedule(&s)

	store.Items = append(store.Items, s)
	if err := saveSchedules(store); err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划保存失败"})
		return
	}
	writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "已创建", Data: toScheduleView(s)})
}

// schedulesDeleteHandler 删除一条计划。
func schedulesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeScheduleJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持DELETE方法"})
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["id"])

	scheduleMu.Lock()
	defer scheduleMu.Unlock()

	store, err := loadSchedules()
	if err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划读取失败"})
		return
	}
	idx := findScheduleIndex(store, id)
	if idx < 0 {
		writeScheduleJSON(w, http.StatusNotFound, APIResponse{Success: false, Message: "计划不存在"})
		return
	}
	store.Items = append(store.Items[:idx], store.Items[idx+1:]...)
	if err := saveSchedules(store); err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划删除失败"})
		return
	}
	writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "已删除"})
}

// schedulesToggleHandler 启用/停用一条计划。重新启用时以当前时间为基准续排。
func schedulesToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeScheduleJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["id"])

	scheduleMu.Lock()
	defer scheduleMu.Unlock()

	store, err := loadSchedules()
	if err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划读取失败"})
		return
	}
	idx := findScheduleIndex(store, id)
	if idx < 0 {
		writeScheduleJSON(w, http.StatusNotFound, APIResponse{Success: false, Message: "计划不存在"})
		return
	}

	cur := &store.Items[idx]
	cur.Enabled = !cur.Enabled
	cur.UpdatedAt = time.Now().Format(scheduleTimeLayout)
	if cur.Enabled {
		cur.LastError = ""
		cur.NextRunAt = computeNextRun(*cur, time.Now()).Format(scheduleTimeLayout)
	}
	if err := saveSchedules(store); err != nil {
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划保存失败"})
		return
	}
	writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "ok", Data: toScheduleView(*cur)})
}

// schedulesRunHandler 立即执行一次计划（不影响既有的续排节奏）。
func schedulesRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeScheduleJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["id"])

	scheduleMu.Lock()
	store, err := loadSchedules()
	if err != nil {
		scheduleMu.Unlock()
		writeScheduleJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "计划读取失败"})
		return
	}
	idx := findScheduleIndex(store, id)
	if idx < 0 {
		scheduleMu.Unlock()
		writeScheduleJSON(w, http.StatusNotFound, APIResponse{Success: false, Message: "计划不存在"})
		return
	}
	scan := store.Items[idx].Scan
	name := store.Items[idx].Name
	nodeURL := store.Items[idx].NodeURL
	scheduleMu.Unlock()

	taskID, _, runErr := launchScheduledScan(id, name, nodeURL, scan)
	recordScheduleRun(id, taskID, runErr)
	if runErr != nil {
		writeScheduleJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: runErr.Error()})
		return
	}
	gologger.Info().Msgf("计划手动起扫: plan=%s name=%s taskId=%s", id, name, taskID)
	writeScheduleJSON(w, http.StatusOK, APIResponse{Success: true, Message: "已开始执行", Data: map[string]string{"taskId": taskID}})
}
