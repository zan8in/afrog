package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// resetRemoteStore 清掉影子任务，避免用例之间互相看到对方的记录。
func resetRemoteStore() {
	remoteStore.mu.Lock()
	remoteStore.items = make(map[string]*remoteTask)
	remoteStore.order = nil
	remoteStore.mu.Unlock()
}

// fakePeer 模拟一个同伴实例：实现派发、状态、停止与命中四类 inbound 接口。
// statusSeq 用一次调用就换一个状态，便于验证「对账把远端状态镜像过来」。
type fakePeer struct {
	srv       *httptest.Server
	token     string
	lastSeen  string
	stopCalls int
	status    string
	progress  ScanProgressData

	mu       sync.Mutex
	dispatch inboundDispatchRequest
}

// lastDispatch 返回执行节点最近一次收到的派发请求（用于断言发起端到底发了什么）。
func (fp *fakePeer) lastDispatch() inboundDispatchRequest {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.dispatch
}

func newFakePeer(t *testing.T, token string) *fakePeer {
	t.Helper()
	fp := &fakePeer{
		token:  token,
		status: string(TaskRunning),
		progress: ScanProgressData{
			Percent: 42, Finished: 42, Total: 100,
		},
	}
	fp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.TrimSpace(r.Header.Get(clusterTokenHeader)) != token {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "集群令牌不匹配"})
			return
		}
		switch {
		case r.URL.Path == "/api/cluster/inbound/dispatch":
			var in inboundDispatchRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			fp.mu.Lock()
			fp.dispatch = in
			fp.mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true,"message":"started","data":{"task_id":"remote-1","name":"远程任务","node":"peerA"}}`))
		case strings.HasSuffix(r.URL.Path, "/stop"):
			fp.stopCalls++
			_, _ = w.Write([]byte(`{"success":true,"message":"stopped","data":{"stopped":true}}`))
		case strings.HasSuffix(r.URL.Path, "/findings"):
			_, _ = w.Write([]byte(`{"success":true,"message":"ok","data":{"items":[{"id":"1","taskId":"remote-1","vulId":"poc-x","vulName":"X","target":"http://a","severity":"HIGH","created":"2026-10-02 10:00:00"}],"page":1,"page_size":50,"total":1,"total_pages":1}}`))
		case strings.HasSuffix(r.URL.Path, "/results"):
			// 回填用的原样快照：字段名与本地 result 表列一一对应。
			_, _ = w.Write([]byte(`{"success":true,"message":"ok","data":[{"TaskID":"remote-1","VulID":"poc-x","VulName":"X","Target":"http://a","FullTarget":"http://a/x","Severity":"high","Poc":"{\"id\":\"poc-x\"}","Result":"[{\"fulltarget\":\"http://a/x\",\"request\":\"GET /x HTTP/1.1\",\"response\":\"HTTP/1.1 200 OK\"}]","Created":"2026-10-02 10:00:00","FingerPrint":"","Extractor":""}]}`))
		case strings.HasPrefix(r.URL.Path, "/api/cluster/inbound/tasks/"):
			body, _ := json.Marshal(APIResponse{Success: true, Message: "ok", Data: clusterTaskStatus{
				TaskID:   "remote-1",
				Name:     "远程任务",
				Status:   fp.status,
				Source:   scanSourceRemote,
				Progress: fp.progress,
				HitTotal: 1,
				Hits:     map[string]int{"HIGH": 1},
				Targets:  []string{"http://a"},
			}})
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"message":"not found"}`))
		}
	}))
	t.Cleanup(fp.srv.Close)
	return fp
}

// useCluster 注入运行态集群（同伴 + 共享令牌），用例结束后由 withCluster 还原。
func useCluster(t *testing.T, peers []config.ClusterPeer) {
	t.Helper()
	withCluster(t, config.Cluster{Name: "本机", Token: "shared-token", Peers: peers})
}

func dispatchRequest(t *testing.T, nodeURL string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"node_url": nodeURL,
		"request": map[string]any{
			"targets": []string{"http://a.example"},
		},
	})
	rec := httptest.NewRecorder()
	clusterRemoteDispatchHandler(rec, httptest.NewRequest(http.MethodPost, "/api/cluster/dispatch", strings.NewReader(string(body))))
	return rec
}

// 派发成功：影子任务带节点信息、状态被镜像，且并入任务列表。
func TestClusterRemoteDispatchAndMirror(t *testing.T) {
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchRequest(t, fp.srv.URL)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var out struct {
		Success bool         `json:"success"`
		Data    scanListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if !out.Success || out.Data.Source != scanSourceRemote {
		t.Fatalf("应返回远程任务：%+v", out)
	}
	if out.Data.NodeName != "节点A" || !out.Data.NodeOK {
		t.Fatalf("节点信息不正确：%+v", out.Data)
	}
	if out.Data.Status != string(TaskRunning) {
		t.Fatalf("状态应镜像为 running，实际 %q", out.Data.Status)
	}
	if out.Data.Progress.Percent != 42 {
		t.Fatalf("进度未镜像：%+v", out.Data.Progress)
	}

	// 影子任务要出现在本机任务列表里。
	found := false
	for _, item := range remoteScanItems() {
		if item.TaskID == out.Data.TaskID && item.Source == scanSourceRemote {
			found = true
		}
	}
	if !found {
		t.Fatalf("影子任务未并入列表：%s", out.Data.TaskID)
	}
}

// 节点不可达：保留状态、标记 node_ok=false，绝不改写成 failed。
func TestClusterRemoteUnreachableKeepsStatus(t *testing.T) {
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchRequest(t, fp.srv.URL)
	if rec.Code != http.StatusCreated {
		t.Fatalf("首次派发应成功：%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data scanListItem `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	// 让同伴下线，再对账一次。
	fp.srv.Close()
	rt := getRemoteTask(out.Data.TaskID)
	if rt == nil {
		t.Fatal("影子任务丢失")
	}
	_ = reconcileRemoteTask(rt)

	item := remoteTaskItem(rt)
	if item.NodeOK {
		t.Fatalf("节点已下线，node_ok 应为 false：%+v", item)
	}
	if item.Status != string(TaskRunning) {
		t.Fatalf("失联不应改写状态，实际 %q", item.Status)
	}
	if strings.TrimSpace(item.Error) == "" {
		t.Fatalf("失联应写明原因")
	}
}

// 停止与命中代理：请求要真的转发到执行节点。
func TestClusterRemoteStopAndFindingsProxy(t *testing.T) {
	resetRemoteStore()
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchRequest(t, fp.srv.URL)
	var out struct {
		Data scanListItem `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id := out.Data.TaskID

	stopReq := httptest.NewRequest(http.MethodPost, "/api/cluster/remote-tasks/"+id+"/stop", nil)
	stopRec := httptest.NewRecorder()
	clusterRemoteTaskStopHandler(stopRec, mux.SetURLVars(stopReq, map[string]string{"taskId": id}))
	if stopRec.Code != http.StatusOK {
		t.Fatalf("停止应转发成功：%d %s", stopRec.Code, stopRec.Body.String())
	}
	if fp.stopCalls != 1 {
		t.Fatalf("执行节点收到的停止次数 = %d，期望 1", fp.stopCalls)
	}
	if st := remoteTaskItem(getRemoteTask(id)).Status; st != string(TaskCancelled) {
		t.Fatalf("停止后本地状态应为 cancelled，实际 %q", st)
	}

	findReq := httptest.NewRequest(http.MethodGet, "/api/cluster/remote-tasks/"+id+"/findings", nil)
	findRec := httptest.NewRecorder()
	clusterRemoteTaskFindingsHandler(findRec, mux.SetURLVars(findReq, map[string]string{"taskId": id}))
	if findRec.Code != http.StatusOK || !strings.Contains(findRec.Body.String(), "poc-x") {
		t.Fatalf("命中代理未转发对端内容：%d %s", findRec.Code, findRec.Body.String())
	}
}

// 执行节点一侧：同一个 dispatch_id 只起一次扫描。
func TestClusterInboundDispatchIdempotent(t *testing.T) {
	dispatchMu.Lock()
	dispatchIndex = make(map[string]string)
	dispatchIndex["dup-1"] = "existing-task"
	dispatchMu.Unlock()
	t.Cleanup(func() {
		dispatchMu.Lock()
		dispatchIndex = make(map[string]string)
		dispatchMu.Unlock()
	})

	SetClusterConfig(config.Cluster{Token: "shared-token"}, "")
	t.Cleanup(func() { SetClusterConfig(config.Cluster{}, "") })

	body := `{"dispatch_id":"dup-1","request":{"targets":["http://a.example"]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/inbound/dispatch", strings.NewReader(body))
	req.Header.Set(clusterTokenHeader, "shared-token")
	rec := httptest.NewRecorder()
	clusterInboundDispatchHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("重复派发应命中幂等分支：%d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "existing-task") {
		t.Fatalf("应返回既有任务号：%s", rec.Body.String())
	}
}

// 执行节点一侧：令牌不对直接拒绝，不泄漏任何任务信息。
func TestClusterInboundRejectsBadToken(t *testing.T) {
	SetClusterConfig(config.Cluster{Token: "shared-token"}, "")
	t.Cleanup(func() { SetClusterConfig(config.Cluster{}, "") })

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/inbound/dispatch", strings.NewReader(`{"dispatch_id":"x"}`))
	req.Header.Set(clusterTokenHeader, "wrong")
	rec := httptest.NewRecorder()
	clusterInboundDispatchHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("令牌错误应 401，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "集群令牌不匹配") {
		t.Fatalf("应说明原因：%s", rec.Body.String())
	}
}

// 未配置令牌的实例不接收远程派发。
func TestClusterInboundDisabledWithoutToken(t *testing.T) {
	SetClusterConfig(config.Cluster{}, "")
	t.Cleanup(func() { SetClusterConfig(config.Cluster{}, "") })

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/inbound/dispatch", strings.NewReader(`{"dispatch_id":"x"}`))
	rec := httptest.NewRecorder()
	clusterInboundDispatchHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("未配置令牌应 403，实际 %d", rec.Code)
	}
}

// 派发到未登记的节点要被拦住，并给出可照做的提示。
func TestClusterRemoteDispatchUnknownNode(t *testing.T) {
	resetRemoteStore()
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: "http://127.0.0.1:1"}})

	rec := dispatchRequest(t, "http://127.0.0.1:9")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知节点应 400，实际 %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "不在集群配置中") {
		t.Fatalf("应说明原因：%s", rec.Body.String())
	}
}

// 影子记录落盘后能读回：发起端重启不丢远程任务列表，未完成的任务仍可继续对账。
func TestRemoteTaskPersistAndRestore(t *testing.T) {
	resetRemoteStore()
	remoteTasksPathOverride = filepath.Join(t.TempDir(), "remote_tasks.json")
	remotePersistEnabled = true
	t.Cleanup(func() {
		remotePersistEnabled = false
		remoteTasksPathOverride = ""
		resetRemoteStore()
	})

	rt := &remoteTask{
		ID:           "20261002-00001-abcdef",
		DispatchID:   "d-1",
		NodeName:     "节点A",
		NodeURL:      "http://peer-a",
		RemoteTaskID: "remote-1",
		Name:         "远程任务",
		Status:       string(TaskRunning),
		Progress:     ScanProgressData{Percent: 42, Finished: 42, Total: 100},
		HitTotal:     1,
		Targets:      []string{"http://a"},
		CreatedAt:    "2026-10-02 10:00:00",
		NodeOK:       true,
		LastSeen:     time.Now(),
		request:      ScanCreateRequest{Targets: []string{"http://a"}},
	}
	addRemoteTask(rt)

	// 模拟进程重启：内存清空后从磁盘读回。
	resetRemoteStore()
	if n := RestoreRemoteTasks(); n != 1 {
		t.Fatalf("恢复记录数 = %d，期望 1", n)
	}

	got := getRemoteTask("20261002-00001-abcdef")
	if got == nil {
		t.Fatal("影子记录未恢复")
	}
	if got.RemoteTaskID != "remote-1" || got.DispatchID != "d-1" {
		t.Fatalf("关键字段未保留：%+v", got)
	}
	if got.Status != string(TaskRunning) || !got.NodeOK {
		t.Fatalf("状态未保留：%+v", got)
	}
	if len(got.request.Targets) != 1 {
		t.Fatalf("派发请求未保留，未拿到远端任务号时无法重试：%+v", got.request)
	}

	// 恢复出来的记录要照常并入任务列表。
	items := remoteScanItems()
	if len(items) != 1 || items[0].TaskID != rt.ID || items[0].Source != scanSourceRemote {
		t.Fatalf("恢复的记录未并入列表：%+v", items)
	}
}

// dispatchBody 用给定的 request 字段发起一次派发。
func dispatchBody(t *testing.T, nodeURL string, reqBody map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"node_url": nodeURL, "request": reqBody})
	rec := httptest.NewRecorder()
	clusterRemoteDispatchHandler(rec, httptest.NewRequest(http.MethodPost, "/api/cluster/dispatch", strings.NewReader(string(body))))
	return rec
}

// 按项目派发：发起端把项目解析成具体目标，执行节点只收到目标清单、不收到 project_id。
func TestClusterRemoteDispatchByProject(t *testing.T) {
	resetRemoteStore()
	withProjectFixture(t)
	if rec := postProject(t, `{"name":"客户A","targets_text":"https://a.example\nhttps://b.example"}`); rec.Code != http.StatusOK {
		t.Fatalf("准备项目失败：%d %s", rec.Code, rec.Body.String())
	}
	p := onlyProject(t)

	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchBody(t, fp.srv.URL, map[string]any{"project_id": p.ID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("按项目派发应成功：%d %s", rec.Code, rec.Body.String())
	}

	sent := fp.lastDispatch()
	if sent.Request.ProjectID != "" {
		t.Fatalf("执行节点不应收到 project_id，实际 %q", sent.Request.ProjectID)
	}
	want, err := resolveScanTargets(ScanCreateRequest{ProjectID: p.ID})
	if err != nil {
		t.Fatalf("本地解析项目目标失败：%v", err)
	}
	if !reflect.DeepEqual(sent.Request.Targets, want) {
		t.Fatalf("执行节点收到的目标 = %v，期望 %v", sent.Request.Targets, want)
	}
	if !strings.Contains(sent.Request.TaskName, "客户A") {
		t.Fatalf("任务名应带上项目名兜底，实际 %q", sent.Request.TaskName)
	}
}

// 项目不存在：派发前就拦住，不产生任何影子记录，也不真的发起派发。
func TestClusterRemoteDispatchByUnknownProject(t *testing.T) {
	resetRemoteStore()
	withProjectFixture(t)
	fp := newFakePeer(t, "shared-token")
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchBody(t, fp.srv.URL, map[string]any{"project_id": "p-does-not-exist"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知项目应 400，实际 %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "项目不存在") {
		t.Fatalf("应说明原因：%s", rec.Body.String())
	}
	if items := remoteScanItems(); len(items) != 0 {
		t.Fatalf("失败派发不应留下影子记录：%+v", items)
	}
	if sent := fp.lastDispatch(); sent.DispatchID != "" || sent.Request.Targets != nil {
		t.Fatalf("未知项目不该真的发起派发：%+v", sent)
	}
}

// 任务终结后把执行节点上的命中回填到本地：落在影子任务号上、标出来源节点，
// 并且「先清后写」保证重放不会写出第二份。
func TestRemoteFindingsBackfill(t *testing.T) {
	withProjectFixture(t) // 顺带准备好临时 HOME 与 sqlite
	resetRemoteStore()

	fp := newFakePeer(t, "shared-token")
	fp.status = string(TaskCompleted)
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchRequest(t, fp.srv.URL)
	if rec.Code != http.StatusCreated {
		t.Fatalf("派发应成功：%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data scanListItem `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id := out.Data.TaskID

	rt := getRemoteTask(id)
	if !remoteTaskNeedsBackfill(rt) {
		t.Fatalf("终态任务应处于待回填状态：%+v", remoteTaskItem(rt))
	}

	backfillRemoteFindings(rt)
	if remoteTaskNeedsBackfill(rt) {
		t.Fatal("回填成功后不应再判为待回填")
	}

	rows, err := sqlite.SelectRawResultsByTask(id, 0)
	if err != nil {
		t.Fatalf("读取回填结果失败：%v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("回填命中数 = %d，期望 1", len(rows))
	}
	if rows[0].TaskID != id {
		t.Fatalf("回填应落在影子任务号上，实际 %q", rows[0].TaskID)
	}
	if rows[0].Node != "节点A" {
		t.Fatalf("回填应标出来源节点，实际 %q", rows[0].Node)
	}
	if !strings.Contains(rows[0].Result, "GET /x") {
		t.Fatalf("回填应保留请求报文原文，实际 %q", rows[0].Result)
	}

	backfillRemoteFindings(rt)
	if rows, _ = sqlite.SelectRawResultsByTask(id, 0); len(rows) != 1 {
		t.Fatalf("重放后命中数 = %d，期望仍为 1", len(rows))
	}
}

// 按项目派发的远程任务：命中回填后要登记到项目名下，
// 否则项目报告与台账的项目筛选都看不到这些远程命中。
func TestRemoteFindingsBackfillKeepsProjectAttribution(t *testing.T) {
	withProjectFixture(t)
	resetRemoteStore()

	if rec := postProject(t, `{"name":"客户A","targets_text":"https://a.example"}`); rec.Code != http.StatusOK {
		t.Fatalf("准备项目失败：%d %s", rec.Code, rec.Body.String())
	}
	p := onlyProject(t)

	fp := newFakePeer(t, "shared-token")
	fp.status = string(TaskCompleted)
	useCluster(t, []config.ClusterPeer{{Name: "节点A", URL: fp.srv.URL}})

	rec := dispatchBody(t, fp.srv.URL, map[string]any{"project_id": p.ID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("按项目派发应成功：%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data scanListItem `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	backfillRemoteFindings(getRemoteTask(out.Data.TaskID))

	pid, err := sqlite.SelectTaskProject(out.Data.TaskID)
	if err != nil {
		t.Fatalf("查询任务归属失败：%v", err)
	}
	if pid != p.ID {
		t.Fatalf("远程任务的项目归属 = %q，期望 %q", pid, p.ID)
	}
	rows, err := sqlite.SelectAllByProject(p.ID, "", false, false)
	if err != nil {
		t.Fatalf("按项目查询失败：%v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("项目下命中数 = %d，期望 1", len(rows))
	}
}
