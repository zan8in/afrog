// Package scanapi 把控制面的扫描能力暴露成 gRPC 服务（协议文档 §6 的 AfrogScanner）。
//
// 它只做协议翻译：任务怎么排队、怎么执行、事件怎么编号，全部由 pkg/scantask 决定。
package scanapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Options 配置 Server。
type Options struct {
	// Manager 是控制面任务管理器，必填。
	Manager *scantask.Manager
	// Token 是控制台 API token。必填：为空时构造失败，避免起出一个无鉴权的控制面。
	Token string
	// Version 是 afrog 版本号，默认取 config.Version。
	Version string
	// Nodes 返回当前可用节点列表，默认只有本机。
	Nodes func() []string
}

// Server 实现 afrogv1.AfrogScannerServer。
type Server struct {
	afrogv1.UnimplementedAfrogScannerServer

	opts Options

	pocOnce  sync.Once
	pocTotal int32

	curatedOnce sync.Once
	curatedOK   bool
}

// New 创建 gRPC 服务实现。
func New(opts Options) (*Server, error) {
	if opts.Manager == nil {
		return nil, errors.New("scanapi: manager is required")
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("scanapi: api token is required")
	}
	if opts.Version == "" {
		opts.Version = config.Version
	}
	return &Server{opts: opts}, nil
}

// SubmitScan 提交扫描，返回任务 ID。
func (s *Server) SubmitScan(_ context.Context, req *afrogv1.SubmitScanRequest) (*afrogv1.SubmitScanResponse, error) {
	spec := req.GetSpec()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}
	if err := rejectUnmappableOOBCredentials(spec); err != nil {
		return nil, err
	}

	snap, err := s.opts.Manager.Submit(fromProtoSpec(spec))
	if err != nil {
		if errors.Is(err, scantask.ErrNoTargets) {
			return nil, status.Error(codes.InvalidArgument, "spec.targets must not be empty")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &afrogv1.SubmitScanResponse{TaskId: snap.ID, Node: snap.Node}, nil
}

// SubmitActions 提交一批同类型的原子动作，返回任务 ID。
//
// 与 SubmitScan 的唯一区别是「动作由谁给出」：这里动作显式列出，工具面动作在进程内执行、
// 执行面动作走 CLI；排队、事件流、订阅、收尾完全复用同一套任务语义。
func (s *Server) SubmitActions(_ context.Context, req *afrogv1.SubmitActionsRequest) (*afrogv1.SubmitActionsResponse, error) {
	spec := req.GetSpec()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}
	if len(req.GetActions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "actions must not be empty")
	}
	if err := rejectUnmappableOOBCredentials(spec); err != nil {
		return nil, err
	}

	batch, err := fromProtoActions(req)
	if err != nil {
		return nil, err
	}
	snap, err := s.opts.Manager.SubmitBatch(batch)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &afrogv1.SubmitActionsResponse{TaskId: snap.ID, Node: snap.Node}, nil
}

// StreamEvents 订阅任务事件：先补发 from_seq 之后的事件，再持续推送，直到任务结束。
//
// 客户端应记录已收到的最大 seq，断线后用 from_seq 重连——这是协议 §5.1 的可靠性约定。
func (s *Server) StreamEvents(req *afrogv1.StreamEventsRequest, stream afrogv1.AfrogScanner_StreamEventsServer) error {
	taskID := strings.TrimSpace(req.GetTaskId())
	if taskID == "" {
		return status.Error(codes.InvalidArgument, "task_id is required")
	}

	sub, _, err := s.opts.Manager.Subscribe(taskID, req.GetFromSeq())
	if err != nil {
		return toStatusError(err)
	}
	defer sub.Close()

	for ev := range sub.Events() {
		if err := stream.Send(ToProtoEvent(ev)); err != nil {
			return err
		}
	}
	if err := sub.Err(); err != nil {
		// 订阅者消费太慢被断开：客户端带 last_seq 重连即可补齐。
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	return nil
}

// GetStatus 查询任务状态与汇总。
func (s *Server) GetStatus(_ context.Context, req *afrogv1.GetStatusRequest) (*afrogv1.GetStatusResponse, error) {
	taskID := strings.TrimSpace(req.GetTaskId())
	if taskID == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	task, ok := s.opts.Manager.Get(taskID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "task %s not found", taskID)
	}

	snap := task.Snapshot()
	resp := &afrogv1.GetStatusResponse{
		Status:   string(snap.Status),
		Node:     snap.Node,
		Pausable: snap.Pausable,
		Progress: &afrogv1.ProgressEvent{
			Percent:   int32(snap.Progress.Percent),
			Finished:  snap.Progress.Finished,
			Total:     snap.Progress.Total,
			Rate:      int32(snap.Progress.Rate),
			ElapsedMs: snap.Progress.ElapsedMs,
		},
	}
	if snap.Summary != nil {
		resp.Summary = &afrogv1.Summary{
			Executed:   snap.Summary.Executed,
			Found:      snap.Summary.Found,
			BySeverity: snap.Summary.BySeverity,
			ElapsedMs:  snap.Summary.ElapsedMs,
		}
	}
	return resp, nil
}

// GetResults 分页查询某个任务已落库的命中结果。
//
// 结果由执行扫描的一方写入控制面的 sqlite（本机由子进程写，远程节点由控制面按事件写），
// 因此这里直接按 task_id 查询，不依赖任务是否还在内存里。
func (s *Server) GetResults(_ context.Context, req *afrogv1.GetResultsRequest) (*afrogv1.GetResultsResponse, error) {
	taskID := strings.TrimSpace(req.GetTaskId())
	if taskID == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	expand := req.GetDetail() == afrogv1.DetailLevel_FULL

	rows, err := sqlite.SelectPageByTask(taskID, req.GetSeverity(), page, pageSize, false, expand)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	total, err := sqlite.CountByTask(taskID, req.GetSeverity())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}

	items := make([]*afrogv1.ResultEvent, 0, len(rows))
	for _, row := range rows {
		item := &afrogv1.ResultEvent{
			Severity: strings.ToUpper(row.Severity),
			PocId:    row.VulID,
			PocName:  row.VulName,
			Target:   row.FullTarget,
		}
		if item.Target == "" {
			item.Target = row.Target
		}
		if expand {
			item.Evidence = &afrogv1.Evidence{}
			for _, pr := range row.ResultList {
				item.Evidence.Exchanges = append(item.Evidence.Exchanges, &afrogv1.Exchange{
					Request:  pr.Request,
					Response: pr.Response,
					Matched:  true,
				})
			}
		}
		items = append(items, item)
	}

	return &afrogv1.GetResultsResponse{
		Items:    items,
		Total:    total,
		Page:     int32(page),
		PageSize: int32(pageSize),
	}, nil
}

// Control 暂停 / 继续 / 取消任务。
func (s *Server) Control(_ context.Context, req *afrogv1.ControlRequest) (*afrogv1.ControlResponse, error) {
	taskID := strings.TrimSpace(req.GetTaskId())
	if taskID == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	action, err := fromProtoAction(req.GetAction())
	if err != nil {
		return nil, err
	}

	if err := s.opts.Manager.Control(taskID, action); err != nil {
		return nil, toStatusError(err)
	}
	return &afrogv1.ControlResponse{Ok: true, Message: action.String()}, nil
}

// ListCapabilities 返回本控制面的能力清单，客户端据此决定要不要置灰按钮等。
func (s *Server) ListCapabilities(_ context.Context, _ *afrogv1.ListCapabilitiesRequest) (*afrogv1.ListCapabilitiesResponse, error) {
	nodes := []string{s.opts.Manager.Node()}
	if s.opts.Nodes != nil {
		nodes = s.opts.Nodes()
	}
	return &afrogv1.ListCapabilitiesResponse{
		Version:         s.opts.Version,
		ProtocolVersion: scanstream.Version,
		PocCount:        s.pocCount(),
		Curated:         s.curatedAvailable(),
		Pausable:        executor.PauseSupported,
		Nodes:           nodes,
	}, nil
}

// pocCount 统计本机可用 PoC 数量。首次调用会遍历一次 PoC 仓库，之后缓存。
func (s *Server) pocCount() int32 {
	s.pocOnce.Do(func() {
		items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"})
		if err != nil {
			return
		}
		s.pocTotal = int32(len(items))
	})
	return s.pocTotal
}

// curatedAvailable 判断本机是否有可用的 curated 内容。
//
// curated PoC 由授权挂载到 ~/.config/afrog/pocs-curated，目录里有 PoC 就说明会员内容
// 可用；这里刻意不去做联网校验，能力查询不该触发外部请求。
func (s *Server) curatedAvailable() bool {
	s.curatedOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return
		}
		dir := filepath.Join(home, ".config", "afrog", "pocs-curated")
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch strings.ToLower(filepath.Ext(e.Name())) {
			case ".yaml", ".yml":
				s.curatedOK = true
				return
			}
		}
	})
	return s.curatedOK
}

// fromProtoSpec 把协议规格翻译成控制面请求。
func fromProtoSpec(spec *afrogv1.ScanSpec) scantask.Request {
	return scantask.Request{
		Targets:         spec.GetTargets(),
		PocSource:       spec.GetPocSource(),
		PocFile:         spec.GetPocFile(),
		PocIDs:          spec.GetPocIds(),
		Search:          spec.GetSearch(),
		Severity:        spec.GetSeverity(),
		Concurrency:     int(spec.GetConcurrency()),
		RateLimit:       int(spec.GetRateLimit()),
		TimeoutSeconds:  int(spec.GetTimeoutSeconds()),
		Retries:         int(spec.GetRetries()),
		Smart:           spec.GetSmart(),
		Proxy:           spec.GetProxy(),
		Headers:         spec.GetHeaders(),
		FollowRedirects: spec.GetFollowRedirects(),
		// 前置阶段开关一律指针直传：nil 表示协议里未设置（交回子进程默认值），
		// 显式 true/false 才覆盖。默认值只在 CLI flag 定义处存在一份。
		PortScan:          spec.PortScan,
		Ports:             spec.GetPorts(),
		SkipHostDiscovery: spec.SkipHostDiscovery,
		ReportStates:      spec.ReportStates,
		WebFingerprint:    spec.WebFingerprint,
		WebProbeTimeout:   int(spec.GetWebProbeTimeout()),
		WebFavicon:        spec.WebFavicon,
		WebAssets:         int32PtrToIntPtr(spec.WebAssets),
		EnableOOB:         spec.GetEnableOob(),
		OOBAdapter:        spec.GetOobAdapter(),
		NoSaveDB:          spec.GetNoSaveDb(),
		TaskName:          spec.GetTaskName(),
		Labels:            spec.GetLabels(),
		NodeSelector:      spec.GetNodeSelector(),
		GatingLevel:       spec.GetGatingLevel(),
		DryRun:            spec.GetDryRun(),
	}
}

// int32PtrToIntPtr 把协议的 *int32 收敛为执行器规格用的 *int，nil 原样保留（未设置）。
// 用于 web_assets 这类「0 是合法值、必须区分未设置」的数值开关。
func int32PtrToIntPtr(v *int32) *int {
	if v == nil {
		return nil
	}
	i := int(*v)
	return &i
}

// fromProtoActions 把协议动作翻译成控制面批量。
//
// params_json 是工具面动作的唯一参数载体：scantask 不理解具体字段，原样交给 Dispatcher，
// 由工具面按自己的 schema 解释。因此这里只做 JSON 合法性校验，不镜像工具 schema，
// 避免出现「proto 与工具各维护一份真相」。
func fromProtoActions(req *afrogv1.SubmitActionsRequest) (scantask.Batch, error) {
	src := req.GetActions()
	batch := scantask.Batch{
		Options: fromProtoSpec(req.GetSpec()),
		Actions: make([]scantask.Action, 0, len(src)),
	}
	for i, a := range src {
		kind := scantask.ActionKind(strings.TrimSpace(a.GetKind()))
		if kind == "" {
			return scantask.Batch{}, status.Errorf(codes.InvalidArgument, "actions[%d].kind is required", i)
		}
		action := scantask.Action{Kind: kind, Target: a.GetTarget(), PocID: a.GetPocId()}
		if p := strings.TrimSpace(a.GetParamsJson()); p != "" {
			if !json.Valid([]byte(p)) {
				return scantask.Batch{}, status.Errorf(codes.InvalidArgument, "actions[%d].params_json is not valid JSON", i)
			}
			action.Params = json.RawMessage(p)
		}
		batch.Actions = append(batch.Actions, action)
	}
	return batch, nil
}

// rejectUnmappableOOBCredentials 明确拒绝无法生效的 OOB 凭据。
//
// CLI 只有 -oob <adapter>，key/domain 只能来自节点自己的 afrog-config.yaml；
// 与其静默忽略（调用方会以为 OOB 生效了），不如直接报错说清楚。
func rejectUnmappableOOBCredentials(spec *afrogv1.ScanSpec) error {
	if !spec.GetEnableOob() {
		return nil
	}
	if strings.TrimSpace(spec.GetOobKey()) == "" && strings.TrimSpace(spec.GetOobDomain()) == "" {
		return nil
	}
	return status.Error(codes.InvalidArgument,
		"oob_key / oob_domain 不能通过本接口下发：请在执行该任务的节点上的 afrog-config.yaml 里配置 OOB 凭据，spec 只需给 oob_adapter")
}

func fromProtoAction(action afrogv1.ControlAction) (scantask.ControlAction, error) {
	switch action {
	case afrogv1.ControlAction_PAUSE:
		return scantask.ControlPause, nil
	case afrogv1.ControlAction_RESUME:
		return scantask.ControlResume, nil
	case afrogv1.ControlAction_CANCEL:
		return scantask.ControlCancel, nil
	default:
		return 0, status.Errorf(codes.InvalidArgument, "unknown control action %d", int32(action))
	}
}

// toStatusError 把控制面的哨兵错误映射成合适的 gRPC 状态码。
func toStatusError(err error) error {
	switch {
	case errors.Is(err, scantask.ErrTaskNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, scantask.ErrNoProcess):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, executor.ErrPauseUnsupported):
		return status.Error(codes.Unimplemented, err.Error())
	case errors.Is(err, executor.ErrAlreadyDone):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, scantask.ErrSlowSubscriber):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, scantask.ErrNoDispatcher):
		// 提交了工具面动作却没有任何派发后端：这是能力缺失，不是参数错误。
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, scantask.ErrMixedActionKinds),
		errors.Is(err, scantask.ErrActionNoTarget),
		errors.Is(err, scantask.ErrUnknownActionKind),
		errors.Is(err, scantask.ErrHeterogeneousBatch),
		errors.Is(err, scantask.ErrNoTargets):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
