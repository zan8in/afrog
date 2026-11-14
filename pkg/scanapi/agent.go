// Package scanapi —— Agent 工具面的 gRPC 适配。
//
// AgentService 把 pkg/mcp 的工具面（观测 / 探测 / 验证）暴露到 gRPC，与 MCP、
// REST 共用同一份工具注册表与策略门控：策略判定、预算扣减、审计落盘都在工具
// 处理器内部完成，本文件只做协议翻译与错误码映射，不重复实现任何门控逻辑。
package scanapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/mcp"
	"github.com/zan8in/afrog/v3/pkg/policy"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AgentService 实现 afrogv1.AgentServiceServer。
type AgentService struct {
	afrogv1.UnimplementedAgentServiceServer

	tools *mcp.Server
}

// NewAgentService 用给定的工具面包一层 gRPC 适配。tools 为 nil 时构造失败，
// 避免起出一个「列不出工具、调用全失败」的空服务。
func NewAgentService(tools *mcp.Server) (*AgentService, error) {
	if tools == nil {
		return nil, errors.New("scanapi: tools server is required")
	}
	return &AgentService{tools: tools}, nil
}

// ListTools 返回全部可用工具及其入参 JSON Schema。
func (a *AgentService) ListTools(context.Context, *afrogv1.ListToolsRequest) (*afrogv1.ListToolsResponse, error) {
	specs := a.tools.Specs()
	out := &afrogv1.ListToolsResponse{Tools: make([]*afrogv1.ToolSpec, 0, len(specs))}
	for _, sp := range specs {
		schema := ""
		if sp.InputSchema != nil {
			b, err := json.Marshal(sp.InputSchema)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			schema = string(b)
		}
		out.Tools = append(out.Tools, &afrogv1.ToolSpec{
			Name:            sp.Name,
			Description:     sp.Description,
			InputSchemaJson: schema,
		})
	}
	return out, nil
}

// Invoke 调用一个工具，返回与 MCP / REST 逐字一致的 JSON 结果。
func (a *AgentService) Invoke(ctx context.Context, req *afrogv1.InvokeRequest) (*afrogv1.InvokeResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	args := json.RawMessage(strings.TrimSpace(req.GetArgumentsJson()))
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}

	result, err := a.tools.Call(ctx, name, args)
	if err != nil {
		return nil, agentStatusError(err)
	}
	b, err := json.Marshal(result)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &afrogv1.InvokeResponse{ResultJson: string(b)}, nil
}

// agentStatusError 把工具错误映射成合适的 gRPC 状态码，语义与 REST 的
// 403 / 429 / 404 / 400 一一对应，便于客户端区分「没被允许」与「没做」。
func agentStatusError(err error) error {
	switch {
	case errors.Is(err, policy.ErrDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, policy.ErrBudgetExceeded):
		return status.Error(codes.ResourceExhausted, err.Error())
	case strings.Contains(err.Error(), "unknown tool"):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.InvalidArgument, err.Error())
	}
}
