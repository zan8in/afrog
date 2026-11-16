package scanapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/mcp"
	"github.com/zan8in/afrog/v3/pkg/policy"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// agentTools 用给定策略构建工具面；与 MCP / REST 走的是同一实现。
func agentTools(t *testing.T, policyYAML string) *mcp.Server {
	t.Helper()
	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return mcp.New(mcp.Options{Policy: p})
}

// newAgentTestClient 在 bufconn 上只起一个 AgentService（含鉴权拦截器）。
func newAgentTestClient(t *testing.T, tools *mcp.Server) afrogv1.AgentServiceClient {
	t.Helper()

	srv, err := NewAgentService(tools)
	if err != nil {
		t.Fatalf("NewAgentService: %v", err)
	}

	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuth(testToken)),
		grpc.StreamInterceptor(StreamAuth(testToken)),
	)
	afrogv1.RegisterAgentServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return afrogv1.NewAgentServiceClient(conn)
}

// ListTools 与 MCP tools/list 同源：名字与入参 schema 都来自同一份注册表。
func TestAgentServiceListTools(t *testing.T) {
	client := newAgentTestClient(t, agentTools(t, "mode: readonly\n"))

	resp, err := client.ListTools(authCtx(t), &afrogv1.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	byName := map[string]*afrogv1.ToolSpec{}
	for _, tool := range resp.GetTools() {
		byName[tool.GetName()] = tool
	}
	for _, want := range []string{"observe.state", "observe.observations", "plan.next", "poc.search", "probe.http", "scan.start"} {
		spec, ok := byName[want]
		if !ok {
			t.Fatalf("tool %q missing from ListTools", want)
		}
		if !json.Valid([]byte(spec.GetInputSchemaJson())) {
			t.Fatalf("tool %q schema is not valid JSON: %q", want, spec.GetInputSchemaJson())
		}
	}
}

// 默认只读：写动作必须被拒，且映射成 PermissionDenied（区别于参数错误）。
func TestAgentServiceInvokeDeniedByReadOnly(t *testing.T) {
	client := newAgentTestClient(t, agentTools(t, "mode: readonly\n"))

	_, err := client.Invoke(authCtx(t), &afrogv1.InvokeRequest{
		Name:          "probe.http",
		ArgumentsJson: `{"url":"http://127.0.0.1:1/"}`,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if !strings.Contains(status.Convert(err).Message(), "policy denied") {
		t.Fatalf("message = %q, want a policy denial", status.Convert(err).Message())
	}
}

// 未知工具：NotFound，与「被策略拒绝」区分。
func TestAgentServiceInvokeUnknownTool(t *testing.T) {
	client := newAgentTestClient(t, agentTools(t, "mode: safe\n"))

	_, err := client.Invoke(authCtx(t), &afrogv1.InvokeRequest{Name: "nope.tool"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

// 空 name：InvalidArgument。
func TestAgentServiceInvokeRequiresName(t *testing.T) {
	client := newAgentTestClient(t, agentTools(t, "mode: safe\n"))

	_, err := client.Invoke(authCtx(t), &afrogv1.InvokeRequest{ArgumentsJson: "{}"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

// 鉴权沿用 UnaryAuth 拦截器：没有 token 一律 Unauthenticated。
func TestAgentServiceRequiresAuth(t *testing.T) {
	client := newAgentTestClient(t, agentTools(t, "mode: readonly\n"))

	_, err := client.ListTools(context.Background(), &afrogv1.ListToolsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}

// safe 模式放行写动作：结果 JSON 与工具返回值一致，证明 gRPC 只是透传协议。
func TestAgentServiceInvokeSafeProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("agent-grpc-ok"))
	}))
	t.Cleanup(upstream.Close)

	client := newAgentTestClient(t, agentTools(t, "mode: safe\nbudget:\n  requests: 5\n  duration: 2m\n"))

	resp, err := client.Invoke(authCtx(t), &afrogv1.InvokeRequest{
		Name:          "probe.http",
		ArgumentsJson: `{"url":"` + upstream.URL + `"}`,
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(resp.GetResultJson()), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%q)", err, resp.GetResultJson())
	}
	if status, _ := out["status"].(float64); int(status) != http.StatusOK {
		t.Fatalf("result status = %v, want 200 (%v)", out["status"], out)
	}
	if body, _ := out["body"].(string); !strings.Contains(body, "agent-grpc-ok") {
		t.Fatalf("result body = %q, want the upstream marker", body)
	}
}
