// Command mcp_agent 演示一个最小 MCP 客户端如何驱动 afrog。
//
// 它跑的是设计文档里的主流程：
//  1. observe.findings 拿一条命中；
//  2. observe.evidence 读它的可重放证据；
//  3. 可选：scan.start 按技术栈/关键词并发复测一次；
//  4. 可选：poc.draft 校验一份草稿，再交给 poc.submit 实跑取证据（-draft）。
//
// 运行前先起服务（默认只读策略即可，读证据与校验草稿都不需要发包）：
//
//	afrog mcp -listen 127.0.0.1:16870
//
// 然后执行：
//
//	go run ./examples/mcp_agent -project <project_id>
//	go run ./examples/mcp_agent -scan -keyword <tech> -target <target>
//	go run ./examples/mcp_agent -draft ./draft.yaml -target http://127.0.0.1:8080
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// rpcClient 是最小 JSON-RPC 客户端：只覆盖本示例用到的请求/响应与通知。
type rpcClient struct {
	endpoint string
	token    string
	session  string
	http     *http.Client
	nextID   int
}

func newRPCClient(endpoint, token string) *rpcClient {
	return &rpcClient{
		endpoint: endpoint,
		token:    strings.TrimSpace(token),
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *rpcClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.nextID++
	payload := map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method}
	if params != nil {
		payload["params"] = params
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

// notify 发送通知：服务端返回 202 且没有响应体。
func (c *rpcClient) notify(ctx context.Context, method string) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *rpcClient) callTool(ctx context.Context, name string, args any) (string, error) {
	raw, err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", err
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("decode tool result: %w", err)
	}
	var sb strings.Builder
	for _, item := range res.Content {
		sb.WriteString(item.Text)
	}
	if res.IsError {
		return "", fmt.Errorf("tool %s failed: %s", name, sb.String())
	}
	return sb.String(), nil
}

type finding struct {
	ID         string   `json:"id"`
	ProjectID  string   `json:"project_id"`
	Subject    string   `json:"subject"`
	VulnClass  string   `json:"vuln_class"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
	State      string   `json:"state"`
	Source     string   `json:"source"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	HitCount   int64    `json:"hit_count"`
	Status     string   `json:"status"`
}

func main() {
	endpoint := flag.String("url", "http://127.0.0.1:16870/mcp", "MCP Streamable HTTP 端点")
	token := flag.String("token", os.Getenv("AFROG_MCP_TOKEN"), "访问 token；服务端未开启鉴权时留空")
	project := flag.String("project", "", "只看某个项目的命中；留空为全局")
	limit := flag.Int("limit", 5, "拉取的命中条数")
	scan := flag.Bool("scan", false, "是否在最后用 scan.start 按关键词并发复测一次")
	keyword := flag.String("keyword", "", "-scan 时传给 scan.start 的技术栈/关键词（如 thinkphp）")
	target := flag.String("target", "", "scan.start 的目标；-draft 时必填")
	draft := flag.String("draft", "", "本地 PoC 草稿路径：先 poc.draft 校验并落盘，再 poc.submit 实跑取证据")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := newRPCClient(*endpoint, *token)
	if _, err := client.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "afrog-mcp-agent-demo", "version": "1.0"},
	}); err != nil {
		fail("initialize", err)
	}
	_ = client.notify(ctx, "notifications/initialized")

	if strings.TrimSpace(*draft) != "" {
		runDraftFlow(ctx, client, *draft, *target)
		return
	}

	text, err := client.callTool(ctx, "observe.findings", map[string]any{
		"project_id": *project,
		"limit":      *limit,
	})
	if err != nil {
		fail("observe.findings", err)
	}

	var page struct {
		Total int64     `json:"total"`
		Items []finding `json:"items"`
	}
	if err := json.Unmarshal([]byte(text), &page); err != nil {
		fail("decode observe.findings", err)
	}

	fmt.Printf("命中总数: %d\n", page.Total)
	if len(page.Items) == 0 {
		fmt.Println("没有命中，先跑一次扫描再来。")
		return
	}

	for i, f := range page.Items {
		fmt.Printf("%d. [%s] %s  %s  命中 %d 次  状态: %s\n",
			i+1, f.Severity, f.Title, firstNonEmpty(f.Subject, f.VulnClass), f.HitCount, f.State)
		if len(f.Evidence) > 0 {
			fmt.Printf("   证据: %s\n", strings.Join(f.Evidence, ", "))
		}
	}

	first := page.Items[0]
	if len(first.Evidence) > 0 {
		evText, err := client.callTool(ctx, "observe.evidence", map[string]any{"id": first.Evidence[0]})
		if err != nil {
			fmt.Printf("\n读取证据失败: %v\n", err)
		} else {
			fmt.Printf("\n第一条命中的证据:\n%s\n", evText)
		}
	} else {
		fmt.Println("\n第一条命中没有证据（可能是证据功能上线前的历史数据）。")
	}

	if *scan {
		if strings.TrimSpace(*keyword) == "" || strings.TrimSpace(*target) == "" {
			fail("-scan", fmt.Errorf("需要同时提供 -keyword 与 -target"))
		}
		out, err := client.callTool(ctx, "scan.start", map[string]any{
			"target": *target,
			"search": *keyword,
		})
		if err != nil {
			fail("scan.start", err)
		}
		fmt.Printf("\n复测结果:\n%s\n", out)
	}
}

// runDraftFlow 走「模型写草稿 → afrog 校验 → afrog 实跑」的闭环：
// 草稿只做结构与成本校验，判定与证据仍然由 poc.submit 的受限实跑产生。
func runDraftFlow(ctx context.Context, client *rpcClient, path, target string) {
	if strings.TrimSpace(target) == "" {
		fail("-draft", fmt.Errorf("需要同时提供 -target"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fail("read draft", err)
	}

	text, err := client.callTool(ctx, "poc.draft", map[string]any{"yaml": string(data), "save": true})
	if err != nil {
		fail("poc.draft", err)
	}
	var draft struct {
		Valid             bool     `json:"valid"`
		Errors            []string `json:"errors"`
		Warnings          []string `json:"warnings"`
		ID                string   `json:"id"`
		Capability        string   `json:"capability"`
		Destructive       bool     `json:"destructive"`
		EstimatedRequests int      `json:"estimated_requests"`
		PocPath           string   `json:"poc_path"`
	}
	if err := json.Unmarshal([]byte(text), &draft); err != nil {
		fail("decode poc.draft", err)
	}

	fmt.Printf("草稿校验: valid=%v id=%s capability=%s destructive=%v 预计请求=%d\n",
		draft.Valid, draft.ID, draft.Capability, draft.Destructive, draft.EstimatedRequests)
	for _, w := range draft.Warnings {
		fmt.Printf("  警告: %s\n", w)
	}
	if !draft.Valid {
		fail("poc.draft", fmt.Errorf("草稿不合法: %s", strings.Join(draft.Errors, "; ")))
	}
	if draft.PocPath == "" {
		fail("poc.draft", fmt.Errorf("服务端没有返回 poc_path"))
	}

	out, err := client.callTool(ctx, "poc.submit", map[string]any{"poc_path": draft.PocPath, "target": target})
	if err != nil {
		fail("poc.submit", err)
	}
	fmt.Printf("\n实跑结果:\n%s\n", out)
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", stage, err)
	os.Exit(1)
}
