package web

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/gologger"
)

// AI 辅助（v1：命中研判）。
//
// 设计取向是「只在用户点击时调用」：绝不后台批量跑模型，也不可能出现
// 「一觉醒来账单几百块」。因此这里没有后台协程，只有同步的 HTTP 调用 + SSE 转发。
//
// 供应商中立：只实现 OpenAI 兼容的 chat completions 协议，换供应商只改 base_url/model。
const (
	// aiFreeMonthlyQuota 是普通用户每月可用的研判次数（会员不限）。
	aiFreeMonthlyQuota = 20

	// 证据截断上限：请求头/体与响应体都可能很大，而判定漏洞只需要关键片段。
	aiEvidenceRequestLimit  = 4000
	aiEvidenceResponseLimit = 8000

	// 单个命中的缓存标识里带上模型名，换模型后不会拿旧模型的结论糊弄人。
	aiTemperature = 0.2
)

// aiConfigPayload 是设置页读写 AI 配置的传输结构。
type aiConfigPayload struct {
	BaseURL    string `json:"base_url"`
	Model      string `json:"model"`
	APIKey     string `json:"api_key"`
	TimeoutSec int    `json:"timeout_sec"`
	MaxTokens  int    `json:"max_tokens"`
	ConfigPath string `json:"config_path"`
}

// aiStatusPayload 告诉界面：能不能用、用的哪个模型、这个月还剩多少试用次数。
type aiStatusPayload struct {
	Configured bool   `json:"configured"`
	Model      string `json:"model"`
	BaseURL    string `json:"base_url"`
	ConfigPath string `json:"config_path"`
	// QuotaLimit 为 0 表示不限次（会员）；QuotaUsed 是这个月的已用次数。
	QuotaLimit int `json:"quota_limit"`
	QuotaUsed  int `json:"quota_used"`
}

var (
	// aiMu 保护下面两项：设置页可以在运行时改写 AI 配置（无需重启）。
	aiMu   sync.RWMutex
	aiCfg  config.AI
	aiPath string
)

// SetAIConfig 注入 AI 配置及它所在的文件路径，由 cmd 层在启动 Web 服务前调用。
func SetAIConfig(cfg config.AI, configPath string) {
	aiMu.Lock()
	defer aiMu.Unlock()
	aiCfg = cfg
	aiPath = configPath
}

func currentAIConfig() (config.AI, string) {
	aiMu.RLock()
	defer aiMu.RUnlock()
	return aiCfg, aiPath
}

// aiReady 判断配置是否可用：三项连接信息缺任意一项都算未配置，
// 界面据此把「AI 研判」按钮变成引导去设置，而不是等用户点了再报错。
func aiReady(cfg config.AI) bool {
	return strings.TrimSpace(cfg.BaseURL) != "" &&
		strings.TrimSpace(cfg.Model) != "" &&
		strings.TrimSpace(cfg.APIKey) != ""
}

// aiChatEndpoint 把 base_url 归一化成 chat completions 的完整地址。
// 用户可能填 https://host/v1、https://host/v1/ 或 https://host/v1/chat/completions，
// 三种写法都要能用。
func aiChatEndpoint(baseURL string) string {
	v := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if v == "" {
		return ""
	}
	if strings.HasSuffix(v, "/chat/completions") {
		return v
	}
	return v + "/chat/completions"
}

// normalizeAIBaseURL 校验并归一化用户填写的接口地址；空值允许（表示先不配）。
func normalizeAIBaseURL(raw string) (string, error) {
	v := strings.TrimRight(strings.TrimSpace(raw), "/")
	if v == "" {
		return "", nil
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return "", fmt.Errorf("接口地址需以 http:// 或 https:// 开头")
	}
	return strings.TrimSuffix(v, "/chat/completions"), nil
}

func aiQuotaLimit() int {
	if curatedRole() == "curated" {
		return 0
	}
	return aiFreeMonthlyQuota
}

// -----------------------
// HTTP API
// -----------------------

// aiStatusHandler 返回可用性与本月的用量，界面据此决定按钮状态与提示文案。
func aiStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cfg, path := currentAIConfig()
	used, err := sqlite.AIUsage(sqlite.AIMonthKey(time.Now()))
	if err != nil {
		gologger.Debug().Msgf("读取 AI 用量失败: %v", err)
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: aiStatusPayload{
		Configured: aiReady(cfg),
		Model:      strings.TrimSpace(cfg.Model),
		BaseURL:    strings.TrimSpace(cfg.BaseURL),
		ConfigPath: resolveClusterConfigPath(path),
		QuotaLimit: aiQuotaLimit(),
		QuotaUsed:  used,
	}})
}

func aiConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	cfg, path := currentAIConfig()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: aiConfigPayload{
		BaseURL:    cfg.BaseURL,
		Model:      cfg.Model,
		APIKey:     cfg.APIKey,
		TimeoutSec: cfg.TimeoutSec,
		MaxTokens:  cfg.MaxTokens,
		ConfigPath: resolveClusterConfigPath(path),
	}})
}

// aiConfigPutHandler 保存 AI 配置：先写回 afrog-config.yaml，再更新内存态，保存即生效。
func aiConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持PUT方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req aiConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	baseURL, err := normalizeAIBaseURL(req.BaseURL)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	next := config.AI{
		BaseURL:    baseURL,
		Model:      strings.TrimSpace(req.Model),
		APIKey:     strings.TrimSpace(req.APIKey),
		TimeoutSec: clampInt(req.TimeoutSec, 5, 600, 60),
		MaxTokens:  clampInt(req.MaxTokens, 64, 8192, 1200),
	}

	_, path := currentAIConfig()
	path = resolveClusterConfigPath(path)
	if err := config.UpdateAISection(path, next); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "写入配置文件失败：" + err.Error()})
		return
	}

	aiMu.Lock()
	aiCfg = next
	aiPath = path
	aiMu.Unlock()

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已保存，立即生效", Data: aiConfigPayload{
		BaseURL:    next.BaseURL,
		Model:      next.Model,
		APIKey:     next.APIKey,
		TimeoutSec: next.TimeoutSec,
		MaxTokens:  next.MaxTokens,
		ConfigPath: path,
	}})
}

func clampInt(v, min, max, fallback int) int {
	if v <= 0 {
		return fallback
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// -----------------------
// 研判：证据 -> 模型 -> 流式回传
// -----------------------

// -----------------------
// 流式回答的公共骨架
// -----------------------

// aiStream 是一次 SSE 响应的写入器。
type aiStream struct {
	send func(event string, data any)
	fail func(msg string)
}

func newAIStream(w http.ResponseWriter) *aiStream {
	w.Header().Del("Content-Type")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	fl, _ := w.(http.Flusher)
	bw := bufio.NewWriter(w)
	send := func(event string, data any) {
		_, _ = bw.WriteString("event: ")
		_, _ = bw.WriteString(event)
		_, _ = bw.WriteString("\n")
		b, _ := json.Marshal(data)
		_, _ = bw.WriteString("data: ")
		_, _ = bw.Write(b)
		_, _ = bw.WriteString("\n\n")
		_ = bw.Flush()
		if fl != nil {
			fl.Flush()
		}
	}
	return &aiStream{
		send: send,
		// 失败事件刻意不叫 "error"：EventSource 的 error 事件同时也是传输层错误的回调，
		// 两者同名会让前端分不清「服务端说清了原因」和「连接断了」。
		fail: func(msg string) { send("failed", map[string]string{"message": msg}) },
	}
}

// aiStreamFlow 是研判与摘要共用的流程：校验配置 → 组装证据 → 查缓存 → 校验额度 → 调模型 → 写缓存。
//
// seed 是缓存键的原始材料（各接口拼自己的业务标识）；prepare 负责各自的数据读取与提示词组装，
// 返回的 errMsg 非空表示「不必调用模型，直接把原因告诉用户」。
func aiStreamFlow(w http.ResponseWriter, ctx context.Context, seed string, force bool, prepare func(cfg config.AI) (system, user, errMsg string)) {
	stream := newAIStream(w)

	cfg, _ := currentAIConfig()
	if !aiReady(cfg) {
		stream.fail("还没有配置模型接口。请在「设置 → AI 辅助」里填写接口地址、模型名与 API Key。")
		return
	}

	system, user, errMsg := prepare(cfg)
	if errMsg != "" {
		stream.fail(errMsg)
		return
	}

	cacheKey := aiCacheKey(seed, cfg.Model)
	// force=1 用于「重新生成」：跳过读取缓存，但仍然写入，方便用户换到满意的一份。
	if !force {
		if cached, ok, err := sqlite.GetAICache(cacheKey); err == nil && ok {
			stream.send("meta", map[string]any{"cached": true, "model": cfg.Model})
			stream.send("delta", map[string]string{"t": cached})
			stream.send("done", map[string]any{"cached": true})
			return
		} else if err != nil {
			gologger.Debug().Msgf("读取 AI 缓存失败: %v", err)
		}
	}

	// 额度在「真的要调用模型」时才扣：命中缓存不花钱，也就不该占额度。
	used, allowed, err := sqlite.TryUseAIQuota(sqlite.AIMonthKey(time.Now()), aiQuotaLimit())
	if err != nil {
		gologger.Debug().Msgf("AI 额度校验失败: %v", err)
	}
	if !allowed {
		stream.fail(fmt.Sprintf("本月免费次数已用完（%d 次），升级 Curated 会员可不限次。", used))
		return
	}

	stream.send("meta", map[string]any{"cached": false, "model": cfg.Model, "quota_used": used})

	text, err := aiStreamCompletion(ctx, cfg, system, user, func(delta string) {
		stream.send("delta", map[string]string{"t": delta})
	})
	if err != nil {
		stream.fail(err.Error())
		return
	}
	if strings.TrimSpace(text) == "" {
		stream.fail("模型没有返回内容，请稍后重试。")
		return
	}

	if err := sqlite.PutAICache(cacheKey, text, cfg.Model); err != nil {
		gologger.Debug().Msgf("写入 AI 缓存失败: %v", err)
	}
	stream.send("done", map[string]any{"cached": false})
}

// -----------------------
// 命中研判
// -----------------------

// aiVerdictHandler 把一条命中的研判结果以 SSE 流式返回。
//
// 用 GET + 查询参数（而不是 POST body）是为了前端能直接用 EventSource：
// 它自带重连与标准的逐段解析，比手写 fetch 流处理更少出错。
//
// 任何失败都以 failed 事件返回，而不是 HTTP 状态码：EventSource 只能拿到
// 「连接失败」，看不到响应体，用事件才能把「未配置模型 / 额度用完 / Key 无效」
// 这些具体原因显示给用户。
func aiVerdictHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	vulid := strings.TrimSpace(q.Get("vulid"))
	target := strings.TrimSpace(q.Get("target"))
	fulltarget := strings.TrimSpace(q.Get("fulltarget"))
	taskID := strings.TrimSpace(q.Get("taskid"))
	force := strings.TrimSpace(q.Get("force")) == "1"

	// 缓存键用「PoC + 目标 + 模型」，换模型会重新研判。
	seed := aiCacheSeed("verdict", vulid, target, fulltarget, taskID)

	aiStreamFlow(w, r.Context(), seed, force, func(cfg config.AI) (string, string, string) {
		if vulid == "" || target == "" {
			return "", "", "缺少 PoC 或目标信息，无法定位这条命中。"
		}
		evidence, err := sqlite.SelectHitEvidence(taskID, vulid, target, fulltarget)
		if err != nil {
			return "", "", "读取命中证据失败：" + err.Error()
		}
		if evidence == nil {
			return "", "", "找不到这条命中的原始记录（可能已不在保留范围内），请从扫描结果页打开。"
		}
		system, user := aiVerdictPrompt(evidence)
		return system, user, ""
	})
}

// -----------------------
// 报告摘要
// -----------------------

// aiSummaryHandler 生成报告执行摘要（SSE 流式）。
//
// 参数二选一：task=<任务ID> 出「某次扫描」的摘要；不传 task 时按 severity / keyword
// 对当前筛选范围做汇总。跨任务的摘要会在提示词里如实写明范围，避免被误当成单次结论。
func aiSummaryHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	taskID := strings.TrimSpace(q.Get("task"))
	severity := strings.TrimSpace(q.Get("severity"))
	keyword := strings.TrimSpace(q.Get("keyword"))
	force := strings.TrimSpace(q.Get("force")) == "1"

	seed := aiCacheSeed("summary", taskID, severity, keyword)

	aiStreamFlow(w, r.Context(), seed, force, func(cfg config.AI) (string, string, string) {
		data, err := sqlite.SelectSummaryData(taskID, severity, keyword)
		if err != nil {
			return "", "", "读取扫描结果失败：" + err.Error()
		}
		if len(data.Findings) == 0 {
			if taskID != "" {
				return "", "", "这次扫描没有命中任何漏洞，无需生成摘要。"
			}
			return "", "", "当前筛选下没有命中记录，先跑一次扫描或放宽筛选条件。"
		}
		system, user := aiSummaryPrompt(data)
		return system, user, ""
	})
}

// aiCacheSeed 把若干业务标识拼成一个稳定的缓存原料。
func aiCacheSeed(parts ...string) string {
	return strings.Join(parts, "\x00")
}

// aiCacheKey 对缓存原料加模型名后取哈希：同一条命中换模型会重新研判。
func aiCacheKey(seed, model string) string {
	sum := sha256.Sum256([]byte(seed + "\x00" + strings.TrimSpace(model)))
	return hex.EncodeToString(sum[:])
}

// -----------------------
// 模型调用（OpenAI 兼容）
// -----------------------

type aiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiChatRequest struct {
	Model       string          `json:"model"`
	Messages    []aiChatMessage `json:"messages"`
	Stream      bool            `json:"stream"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens"`
}

// aiStreamCompletion 调用模型并逐段回调增量文本，返回完整文本。
//
// 流式不只是为了好看：研判动辄十几秒，逐字输出让用户立刻看到「它在思考」，
// 而不是盯着一个转圈的空抽屉怀疑是不是卡死了。
func aiStreamCompletion(ctx context.Context, cfg config.AI, system, user string, onDelta func(string)) (string, error) {
	body, err := json.Marshal(aiChatRequest{
		Model: cfg.Model,
		Messages: []aiChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Stream:      true,
		Temperature: aiTemperature,
		MaxTokens:   cfg.MaxTokens,
	})
	if err != nil {
		return "", fmt.Errorf("构造请求失败：%s", err.Error())
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := aiChatEndpoint(cfg.BaseURL)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("模型地址无效：%s", err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("研判已取消")
		}
		return "", fmt.Errorf("无法连接模型服务：%s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("%s", aiUpstreamError(resp.StatusCode, endpoint, string(detail)))
	}

	var full strings.Builder
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if payload == "[DONE]" {
					break
				}
				if delta := aiDeltaFromChunk(payload); delta != "" {
					full.WriteString(delta)
					onDelta(delta)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ctx.Err() != nil {
				return full.String(), fmt.Errorf("研判已取消")
			}
			return full.String(), fmt.Errorf("读取模型响应失败：%s", err.Error())
		}
	}
	return full.String(), nil
}

// aiDeltaFromChunk 从一帧 SSE 增量里取出正文；不是可解析的增量帧时返回空串
// （心跳、注释行、usage 尾帧都会走到这里，直接忽略即可）。
func aiDeltaFromChunk(payload string) string {
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
		return ""
	}
	if len(chunk.Choices) == 0 {
		return ""
	}
	if c := chunk.Choices[0].Delta.Content; c != "" {
		return c
	}
	// 少数服务商在 stream 模式下也用 message 字段整段返回，一并兼容。
	return chunk.Choices[0].Message.Content
}

// aiUpstreamError 把上游状态码翻译成用户能照着做的事，而不是把裸 JSON 甩给用户。
func aiUpstreamError(status int, endpoint, detail string) string {
	hint := strings.TrimSpace(detail)
	if len(hint) > 300 {
		hint = hint[:300]
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "模型服务拒绝了这次请求（检查 ai.api_key 是否正确、是否有该模型的权限）"
	case http.StatusNotFound:
		return "模型地址不对：" + endpoint + " 返回 404（检查 ai.base_url，通常需要带上 /v1）"
	case http.StatusTooManyRequests:
		return "模型服务限流或账户额度不足（HTTP 429），请稍后再试"
	}
	if status >= 500 {
		return fmt.Sprintf("模型服务异常（HTTP %d），请稍后再试", status)
	}
	if hint != "" {
		return fmt.Sprintf("模型返回 HTTP %d：%s", status, hint)
	}
	return fmt.Sprintf("模型返回 HTTP %d", status)
}

// -----------------------
// 提示词与证据处理
// -----------------------

const aiSystemPrompt = `你是资深漏洞研判专家，负责复核 afrog（漏洞扫描器）的一条命中结果，帮助工程师决定「先处理哪条、要不要花时间复现」。

必须遵守：
1. 只依据用户给出的证据（PoC 元信息、原始请求、原始响应）推断；不得引入证据里没有的事实。
2. 证据不足时必须明确说「证据不足」；严禁编造 CVE 编号、厂商公告、未提供的响应内容或未验证的执行结果。
3. 输出简体中文 Markdown，严格使用下面六个二级标题，不要开场白、不要总结性客套话：
## 结论
一句话说明这是不是真实漏洞，并给出置信度（高/中/低）。
## 判定依据
逐条列出支撑结论的证据，指明来自哪一段请求或响应（例如「响应体中出现了计算后的结果值」）。
## 误报可能
给出具体的误报场景（例如「仅回显了 payload，未体现执行结果」）。没有明显风险时写「未发现明显误报特征」。
## 人工验证
3 步以内、可直接照做的确认动作（含需要替换的参数）。
## 危害与影响
说清能被利用到什么程度、影响范围有多大。
## 修复建议
可落地的动作：升级版本、配置变更、临时缓解措施。`

// aiVerdictPrompt 组装 system / user 两条消息。
func aiVerdictPrompt(evidence *db2.HitEvidence) (string, string) {
	meta := parseAIPocMeta(evidence.Poc)

	var b strings.Builder
	b.WriteString("请复核下面这条扫描命中。\n\n")
	b.WriteString("### 命中信息\n")
	b.WriteString("- 目标：" + fallbackString(evidence.FullTarget, evidence.Target) + "\n")
	b.WriteString("- PoC：" + fallbackString(evidence.VulName, evidence.VulID) + "（id: " + evidence.VulID + "）\n")
	b.WriteString("- 严重级别：" + fallbackString(evidence.Severity, "未知") + "\n")
	if evidence.Created != "" {
		b.WriteString("- 命中时间：" + evidence.Created + "\n")
	}
	if meta.Severity != "" && !strings.EqualFold(meta.Severity, evidence.Severity) {
		b.WriteString("- PoC 声明的级别：" + meta.Severity + "\n")
	}

	b.WriteString("\n### PoC 元信息（来自本地 PoC 文件）\n")
	if meta.Description != "" {
		b.WriteString("描述：" + meta.Description + "\n")
	}
	if meta.Affected != "" {
		b.WriteString("影响版本：" + meta.Affected + "\n")
	}
	if meta.Solutions != "" {
		b.WriteString("PoC 给出的修复建议：" + meta.Solutions + "\n")
	}
	if len(meta.Reference) > 0 {
		b.WriteString("参考链接：" + strings.Join(meta.Reference, " ") + "\n")
	}
	if meta.Description == "" && meta.Affected == "" && len(meta.Reference) == 0 {
		b.WriteString("（该 PoC 没有提供额外元信息）\n")
	}

	req, reqCut := truncateUTF8(maskEvidence(strings.TrimSpace(evidence.Request)), aiEvidenceRequestLimit)
	resp, respCut := truncateUTF8(maskEvidence(strings.TrimSpace(evidence.Response)), aiEvidenceResponseLimit)

	b.WriteString("\n### 原始请求（已隐藏敏感请求头）\n```http\n")
	if req == "" {
		b.WriteString("（未记录到请求内容）\n")
	} else {
		b.WriteString(req + "\n")
	}
	if reqCut {
		b.WriteString("（注：请求体过长，已截断）\n")
	}
	b.WriteString("```\n")

	b.WriteString("\n### 原始响应（已隐藏敏感响应头）\n```http\n")
	if resp == "" {
		b.WriteString("（未记录到响应内容）\n")
	} else {
		b.WriteString(resp + "\n")
	}
	if respCut {
		b.WriteString("（注：响应体过长，已截断）\n")
	}
	b.WriteString("```\n")

	return aiSystemPrompt, b.String()
}

const aiSummarySystemPrompt = `你是资深安全顾问，负责为一次漏洞扫描结果写「执行摘要」，读者是客户方的管理层与项目负责人（不一定懂技术）。

必须遵守：
1. 只依据给出的统计数据与条目清单，不得引入其中没有的事实，也不得编造 CVE 编号、厂商公告或补丁号。
2. 数字必须与给出的统计一致；没给的数据不要臆测（例如未提供资产归属就不要推断业务系统名称）。
3. 输出简体中文 Markdown，严格使用下面四个二级标题，不要开场白、不要客套话：
## 执行摘要
3~5 句话讲清：扫了什么范围、整体情况如何、最需要关注什么。面向非技术读者，不要罗列 PoC 名称。
## 整体风险评级
在高/中/低中给出唯一一档，并用一句话说明依据（结合最高危害与高危条目占比）。
## 关键风险
按处置优先级列出不超过 5 条。每条写成：风险（一句话说清是什么、影响什么）→ 建议动作（先做什么）。要引用具体目标与等级，但不要粘贴长篇技术细节。
## 处置建议
先说「下一步先做什么」（例如先去人工确认哪几条），再说哪些类型可以延后处理。`

// aiSummaryPrompt 组装摘要的 system / user 两条消息。
//
// 摘要喂给模型的是「统计 + 条目清单」，而不是原始请求响应：报告摘要要的是全局判断，
// 逐条技术细节既贵又会把结论带偏（那也是「命中研判」负责的事）。
func aiSummaryPrompt(data *db2.SummaryData) (string, string) {
	var b strings.Builder
	b.WriteString("请为下面这次扫描结果写执行摘要。\n\n### 扫描范围\n")

	if data.Scope == "task" {
		b.WriteString("- 范围：单次扫描任务\n")
		if data.TaskName != "" {
			b.WriteString("- 任务名：" + data.TaskName + "\n")
		}
		b.WriteString("- 来源：" + aiSourceLabel(data.TaskSource) + "\n")
		if data.StartedAt != "" || data.EndedAt != "" {
			b.WriteString("- 开始 / 结束：" + fallbackString(data.StartedAt, "—") + " ~ " + fallbackString(data.EndedAt, "—") + "\n")
		}
		if data.TotalTargets > 0 {
			b.WriteString(fmt.Sprintf("- 目标数：%d\n", data.TotalTargets))
		}
		if data.TotalPocs > 0 {
			b.WriteString(fmt.Sprintf("- 加载 PoC 数：%d\n", data.TotalPocs))
		}
		if data.TotalScans > 0 {
			b.WriteString(fmt.Sprintf("- 请求总数（约）：%d\n", data.TotalScans))
		}
	} else {
		b.WriteString("- 范围：跨任务的筛选结果，**不是单次扫描**（不要把结论写成「本次扫描」）\n")
		if data.Severity != "" {
			b.WriteString("- 严重级别筛选：" + data.Severity + "\n")
		}
		if data.Keyword != "" {
			b.WriteString("- 关键字筛选：" + data.Keyword + "\n")
		}
	}

	b.WriteString("\n### 命中统计\n")
	counts := map[string]int64{}
	var total int64
	for k, v := range data.SeverityDist {
		counts[k] = v
		total += v
	}
	b.WriteString(fmt.Sprintf("- 命中条目（按 PoC + 目标聚合）：%d 条\n", total))
	b.WriteString(fmt.Sprintf("- 原始命中记录：%d 条\n", data.HitRows))
	if total == 0 {
		b.WriteString("- 各严重级别：无\n")
	}
	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if n, ok := counts[level]; ok && n > 0 {
			b.WriteString(fmt.Sprintf("- %s：%d 条\n", level, n))
		}
	}

	b.WriteString("\n### 命中条目（已按严重级别与命中次数排序）\n")
	for i, f := range data.Findings {
		name := fallbackString(f.VulName, f.VulID)
		line := fmt.Sprintf("%d. [%s] %s（%s）命中 %d 次", i+1, fallbackString(f.Severity, "未知"), name, fallbackString(f.FullTarget, f.Target), f.HitCount)
		if label := aiLedgerStatusLabel(f.Status); label != "" {
			line += "，台账状态：" + label
		}
		b.WriteString(line + "\n")
	}
	if data.Truncated {
		b.WriteString("（注：命中条目较多，这里只给出优先级最高的部分）\n")
	}

	return aiSummarySystemPrompt, b.String()
}

// aiSourceLabel 把任务来源翻译成中文，避免摘要里出现裸的 schedule / web。
func aiSourceLabel(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "schedule":
		return "计划扫描（自动触发）"
	case "web", "":
		return "Web 控制台手动发起"
	default:
		return source
	}
}

// aiLedgerStatusLabel 说明这条命中的人工状态；待确认不写，免得清单被噪音塞满。
func aiLedgerStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed":
		return "已人工确认"
	case "false_positive":
		return "已标记误报"
	case "fixed":
		return "已修复"
	default:
		return ""
	}
}

type aiPocMeta struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Affected    string
	Solutions   string
	Reference   []string
}

// parseAIPocMeta 从 result 表的 poc 字段里提取研判需要的元信息。
// 该字段是 poc.Poc 的 json.Marshal 结果（只有 yaml tag，所以键名是 Go 字段名）。
func parseAIPocMeta(raw string) aiPocMeta {
	var parsed struct {
		Id   string `json:"Id"`
		Info struct {
			Name        string   `json:"Name"`
			Severity    string   `json:"Severity"`
			Description string   `json:"Description"`
			Affected    string   `json:"Affected"`
			Solutions   string   `json:"Solutions"`
			Reference   []string `json:"Reference"`
		} `json:"Info"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return aiPocMeta{}
	}
	return aiPocMeta{
		ID:          strings.TrimSpace(parsed.Id),
		Name:        strings.TrimSpace(parsed.Info.Name),
		Severity:    strings.TrimSpace(parsed.Info.Severity),
		Description: strings.TrimSpace(parsed.Info.Description),
		Affected:    strings.TrimSpace(parsed.Info.Affected),
		Solutions:   strings.TrimSpace(parsed.Info.Solutions),
		Reference:   parsed.Info.Reference,
	}
}

// aiSensitiveHeaders 是要在发送前隐藏的请求/响应头。只掩码这些名字的行：
// 掩码过头会把判定所需的特征（payload、回显内容）也抹掉，那才是真的帮倒忙。
var aiSensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"token":               true,
	"password":            true,
}

func maskEvidence(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		if !aiSensitiveHeaders[name] {
			continue
		}
		lines[i] = line[:idx] + ": <已隐藏>"
	}
	return strings.Join(lines, "\n")
}

// truncateUTF8 按字节上限截断，但不切碎多字节字符。
func truncateUTF8(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…", true
}

func fallbackString(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
