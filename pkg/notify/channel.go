package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/webhook/dingtalk"
	"github.com/zan8in/afrog/v3/pkg/webhook/wecom"
)

// Message 是一条待发送的通知。
type Message struct {
	Title string
	Lines []string
	// Level 用于钉钉/企微上色与通用 Webhook 的粗粒度分级。
	Level string
	// Extra 作为结构化字段放进通用 Webhook 的请求体，便于对接方解析。
	Extra map[string]any
}

// Text 返回标题与正文拼成的纯文本。
func (m Message) Text() string {
	parts := make([]string, 0, len(m.Lines)+1)
	if strings.TrimSpace(m.Title) != "" {
		parts = append(parts, m.Title)
	}
	parts = append(parts, m.Lines...)
	return strings.Join(parts, "\n")
}

// httpClient 供所有渠道复用。通知不应拖慢扫描，超时给短一些。
var httpClient = &http.Client{Timeout: 10 * time.Second}

// sendChannel 按渠道类型分发到对应实现。
func sendChannel(ctx context.Context, ch Channel, msg Message) error {
	switch ch.Type {
	case ChannelWebhook:
		return sendWebhook(ctx, ch, msg)
	case ChannelFeishu:
		return sendFeishu(ctx, ch, msg)
	case ChannelDingtalk:
		return sendDingtalk(ch, msg)
	case ChannelWecom:
		return sendWecom(ch, msg)
	case ChannelServerChan:
		return sendServerChan(ctx, ch, msg)
	default:
		return fmt.Errorf("unsupported channel type: %s", ch.Type)
	}
}

// webhookPayload 是通用 Webhook 的请求体。字段保持稳定，方便对接方按需解析。
type webhookPayload struct {
	Source string         `json:"source"`
	Title  string         `json:"title"`
	Text   string         `json:"text"`
	Level  string         `json:"level"`
	Time   string         `json:"time"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func sendWebhook(ctx context.Context, ch Channel, msg Message) error {
	body, err := json.Marshal(webhookPayload{
		Source: "afrog",
		Title:  msg.Title,
		Text:   msg.Text(),
		Level:  msg.Level,
		Time:   time.Now().Format(time.RFC3339),
		Extra:  msg.Extra,
	})
	if err != nil {
		return err
	}
	_, err = postJSON(ctx, ch.Target, body)
	return err
}

func sendFeishu(ctx context.Context, ch Channel, msg Message) error {
	body, err := json.Marshal(map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": msg.Text()},
	})
	if err != nil {
		return err
	}
	raw, err := postJSON(ctx, ch.Target, body)
	if err != nil {
		return err
	}
	// 飞书机器人失败时仍返回 HTTP 200，需要看业务码。
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &resp); err == nil && resp.Code != 0 {
		return fmt.Errorf("feishu rejected: code=%d msg=%s", resp.Code, resp.Msg)
	}
	return nil
}

// sendDingtalk 复用 pkg/webhook/dingtalk 的多 token 与 @ 能力。
// 级别过滤由上游按配置统一完成，这里不传 Range。
func sendDingtalk(ch Channel, msg Message) error {
	if len(msg.Lines) == 0 {
		return nil
	}
	d, err := dingtalk.New([]string{ch.Target}, ch.AtMobiles, "", ch.AtAll)
	if err != nil {
		return err
	}
	return d.SendMarkDownMessageBySlice(msg.Title, msg.Lines)
}

func sendWecom(ch Channel, msg Message) error {
	if len(msg.Lines) == 0 {
		return nil
	}
	w, err := wecom.New([]string{ch.Target}, ch.AtMobiles, "", ch.AtAll, true)
	if err != nil {
		return err
	}
	return w.SendMarkdown(msg.Title, msg.Lines)
}

// serverChanBase 是 Server 酱的接口前缀。抽成变量便于测试指向本地服务。
var serverChanBase = "https://sctapi.ftqq.com"

func sendServerChan(ctx context.Context, ch Channel, msg Message) error {
	endpoint := serverChanBase + "/" + url.PathEscape(ch.Target) + ".send"

	form := url.Values{}
	form.Set("title", msg.Title)
	form.Set("desp", strings.Join(msg.Lines, "\n\n"))

	status, raw, err := doRequest(ctx, http.MethodPost, endpoint,
		"application/x-www-form-urlencoded; charset=utf-8", []byte(form.Encode()))
	if err != nil {
		return err
	}
	if status >= http.StatusBadRequest {
		return fmt.Errorf("serverchan http %d: %s", status, snippet(raw))
	}

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &resp); err == nil && resp.Code != 0 {
		return fmt.Errorf("serverchan rejected: code=%d msg=%s", resp.Code, resp.Message)
	}
	return nil
}

// postJSON 发送 JSON 请求体并返回响应内容。
func postJSON(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	status, raw, err := doRequest(ctx, http.MethodPost, endpoint, "application/json; charset=utf-8", body)
	if err != nil {
		return nil, err
	}
	if status >= http.StatusBadRequest {
		return raw, fmt.Errorf("http %d: %s", status, snippet(raw))
	}
	return raw, nil
}

// doRequest 是所有渠道共用的底层调用。
// 这里只放行 http/https：webhook 地址由用户填写，避免被写出 file:// 之类的协议。
func doRequest(ctx context.Context, method, endpoint, contentType string, body []byte) (int, []byte, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return 0, nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return 0, nil, fmt.Errorf("unsupported scheme %q, want http or https", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// 限制读取长度：通知响应体只用来报错，不需要全量。
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// snippet 把响应内容裁成适合放进错误信息的一行。
func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
