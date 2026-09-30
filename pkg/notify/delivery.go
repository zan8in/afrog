package notify

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zan8in/gologger"
)

// 发送可见性是通知集成的信任基础：之前发送失败只写进进程日志，
// 用户在界面上完全看不到「到底发出去没有、为什么没发出去」。
// 这里把每次「发给某个渠道」的结果都留一条记录，并配上自动重试。

// deliveryRetries 是单渠道发送的额外重试次数。网络抖动不该让告警直接丢掉。
//
// 语义是「至少一次」：超时无法区分「没送到」和「送到了但响应丢了」，
// 因此极端情况下可能收到重复消息，但漏报的代价更高。
const deliveryRetries = 2

// deliveryLogCapacity 是内存里保留的最近发送记录条数。
// 只做「最近发生了什么」的观测，不落库：重启即清空是可接受的。
const deliveryLogCapacity = 200

// deliveryRetryDelay 是第 1、2 次重试前的等待时长。
var deliveryRetryDelay = [deliveryRetries]time.Duration{time.Second, 3 * time.Second}

// timeLayout 与扫描结果保持一致，便于在界面上并排展示。
const timeLayout = "2006-01-02 15:04:05"

// DeliveryRecord 是一次「发给某个渠道」的结果，用于界面上的发送记录。
type DeliveryRecord struct {
	ID          int64  `json:"id"`
	At          string `json:"at"`
	Event       string `json:"event"`
	Title       string `json:"title"`
	TaskID      string `json:"task_id"`
	TaskName    string `json:"task_name"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	ChannelType string `json:"channel_type"`
	OK          bool   `json:"ok"`
	// Attempts 是实际尝试次数（含自动重试），大于 1 说明中途抖动过。
	Attempts   int    `json:"attempts"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// DeliveryStats 是保留窗口内的成功/失败汇总。
type DeliveryStats struct {
	Total  int `json:"total"`
	OK     int `json:"ok"`
	Failed int `json:"failed"`
}

// deliveryEntry 在记录之外保留原始消息，供失败后手动重发。
type deliveryEntry struct {
	rec DeliveryRecord
	msg Message
}

// deliveryLog 是固定容量的发送记录环形缓冲。
type deliveryLog struct {
	mu     sync.Mutex
	items  []deliveryEntry
	nextID int64
}

func newDeliveryLog() *deliveryLog {
	return &deliveryLog{items: make([]deliveryEntry, 0, deliveryLogCapacity)}
}

func (l *deliveryLog) add(rec DeliveryRecord, msg Message) DeliveryRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.nextID++
	rec.ID = l.nextID
	l.items = append(l.items, deliveryEntry{rec: rec, msg: msg})
	if len(l.items) > deliveryLogCapacity {
		trimmed := make([]deliveryEntry, deliveryLogCapacity)
		copy(trimmed, l.items[len(l.items)-deliveryLogCapacity:])
		l.items = trimmed
	}
	return rec
}

// recent 返回最近 limit 条记录，最新的在前。
func (l *deliveryLog) recent(limit int) []DeliveryRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit <= 0 || limit > len(l.items) {
		limit = len(l.items)
	}
	out := make([]DeliveryRecord, 0, limit)
	for i := len(l.items) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, l.items[i].rec)
	}
	return out
}

func (l *deliveryLog) stats() DeliveryStats {
	l.mu.Lock()
	defer l.mu.Unlock()

	s := DeliveryStats{Total: len(l.items)}
	for _, it := range l.items {
		if it.rec.OK {
			s.OK++
		} else {
			s.Failed++
		}
	}
	return s
}

func (l *deliveryLog) find(id int64) (deliveryEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for i := len(l.items) - 1; i >= 0; i-- {
		if l.items[i].rec.ID == id {
			return l.items[i], true
		}
	}
	return deliveryEntry{}, false
}

// deliver 发送到单个渠道：失败按退避重试，并把最终结果写进发送记录。
// 这是所有发送路径（实时命中、汇总、异常、测试、重发）的唯一出口。
func (n *Notifier) deliver(ctx context.Context, sender Sender, ch Channel, msg Message) DeliveryRecord {
	started := time.Now()
	attempts := 0
	var lastErr error

	for attempt := 0; attempt <= deliveryRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(deliveryRetryDelay[attempt-1])
		}
		if ctx.Err() != nil {
			break
		}

		attempts++
		attemptCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		lastErr = sender(attemptCtx, ch, msg)
		cancel()
		if lastErr == nil {
			break
		}
	}

	rec := DeliveryRecord{
		At:          time.Now().Format(timeLayout),
		Event:       extraString(msg.Extra, "event"),
		Title:       msg.Title,
		TaskID:      extraString(msg.Extra, "task_id"),
		TaskName:    extraString(msg.Extra, "task_name"),
		ChannelID:   ch.ID,
		ChannelName: ch.Name,
		ChannelType: string(ch.Type),
		OK:          lastErr == nil,
		Attempts:    attempts,
		DurationMS:  time.Since(started).Milliseconds(),
	}
	if lastErr != nil {
		rec.Error = lastErr.Error()
		gologger.Warning().
			Str("channel", ch.Name).
			Str("type", string(ch.Type)).
			Msgf("notify send failed after %d attempt(s): %v", attempts, lastErr)
	}
	return n.log.add(rec, msg)
}

// RecentDeliveries 返回最近的发送记录与汇总。
func (n *Notifier) RecentDeliveries(limit int) ([]DeliveryRecord, DeliveryStats) {
	return n.log.recent(limit), n.log.stats()
}

// Resend 重新发送一条历史记录，用于自动重试仍失败后的手动补发。
//
// 渠道按 ID 从「当前配置」里取，而不是复用记录里的旧凭据——
// 用户改对了 token 之后再点重发，应该用新的配置。
func (n *Notifier) Resend(id int64) (DeliveryRecord, error) {
	entry, ok := n.log.find(id)
	if !ok {
		return DeliveryRecord{}, fmt.Errorf("发送记录不存在")
	}

	n.mu.Lock()
	cfg := n.cfg
	sender := n.sender
	n.mu.Unlock()

	var target *Channel
	for i := range cfg.Channels {
		if cfg.Channels[i].ID == entry.rec.ChannelID {
			target = &cfg.Channels[i]
			break
		}
	}
	if target == nil {
		return DeliveryRecord{}, fmt.Errorf("渠道已被删除，无法重发")
	}

	return n.deliver(context.Background(), sender, *target, entry.msg), nil
}

// extraString 从消息的结构化字段里取一个字符串值。
func extraString(extra map[string]any, key string) string {
	if extra == nil {
		return ""
	}
	if v, ok := extra[key].(string); ok {
		return v
	}
	return ""
}
