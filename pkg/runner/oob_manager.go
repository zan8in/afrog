package runner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

type OOBManager struct {
	adapter       *oobadapter.OOBAdapter
	pollInterval  time.Duration
	hitRetention  time.Duration
	mu            sync.Mutex
	waiters       map[string]*oobWaitEntry
	watchers      map[string]time.Time
	hits          map[string]oobHit
	events        map[string][]oobEvent
	seen          map[string]map[string]time.Time
	maxEvents     int
	maxSeen       int
	lastPolledAt  map[string]time.Time
	lastPollError map[string]time.Time
}

type OOBHitSnapshot struct {
	Filter     string
	FilterType string
	FirstAt    time.Time
	LastAt     time.Time
	Count      uint64
	Snippet    string
}

type oobHit struct {
	firstAt time.Time
	lastAt  time.Time
	count   uint64
	snippet string
}

type oobEvent struct {
	at        time.Time
	uniqueKey string
	snippet   string
	raw       string
}

type oobWaitEntry struct {
	filter     string
	filterType string
	done       chan struct{}
	refs       int
}

type oobWaitSnapshot struct {
	key    string
	filter string
	done   chan struct{}
}

func NewOOBManager(ctx context.Context, adapter *oobadapter.OOBAdapter, pollInterval time.Duration, hitRetention time.Duration) *OOBManager {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	if hitRetention <= 0 {
		hitRetention = 10 * time.Minute
	}
	m := &OOBManager{
		adapter:       adapter,
		pollInterval:  pollInterval,
		hitRetention:  hitRetention,
		waiters:       make(map[string]*oobWaitEntry),
		watchers:      make(map[string]time.Time),
		hits:          make(map[string]oobHit),
		events:        make(map[string][]oobEvent),
		seen:          make(map[string]map[string]time.Time),
		maxEvents:     50,
		maxSeen:       200,
		lastPolledAt:  make(map[string]time.Time),
		lastPollError: make(map[string]time.Time),
	}
	go m.loop(ctx)
	return m
}

func (m *OOBManager) Watch(filter string, filterType string) {
	if m == nil || m.adapter == nil || strings.TrimSpace(filter) == "" {
		return
	}
	if strings.TrimSpace(filterType) == "" {
		filterType = oobadapter.OOBDNS
	}
	key := filterType + "|" + filter
	now := time.Now().UTC()
	m.mu.Lock()
	if m.watchers == nil {
		m.watchers = make(map[string]time.Time)
	}
	m.watchers[key] = now
	if m.maxSeen > 0 && len(m.watchers) > m.maxSeen {
		n := len(m.watchers) - m.maxSeen
		for k := range m.watchers {
			delete(m.watchers, k)
			n--
			if n <= 0 {
				break
			}
		}
	}
	m.mu.Unlock()
}

func (m *OOBManager) Wait(filter string, filterType string, timeout time.Duration) bool {
	if m == nil || m.adapter == nil || filter == "" || timeout <= 0 {
		return false
	}
	if filterType == "" {
		filterType = oobadapter.OOBDNS
	}

	key := filterType + "|" + filter

	m.mu.Lock()
	if hit, ok := m.hits[key]; ok && m.hitRetention > 0 && time.Since(hit.lastAt) <= m.hitRetention {
		m.mu.Unlock()
		return true
	}
	if e, ok := m.waiters[key]; ok {
		e.refs++
		ch := e.done
		m.mu.Unlock()
		return waitClosed(ch, timeout)
	}

	e := &oobWaitEntry{
		filter:     filter,
		filterType: filterType,
		done:       make(chan struct{}),
		refs:       1,
	}
	m.waiters[key] = e
	ch := e.done
	m.mu.Unlock()

	ok := waitClosed(ch, timeout)

	m.mu.Lock()
	if cur, exists := m.waiters[key]; exists {
		cur.refs--
		if cur.refs <= 0 {
			delete(m.waiters, key)
		}
	}
	m.mu.Unlock()

	return ok
}

func (m *OOBManager) HitSnapshot(filter string, filterType string) (OOBHitSnapshot, bool) {
	if m == nil || filter == "" {
		return OOBHitSnapshot{}, false
	}
	if filterType == "" {
		filterType = oobadapter.OOBDNS
	}
	key := filterType + "|" + filter
	m.mu.Lock()
	h, ok := m.hits[key]
	retention := m.hitRetention
	m.mu.Unlock()
	if !ok {
		return OOBHitSnapshot{}, false
	}
	if retention > 0 && time.Since(h.lastAt) > retention {
		return OOBHitSnapshot{}, false
	}
	return OOBHitSnapshot{
		Filter:     filter,
		FilterType: filterType,
		FirstAt:    h.firstAt,
		LastAt:     h.lastAt,
		Count:      h.count,
		Snippet:    h.snippet,
	}, true
}

func (m *OOBManager) Evidence(filter string, filterType string, maxEvents int) string {
	if m == nil || filter == "" {
		return ""
	}
	if filterType == "" {
		filterType = oobadapter.OOBDNS
	}
	if maxEvents <= 0 {
		maxEvents = 5
	}

	key := filterType + "|" + filter
	m.mu.Lock()
	h, ok := m.hits[key]
	evs := append([]oobEvent(nil), m.events[key]...)
	m.mu.Unlock()
	if !ok {
		return ""
	}
	if m.hitRetention > 0 && time.Since(h.lastAt) > m.hitRetention {
		return ""
	}

	meta := "protocol=" + filterType + " count=" + itoaU64(h.count) + " last_at=" + h.lastAt.UTC().Format(time.RFC3339Nano)
	if len(evs) == 0 {
		if strings.TrimSpace(h.snippet) == "" {
			return meta
		}
		return meta + "\n" + h.snippet
	}
	if len(evs) > maxEvents {
		evs = evs[len(evs)-maxEvents:]
	}
	var b strings.Builder
	b.Grow(len(meta) + 32*len(evs))
	b.WriteString(meta)
	for _, ev := range evs {
		b.WriteString("\n[")
		b.WriteString(ev.at.UTC().Format(time.RFC3339Nano))
		b.WriteString("] ")
		s := strings.TrimSpace(ev.snippet)
		if s == "" {
			s = strings.TrimSpace(ev.raw)
		}
		if s != "" {
			b.WriteString(s)
		}
	}
	return b.String()
}

func waitClosed(ch <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

func (m *OOBManager) loop(ctx context.Context) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		typeGroup := m.snapshotWatchTargets()
		if len(typeGroup) == 0 {
			m.cleanupHits()
			continue
		}

		now := time.Now()
		for filterType, waiters := range typeGroup {
			m.mu.Lock()
			lastAt := m.lastPolledAt[filterType]
			m.mu.Unlock()
			if !lastAt.IsZero() && now.Sub(lastAt) < m.pollInterval {
				continue
			}

			records, err := m.adapter.PollRecords(filterType)
			m.mu.Lock()
			m.lastPolledAt[filterType] = now
			if err != nil {
				m.lastPollError[filterType] = now
			}
			m.mu.Unlock()
			if err != nil || len(records) == 0 {
				continue
			}

			hitKeys := make(map[string]chan struct{})
			for _, rec := range records {
				raw := strings.TrimSpace(rec.Raw)
				if raw == "" {
					continue
				}
				rawBytes := []byte(raw)

				at := rec.Timestamp
				if at.IsZero() {
					at = time.Now().UTC()
				} else {
					at = at.UTC()
				}

				uniq := strings.TrimSpace(rec.UniqueKey)
				if uniq == "" {
					sum := sha1.Sum([]byte(raw))
					uniq = hex.EncodeToString(sum[:])
				}

				sn := strings.TrimSpace(rec.Snippet)
				if sn == "" {
					sn = oobSnippet(rawBytes, 512)
				}

				for _, w := range waiters {
					if !m.adapter.Match(rawBytes, filterType, w.filter) {
						continue
					}
					if m.appendEvent(w.key, oobEvent{at: at, uniqueKey: uniq, snippet: sn, raw: raw}) {
						hitKeys[w.key] = w.done
					}
				}
			}

			if len(hitKeys) > 0 {
				m.mu.Lock()
				for key, ch := range hitKeys {
					if _, ok := m.waiters[key]; ok {
						delete(m.waiters, key)
						close(ch)
					}
				}
				m.mu.Unlock()
			}
		}

		m.cleanupHits()
	}
}

func (m *OOBManager) appendEvent(key string, ev oobEvent) bool {
	if m == nil || strings.TrimSpace(key) == "" || strings.TrimSpace(ev.uniqueKey) == "" {
		return false
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.seen == nil {
		m.seen = make(map[string]map[string]time.Time)
	}
	if m.events == nil {
		m.events = make(map[string][]oobEvent)
	}
	seenSet := m.seen[key]
	if seenSet == nil {
		seenSet = make(map[string]time.Time)
		m.seen[key] = seenSet
	}
	if last, ok := seenSet[ev.uniqueKey]; ok {
		if m.hitRetention <= 0 || now.Sub(last) <= m.hitRetention {
			return false
		}
	}
	seenSet[ev.uniqueKey] = now

	m.events[key] = append(m.events[key], ev)
	if m.maxEvents > 0 && len(m.events[key]) > m.maxEvents {
		m.events[key] = m.events[key][len(m.events[key])-m.maxEvents:]
	}

	h := m.hits[key]
	if h.count == 0 {
		h.firstAt = ev.at
		h.snippet = ev.snippet
	}
	h.lastAt = ev.at
	h.count++
	if strings.TrimSpace(h.snippet) == "" {
		h.snippet = ev.snippet
	}
	m.hits[key] = h

	if m.maxSeen > 0 && len(seenSet) > m.maxSeen {
		for k, t := range seenSet {
			if m.hitRetention > 0 && now.Sub(t) > m.hitRetention {
				delete(seenSet, k)
			}
		}
		if len(seenSet) > m.maxSeen {
			n := len(seenSet) - m.maxSeen
			for k := range seenSet {
				delete(seenSet, k)
				n--
				if n <= 0 {
					break
				}
			}
		}
	}

	return true
}

func (m *OOBManager) snapshotWaiters() map[string][]oobWaitSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.waiters) == 0 {
		return nil
	}
	group := make(map[string][]oobWaitSnapshot)
	for k, e := range m.waiters {
		group[e.filterType] = append(group[e.filterType], oobWaitSnapshot{
			key:    k,
			filter: e.filter,
			done:   e.done,
		})
	}
	return group
}

func (m *OOBManager) snapshotWatchTargets() map[string][]oobWaitSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.waiters) == 0 && len(m.watchers) == 0 {
		return nil
	}
	group := make(map[string][]oobWaitSnapshot)
	for k, e := range m.waiters {
		group[e.filterType] = append(group[e.filterType], oobWaitSnapshot{
			key:    k,
			filter: e.filter,
			done:   e.done,
		})
	}
	for key := range m.watchers {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		filterType := parts[0]
		filter := parts[1]
		group[filterType] = append(group[filterType], oobWaitSnapshot{
			key:    key,
			filter: filter,
			done:   nil,
		})
	}
	return group
}

func (m *OOBManager) cleanupHits() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.hits) == 0 {
		if m.hitRetention <= 0 {
			return
		}
		now := time.Now().UTC()
		for k, t := range m.watchers {
			if now.Sub(t) > m.hitRetention {
				delete(m.watchers, k)
			}
		}
		return
	}
	if m.hitRetention <= 0 {
		return
	}
	now := time.Now()
	for k, h := range m.hits {
		if now.Sub(h.lastAt) > m.hitRetention {
			delete(m.hits, k)
			delete(m.events, k)
			delete(m.seen, k)
		}
	}
	nowUTC := now.UTC()
	for k, t := range m.watchers {
		if nowUTC.Sub(t) > m.hitRetention {
			delete(m.watchers, k)
		}
	}
}

func oobSnippet(body []byte, max int) string {
	if len(body) == 0 || max <= 0 {
		return ""
	}
	if len(body) > max {
		body = body[:max]
	}
	return string(body)
}

func itoaU64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(b[i:])
}
