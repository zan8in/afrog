package sqlite

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/zan8in/gologger"
)

// 数据库可观测性：连接池等待与慢查询。
//
// 背景：整个进程只有一条 SQLite 连接（见 NewWebSqliteDB），读与写共用同一条。
// 一次全量导出就可能把连接占住，这期间被动命中写不进去、界面轮询也拿不到连接。
// 这类「队首阻塞」在没有指标时完全不可见，所以这里只补两件事：
//
//  1. 连接池等待的真实计数：database/sql 自带 WaitCount / WaitDuration，直接暴露；
//  2. 超过阈值的查询打一条 WARN，带上耗时、行数与 SQL 片段。
//
// 不做 SQL 重写、不做后台采样：只在查询返回时记一次，不给扫描主链路加开销。

const defaultSlowQueryThreshold = 200 * time.Millisecond

var (
	slowQueryThresholdNs atomic.Int64
	queriesObserved      atomic.Int64
	slowQueries          atomic.Int64
	slowestQueryNs       atomic.Int64
)

func init() {
	slowQueryThresholdNs.Store(int64(defaultSlowQueryThreshold))
}

// SetSlowQueryThreshold 调整慢查询日志阈值；<=0 表示关闭日志（计数仍然保留）。
func SetSlowQueryThreshold(d time.Duration) {
	slowQueryThresholdNs.Store(int64(d))
}

// PoolStat 是数据库层对外暴露的可观测快照。
//
// WaitCount / WaitDurationMs 是判断「是不是在等连接」的唯一依据：两者都为 0
// 说明瓶颈不在连接池，改读写分离没有意义。
type PoolStat struct {
	// 连接池现状
	MaxOpenConnections int   `json:"max_open_connections"`
	OpenConnections    int   `json:"open_connections"`
	InUse              int   `json:"in_use"`
	Idle               int   `json:"idle"`
	WaitCount          int64 `json:"wait_count"`
	WaitDurationMs     int64 `json:"wait_duration_ms"`
	// 查询耗时（只覆盖走 runResultQuery 的读路径）
	QueriesObserved int64 `json:"queries_observed"`
	SlowQueries     int64 `json:"slow_queries"`
	SlowestMs       int64 `json:"slowest_ms"`
	SlowThresholdMs int64 `json:"slow_threshold_ms"`
}

// PoolStats 返回当前快照；数据库未初始化时返回零值。
func PoolStats() PoolStat {
	st := PoolStat{
		QueriesObserved: queriesObserved.Load(),
		SlowQueries:     slowQueries.Load(),
		SlowestMs:       time.Duration(slowestQueryNs.Load()).Milliseconds(),
		SlowThresholdMs: time.Duration(slowQueryThresholdNs.Load()).Milliseconds(),
	}
	if dbx == nil {
		return st
	}
	s := dbx.Stats()
	st.MaxOpenConnections = s.MaxOpenConnections
	st.OpenConnections = s.OpenConnections
	st.InUse = s.InUse
	st.Idle = s.Idle
	st.WaitCount = s.WaitCount
	st.WaitDurationMs = s.WaitDuration.Milliseconds()
	return st
}

// observeQuery 记录一次读查询的耗时。
//
// 耗时从调用 SelectContext 开始算，因此包含「等连接」的时间——这正是要观测的部分。
// SQL 只截取片段：语句里没有参数值，不存在敏感数据。
func observeQuery(label, query string, start time.Time, rows int, err error) {
	elapsed := time.Since(start)
	queriesObserved.Add(1)

	for {
		cur := slowestQueryNs.Load()
		if int64(elapsed) <= cur || slowestQueryNs.CompareAndSwap(cur, int64(elapsed)) {
			break
		}
	}

	threshold := time.Duration(slowQueryThresholdNs.Load())
	if threshold <= 0 || elapsed < threshold {
		return
	}
	slowQueries.Add(1)

	snippet := strings.Join(strings.Fields(query), " ")
	if len(snippet) > 160 {
		snippet = snippet[:160] + "..."
	}
	gologger.Warning().Msgf("slow-query: %s took %dms (rows=%d, err=%v, sql=%s)",
		label, elapsed.Milliseconds(), rows, err, snippet)
}
