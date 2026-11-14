package sqlite

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/zan8in/afrog/v3/pkg/observation"
)

// 观测流表：只追加、不更新，seq 即游标。
//
// 与 evidence 的区别：evidence 回答「这条命中凭什么成立」，observation 回答
// 「过程中还看到了什么」。去重键是 (project_id, id) 而不是 (taskid, id)：
// 同一事实重扫后不该新增行，Agent 才能把 obs_ 当作稳定引用。
const observationDDL = `CREATE TABLE IF NOT EXISTS "observation" (
	"seq"        INTEGER PRIMARY KEY AUTOINCREMENT,
	"id"         TEXT NOT NULL DEFAULT '',
	"project_id" TEXT NOT NULL DEFAULT '',
	"source"     TEXT NOT NULL DEFAULT '',
	"kind"       TEXT NOT NULL DEFAULT '',
	"subject"    TEXT NOT NULL DEFAULT '',
	"digest"     TEXT NOT NULL DEFAULT '',
	"payload"    TEXT NOT NULL DEFAULT '{}',
	"ts"         TEXT NOT NULL DEFAULT ''
  );
  CREATE UNIQUE INDEX IF NOT EXISTS "idx_observation_dedupe"
	ON "observation" ("project_id", "id");
  CREATE INDEX IF NOT EXISTS "idx_observation_subject"
	ON "observation" ("project_id", "subject", "seq");`

// observationMaxRows 是保留上限：事件增长远快于命中，必须有硬上限。
// 0 表示不限制，由 afrog-config.yaml 的 observe.max_rows 控制。
var observationMaxRows int64 = 200000

// SetObservationMaxRows 设置观测流保留行数上限；n <= 0 表示不限制。
//
// 只在启动阶段调用：裁剪发生在写协程里，运行时改值只会影响后续的裁剪批次。
func SetObservationMaxRows(n int) {
	if n < 0 {
		n = 0
	}
	atomic.StoreInt64(&observationMaxRows, int64(n))
}

func ensureObservation() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := execBusyRetry(observationDDL)
	return err
}

// ---------------------------------------------------------------------------
// 异步写入
// ---------------------------------------------------------------------------

// obsItem 既承载一条观测，也用作 flush 的屏障（done 非空时只回信号）。
type obsItem struct {
	obs  *observation.Observation
	done chan struct{}
}

var (
	observeMu      sync.Mutex
	observeCh      chan obsItem
	observeWG      sync.WaitGroup
	observeDropped uint64
)

// startObservationWriter 启动写协程；dbx 未初始化时什么都不做。
func startObservationWriter() {
	observeMu.Lock()
	defer observeMu.Unlock()
	if observeCh != nil || dbx == nil {
		return
	}
	ch := make(chan obsItem, 4096)
	observeCh = ch
	observeWG.Add(1)
	go func() {
		defer observeWG.Done()
		inserted := 0
		for item := range ch {
			if item.obs != nil {
				if err := insertObservation(item.obs); err == nil {
					inserted++
					if inserted%1000 == 0 {
						pruneObservations()
					}
				}
			}
			if item.done != nil {
				close(item.done)
			}
		}
	}()
}

// RecordObservation 把观测放进写协程的缓冲：永不阻塞扫描，缓冲满时丢弃。
//
// 观测流是尽力而为的旁路证据，宁可丢尾部，也不能让磁盘 I/O 拖慢端口扫描。
func RecordObservation(obs *observation.Observation) {
	if obs == nil || dbx == nil {
		return
	}
	startObservationWriter()

	observeMu.Lock()
	defer observeMu.Unlock()
	if observeCh == nil {
		return
	}
	select {
	case observeCh <- obsItem{obs: obs}:
	default:
		atomic.AddUint64(&observeDropped, 1)
	}
}

// FlushObservations 等待已入队的观测全部落库，供测试与需要确定性的调用方使用。
func FlushObservations() {
	if dbx == nil {
		return
	}
	startObservationWriter()

	done := make(chan struct{})
	observeMu.Lock()
	if observeCh == nil {
		observeMu.Unlock()
		return
	}
	observeCh <- obsItem{done: done}
	observeMu.Unlock()
	<-done
}

// DroppedObservations 返回因缓冲满被丢弃的条数。
func DroppedObservations() uint64 { return atomic.LoadUint64(&observeDropped) }

// stopObservationWriter 关闭写协程并等待已入队的数据落库。
func stopObservationWriter() {
	observeMu.Lock()
	ch := observeCh
	observeCh = nil
	if ch != nil {
		close(ch)
	}
	observeMu.Unlock()
	observeWG.Wait()
}

// ---------------------------------------------------------------------------
// 读写
// ---------------------------------------------------------------------------

func insertObservation(obs *observation.Observation) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	const insertSQL = `INSERT OR IGNORE INTO "observation"
		("id","project_id","source","kind","subject","digest","payload","ts")
		VALUES(?,?,?,?,?,?,?,?)`

	payload := string(obs.Payload)
	if payload == "" {
		payload = "{}"
	}
	_, err := execBusyRetry(insertSQL,
		obs.ID, obs.ProjectID, obs.Source, obs.Kind, obs.Subject, obs.Digest, payload, obs.Ts)
	return err
}

// InsertObservation 同步写入一条观测，供测试与少量确定性场景使用。
func InsertObservation(obs *observation.Observation) error {
	return insertObservation(obs)
}

// ObservationFilter 是观测流的查询条件。
type ObservationFilter struct {
	// SinceSeq 只返回 seq 严格大于它的记录。
	SinceSeq int64
	Sources  []string
	Kinds    []string
	// Subject 精确匹配；SubjectUnder 为真时改为「子树」匹配。
	Subject string
	// SubjectUnder 让 Subject 覆盖它下面的节点：host 命中 host:port，端点命中
	// 端点本身与它的参数节点。不做纯字符串前缀匹配，避免 a.example 命中
	// a.example.evil.com。
	SubjectUnder bool
	ProjectID    string
	Limit        int
}

// ObservationPage 是一页观测流。
type ObservationPage struct {
	Items   []observation.Observation `json:"items"`
	NextSeq int64                     `json:"next_seq"`
	HasMore bool                      `json:"has_more"`
}

// SelectObservations 按 seq 升序返回一页观测。
func SelectObservations(f ObservationFilter) (*ObservationPage, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	where := []string{`"seq" > ?`}
	args := []any{f.SinceSeq}
	if project := strings.TrimSpace(f.ProjectID); project != "" {
		where = append(where, `"project_id" = ?`)
		args = append(args, project)
	}
	if subject := strings.TrimSpace(f.Subject); subject != "" {
		if f.SubjectUnder {
			subject = strings.TrimRight(subject, "/")
			escaped := escapeLike(subject)
			where = append(where, `("subject" = ? OR "subject" LIKE ? ESCAPE '\' OR "subject" LIKE ? ESCAPE '\' OR "subject" LIKE ? ESCAPE '\')`)
			args = append(args, subject, escaped+":%", escaped+"/%", escaped+"#%")
		} else {
			where = append(where, `"subject" = ?`)
			args = append(args, subject)
		}
	}
	if len(f.Sources) > 0 {
		where = append(where, `"source" IN (`+placeholders(len(f.Sources))+`)`)
		for _, s := range f.Sources {
			args = append(args, s)
		}
	}
	if len(f.Kinds) > 0 {
		where = append(where, `"kind" IN (`+placeholders(len(f.Kinds))+`)`)
		for _, k := range f.Kinds {
			args = append(args, k)
		}
	}

	query := `SELECT "seq","id","project_id","source","kind","subject","ts","payload","digest"
		FROM "observation" WHERE ` + strings.Join(where, " AND ") + ` ORDER BY "seq" ASC LIMIT ?`
	args = append(args, limit+1)

	rows, err := dbx.Queryx(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]observation.Observation, 0, limit)
	for rows.Next() {
		var (
			obs     observation.Observation
			payload string
		)
		if err := rows.Scan(&obs.Seq, &obs.ID, &obs.ProjectID, &obs.Source, &obs.Kind,
			&obs.Subject, &obs.Ts, &payload, &obs.Digest); err != nil {
			return nil, err
		}
		if payload != "" {
			obs.Payload = json.RawMessage(payload)
		}
		items = append(items, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	page := &ObservationPage{NextSeq: f.SinceSeq}
	if len(items) > limit {
		items = items[:limit]
		page.HasMore = true
	}
	if len(items) > 0 {
		page.NextSeq = items[len(items)-1].Seq
	}
	page.Items = items
	return page, nil
}

// pruneObservations 在超出上限时删除最旧的 10%，避免每 1000 次插入都删一次。
func pruneObservations() {
	if dbx == nil {
		return
	}
	limit := atomic.LoadInt64(&observationMaxRows)
	if limit <= 0 {
		return
	}
	var count int64
	if err := dbx.Get(&count, `SELECT COUNT(*) FROM "observation"`); err != nil || count <= limit {
		return
	}
	remove := count / 10
	if remove <= 0 {
		remove = 1
	}
	_, _ = dbx.Exec(`DELETE FROM "observation" WHERE "seq" IN (
		SELECT "seq" FROM "observation" ORDER BY "seq" ASC LIMIT ?)`, remove)
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// escapeLike 转义 LIKE 通配符，配合 ESCAPE '\' 使用。
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
