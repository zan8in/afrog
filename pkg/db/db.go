package db

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/gologger"
	snowflake "github.com/zan8in/pins/snowflake"
	"gopkg.in/yaml.v2"
)

type Result struct {
	TaskID      string        `json:"taskid"`
	VulID       string        `json:"vulid"`
	VulName     string        `json:"vulname"`
	Target      string        `json:"target"`
	FullTarget  string        `json:"fulltarget,omitempty"`
	Severity    string        `json:"severity"`
	Poc         *poc.Poc      `json:"poc,omitempty"`
	Result      []*PocResult  `json:"pocresult,omitempty"`
	Created     time.Time     `json:"created"`
	FingerPrint any           `json:"fingerprint"`
	Extractor   yaml.MapSlice `json:"extractor"`
}

type PocResult struct {
	FullTarget string `json:"fulltarget,omitempty"`
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
	Other      Other  `json:"other,omitempty"`
}

type Other struct {
	Latency int64 `json:"latency,omitempty"`
}

type ResultData struct {
	ID          int64
	TaskID      string
	VulID       string
	VulName     string
	Target      string
	FullTarget  string
	Severity    string
	Poc         string
	Result      string
	Created     string
	FingerPrint string
	Extractor   string
	ResultList  []PocResult
	PocInfo     poc.Poc
}

// HitEvidence 是「AI 研判」要喂给模型的证据：一条命中的 PoC 元信息 + 原始请求/响应。
//
// 只有真实证据才能让模型判断「这次命中为什么成立、有没有可能是误报」；
// 请求/响应在发送前会在 web 层做脱敏与截断。
type HitEvidence struct {
	TaskID     string
	VulID      string
	VulName    string
	Severity   string
	Target     string
	FullTarget string
	Created    string
	// Poc 是 result 表的 poc 字段原文（含 description / reference 等 PoC 元信息）。
	Poc      string
	Request  string
	Response string
}

// SummaryFinding 是报告摘要里的一条命中（按「PoC + 目标」聚合后的粒度）。
type SummaryFinding struct {
	VulID      string
	VulName    string
	Target     string
	FullTarget string
	Severity   string
	HitCount   int64
	// Status 是台账里的人工状态（pending / confirmed / false_positive / fixed）：
	// 摘要要能区分「已确认的漏洞」和「用户已标为误报的条目」。
	Status    string
	ProjectID string
}

// SummaryData 是生成报告摘要所需的全部聚合信息。
type SummaryData struct {
	// 任务元信息（按任务出摘要时才有；跨任务的筛选场景为空）
	TaskID       string
	TaskName     string
	TaskSource   string
	TaskStatus   string
	CreatedAt    string
	StartedAt    string
	EndedAt      string
	TotalTargets int
	TotalPocs    int
	TotalScans   int

	// 统计口径：Findings 是聚合后的条目，HitRows 是未聚合的命中条数
	Findings     []SummaryFinding
	SeverityDist map[string]int64
	HitRows      int64
	Truncated    bool

	// 本次摘要覆盖的范围（task / filter），用于在提示词里说明「扫的是哪一片数据」
	Scope    string
	Severity string
	Keyword  string
}

// LedgerRow 是漏洞台账的一行：由 result 表按「PoC + 目标」聚合，再叠加人工状态与备注。
type LedgerRow struct {
	VulID      string `db:"vulid" json:"vulid"`
	VulName    string `db:"vulname" json:"vulname"`
	Target     string `db:"target" json:"target"`
	FullTarget string `db:"fulltarget" json:"fulltarget"`
	Severity   string `db:"severity" json:"severity"`
	FirstSeen  string `db:"first_seen" json:"first_seen"`
	LastSeen   string `db:"last_seen" json:"last_seen"`
	HitCount   int64  `db:"hit_count" json:"hit_count"`
	Status     string `db:"status" json:"status"`
	Note       string `db:"note" json:"note"`
	ProjectID  string `db:"project_id" json:"project_id"`
	UpdatedAt  string `db:"updated_at" json:"updated_at"`
}

// LedgerStats 是各状态的数量分布。
type LedgerStats struct {
	Pending       int64 `json:"pending"`
	Confirmed     int64 `json:"confirmed"`
	FalsePositive int64 `json:"false_positive"`
	Fixed         int64 `json:"fixed"`
}

// TaskFinding 是一次扫描中的一条命中（按「PoC + 目标」聚合后的最小单元），
// 用于扫描差异对比。
type TaskFinding struct {
	VulID      string `db:"vulid" json:"vulid"`
	VulName    string `db:"vulname" json:"vulname"`
	Target     string `db:"target" json:"target"`
	FullTarget string `db:"fulltarget" json:"fulltarget"`
	Severity   string `db:"severity" json:"severity"`
	HitCount   int64  `db:"hit_count" json:"hit_count"`
}

// ScanTaskRow 是一次扫描的任务元数据快照。
//
// 任务的实时状态活在服务进程内存里（pkg/web 的 TaskManager），进程一停就没了；
// 但计划扫描是长期存在的，重启后用户仍要能看到「上次跑了什么、结果如何」，
// 因此把元数据落库。命中明细不在这里——它只以 result 表为准（按 taskid 关联），
// 本表只保留任务列表与详情页需要的展示字段。
type ScanTaskRow struct {
	TaskID     string `db:"taskid" json:"taskid"`
	Name       string `db:"name" json:"name"`
	Status     string `db:"status" json:"status"`
	Source     string `db:"source" json:"source"`
	ScheduleID string `db:"schedule_id" json:"schedule_id"`
	ProjectID  string `db:"project_id" json:"project_id"`
	// TargetsRaw / HitsRaw 是存储格式，对外走 Targets / Hits。
	TargetsRaw string         `db:"targets" json:"-"`
	Targets    []string       `db:"-" json:"targets"`
	HitsRaw    string         `db:"hits" json:"-"`
	Hits       map[string]int `db:"-" json:"hits"`
	HitTotal   int            `db:"hit_total" json:"hit_total"`
	Percent    int            `db:"percent" json:"percent"`
	Finished   int            `db:"finished" json:"finished"`
	Total      int            `db:"total" json:"total"`
	ElapsedMs  int64          `db:"elapsed_ms" json:"elapsed_ms"`
	// 引擎开扫前的前置汇总，对应 scan_info 事件。
	TotalTargets int    `db:"total_targets" json:"total_targets"`
	TotalPocs    int    `db:"total_pocs" json:"total_pocs"`
	TotalScans   int    `db:"total_scans" json:"total_scans"`
	OOBEnabled   bool   `db:"oob_enabled" json:"oob_enabled"`
	OOBStatus    string `db:"oob_status" json:"oob_status"`
	Error        string `db:"error" json:"error"`
	CreatedAt    string `db:"created_at" json:"created_at"`
	StartedAt    string `db:"started_at" json:"started_at"`
	EndedAt      string `db:"ended_at" json:"ended_at"`
	UpdatedAt    string `db:"updated_at" json:"updated_at"`
}

// AssetRow 是一条资产。address（归一化后）是唯一键，也是 id。
//
// TagsRaw 只用于扫描落库，对外 JSON 走 Tags 数组，避免前端再关心存储格式。
type AssetRow struct {
	ID          string   `db:"id" json:"id"`
	Address     string   `db:"address" json:"address"`
	Type        string   `db:"type" json:"type"`
	TagsRaw     string   `db:"tags" json:"-"`
	Tags        []string `db:"-" json:"tags"`
	Source      string   `db:"source" json:"source"`
	SourceRef   string   `db:"source_ref" json:"source_ref"`
	Starred     bool     `db:"starred" json:"starred"`
	Archived    bool     `db:"archived" json:"archived"`
	Note        string   `db:"note" json:"note"`
	FirstSeenAt string   `db:"first_seen_at" json:"first_seen_at"`
	LastScanAt  string   `db:"last_scan_at" json:"last_scan_at"`
	LastTaskID  string   `db:"last_task_id" json:"last_task_id"`
	ScanCount   int64    `db:"scan_count" json:"scan_count"`
}

var (
	LIMIT        = "100"
	DBName       = "afrog"
	TableName    = "result"
	SqliteCreate = `CREATE TABLE IF NOT EXISTS "result" (
		"id" INTEGER NOT NULL DEFAULT '',
		"taskid" text NOT NULL DEFAULT '',
		"vulid" text NOT NULL DEFAULT '',
		"vulname" text NOT NULL DEFAULT '',
		"target" TEXT NOT NULL DEFAULT '',
		"fulltarget" TEXT NOT NULL DEFAULT '',
		"severity" TEXT NOT NULL DEFAULT '',
		"poc" TEXT NOT NULL DEFAULT '',
		"result" TEXT NOT NULL DEFAULT '',
		"created" TEXT NOT NULL DEFAULT '',
		"fingerprint" TEXT NOT NULL DEFAULT '',
  		"extractor" TEXT NOT NULL DEFAULT '',
		PRIMARY KEY ("id")
	  );

	  CREATE INDEX IF NOT EXISTS "idx_search"
		ON "result" (
		"taskid",
		"vulid",
		"vulname",
		"severity"
		);
	  
	  CREATE INDEX IF NOT EXISTS "idx_severity"
	  ON "result" (
		"severity" ASC
	  );
	  
	  CREATE INDEX IF NOT EXISTS "idx_taskid"
	  ON "result" (
		"taskid" ASC
	  );

	  CREATE INDEX IF NOT EXISTS "idx_vulname"
	  ON "result" (
		"vulname"
	  );
	  
	  CREATE INDEX IF NOT EXISTS "idx_vulid"
	  ON "result" (
		"vulid"
	  );
	  `

	TaskID string
)

var SnowFlake *snowflake.Snowflake

func init() {
	TaskID = resolveTaskID()
	if err := NewSnowFlake(); err != nil {
		gologger.Fatal().Msgf("New SnowFlake failed: %v", err)
	}
}

// resolveTaskID 优先使用父进程通过 AFROG_TASK_ID 指定的任务 ID。
// 本地进程执行器会给子进程注入该变量，使子进程写入 sqlite 的结果能与父进程
// （控制面）持有的任务关联；未设置时维持原有的自生成逻辑。
func resolveTaskID() string {
	if v := strings.TrimSpace(os.Getenv("AFROG_TASK_ID")); v != "" {
		return v
	}
	return createTaskID()
}

func createTaskID() string {
	timestamp := time.Now().UnixNano()
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)
	randomNum := randomGenerator.Intn(10000)
	taskID := fmt.Sprintf("%d%d", timestamp, randomNum)
	return taskID
}

func DbName() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir failed: %w", err)
	}

	path := filepath.Join(homeDir, ".config", "afrog")
	// 权限收紧为 0700，避免其它系统用户读取数据库
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", fmt.Errorf("create db dir failed: %w", err)
	}

	return filepath.Join(path, DBName+".db"), nil
}

func NewSnowFlake() error {
	if node, err := snowflake.NewSnowflake(1); err != nil {
		return err
	} else {
		SnowFlake = node
		return nil
	}
}
