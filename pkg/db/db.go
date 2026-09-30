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
