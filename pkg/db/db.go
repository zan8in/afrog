package db

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
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

	  CREATE INDEX "idx_search"
		ON "result" (
		"taskid",
		"vulid",
		"vulname",
		"severity"
		);
	  
	  CREATE INDEX "idx_severity"
	  ON "result" (
		"severity" ASC
	  );
	  
	  CREATE INDEX "idx_taskid"
	  ON "result" (
		"taskid" ASC
	  );

	  CREATE INDEX "idx_vulname"
	  ON "result" (
		"vulname"
	  );
	  
	  CREATE INDEX "idx_vulid"
	  ON "result" (
		"vulid"
	  );`

	TaskID string
)

var SnowFlake *snowflake.Snowflake

func init() {
	TaskID = createTaskID()
	if err := NewSnowFlake(); err != nil {
		gologger.Fatal().Msgf("New SnowFlake failed: %v", err)
	}
}

func createTaskID() string {
	timestamp := time.Now().UnixNano()
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)
	randomNum := randomGenerator.Intn(10000)
	taskID := fmt.Sprintf("%d%d", timestamp, randomNum)
	return taskID
}

func DbName() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	path := path.Join(homeDir, ".config", "afrog")
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return ""
	}

	return filepath.Join(path, DBName+".db")
}

func NewSnowFlake() error {
	if node, err := snowflake.NewSnowflake(1); err != nil {
		return err
	} else {
		SnowFlake = node
		return nil
	}
}
