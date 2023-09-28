//go:build ignore
// +build ignore

package db

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/zan8in/afrog/v2/pkg/poc"
	"github.com/zan8in/afrog/v2/pkg/utils"
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

func init() {
	TaskID = createTaskID()
}

func createTaskID() string {
	timestamp := time.Now().UnixNano()
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)
	randomNum := randomGenerator.Intn(10000)
	taskID := fmt.Sprintf("%d%d", timestamp, randomNum)
	return taskID
}

func GetSqliteFullDBName() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	configFile := filepath.Join(homeDir, ".config", "afrog", DBName+".db")
	if !utils.Exists(configFile) {
		return configFile
	}
	return configFile
}
