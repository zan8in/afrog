package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/logoove/sqlite"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	randutil "github.com/zan8in/pins/rand"
)

var dbx *sqlx.DB
var insertChannel chan *result.Result
var wg sync.WaitGroup

// 可根据实际负载调整
var workerCount = 4

func InitX() error {

	// 使用带缓冲通道，避免生产者阻塞
	insertChannel = make(chan *result.Result, 1024)

	// 启动固定数量的 worker，避免无界并发写入导致 database is locked
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go saveToDatabaseX()
	}

	return nil
}

func SetResultX(result *result.Result) {
	insertChannel <- result
}

func saveToDatabaseX() {
	defer wg.Done()

	for r := range insertChannel {
		// @date 2023/10/12 added insert sqlite failed repeat 5 time.
		c := 0
		for {
			if err := addx(r); err != nil {
				if strings.Contains(err.Error(), "database is locked") && c < 5 {
					c++
					randutil.RandSleep(1000)
					continue
				}
				gologger.Error().Msgf("Error inserting result into database: %v\n", err)
			}
			break
		}
	}
}

func NewWebSqliteDB() error {
	// 初始化数据库连接（增加 busy_timeout，开启 WAL）
	// 备注：logoove/sqlite 驱动使用名为 sqlite3 的驱动注册
	dbName, err := db2.DbName()
	if err != nil {
		return err
	}
	dsn := "file:" + dbName + "?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000"
	db, err := sqlx.Connect("sqlite3", dsn)
	if err != nil {
		return err
	}
	dbx = db

	// sqlite 通常建议较小的连接数；WAL 下单连接最稳妥
	dbx.SetMaxOpenConns(1)
	dbx.SetMaxIdleConns(1)

	_, err = dbx.Exec(db2.SqliteCreate)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating table: %v", err)
	}

	if _, err = dbx.Exec(ledgerDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating ledger table: %v", err)
	}

	if _, err = dbx.Exec(assetDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating asset table: %v", err)
	}

	if _, err = dbx.Exec(scanTaskDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating scan task table: %v", err)
	}

	if _, err = dbx.Exec(aiDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating ai tables: %v", err)
	}

	if err = ensureResultNodeColumn(); err != nil {
		return fmt.Errorf("error migrating result table: %v", err)
	}

	return dbx.Ping()
}

// ensureResultNodeColumn 给已有库补上 result.node 列。
//
// 建表用的是 CREATE TABLE IF NOT EXISTS，老库不会因为改了这个常量就长出新列；
// 本项目也没有版本号式的迁移机制，所以这里做一次显式检查：缺列才 ALTER。
func ensureResultNodeColumn() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	rows, err := dbx.Queryx("PRAGMA table_info(" + db2.TableName + ")")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		col := map[string]interface{}{}
		if err := rows.MapScan(col); err != nil {
			return err
		}
		if name, ok := col["name"]; ok && fmt.Sprintf("%v", name) == "node" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = dbx.Exec("ALTER TABLE " + db2.TableName + " ADD COLUMN \"node\" TEXT NOT NULL DEFAULT ''")
	return err
}

func CloseX() {
	// 安全关闭任务通道并等待 worker 退出
	ch := insertChannel
	if ch != nil {
		close(ch)
	}

	wg.Wait()

	// 必须等 worker 全部退出后再清空全局引用：worker 的 `range insertChannel`
	// 会读取这个全局变量，提前置空与它们构成数据竞争。
	insertChannel = nil

	if dbx != nil {
		dbx.Close()
	}
}

func addx(r *result.Result) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}

	insertSQL := "INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	currentTime := time.Now()
	createdTime := currentTime.Format("2006-01-02 15:04:05")

	poc, _ := json.Marshal(r.PocInfo)

	pocList := []db2.PocResult{}
	if len(r.AllPocResult) > 0 {
		for _, pocResult := range r.AllPocResult {
			var reqRaw []byte
			var respRaw []byte
			if pocResult != nil && pocResult.ResultRequest != nil && pocResult.ResultRequest.Raw != nil {
				reqRaw = pocResult.ResultRequest.Raw
			}
			if pocResult != nil && pocResult.ResultResponse != nil && pocResult.ResultResponse.Raw != nil {
				respRaw = pocResult.ResultResponse.Raw
			}
			responseText := utils.Str2UTF8(string(respRaw))
			pocList = append(pocList, db2.PocResult{
				FullTarget: pocResult.FullTarget,
				Request:    string(reqRaw),
				Response:   responseText,
				Other:      db2.Other{Latency: pocResult.ResultResponse.GetLatency()},
			})
		}
	}
	result, _ := json.Marshal(pocList)

	extractor, _ := json.Marshal(r.Extractor)

	finger, _ := json.Marshal(r.FingerResult)

	// 为单次写入设置整体超时，防止长期阻塞
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx, insertSQL, db2.SnowFlake.NextID(), db2.TaskID, r.PocInfo.Id, r.PocInfo.Info.Name, r.Target, r.FullTarget, r.PocInfo.Info.Severity, poc, result, createdTime, finger, extractor)
	return err
}

// InsertResultAndReturnID 同步写入一条结果并返回插入的主键 id（带锁冲突重试）
func InsertResultAndReturnID(r *result.Result) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}

	insertSQL := "INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	currentTime := time.Now()
	createdTime := currentTime.Format("2006-01-02 15:04:05")

	pocBytes, _ := json.Marshal(r.PocInfo)

	pocList := []db2.PocResult{}
	if len(r.AllPocResult) > 0 {
		for _, pocResult := range r.AllPocResult {
			var reqRaw []byte
			var respRaw []byte
			if pocResult != nil && pocResult.ResultRequest != nil && pocResult.ResultRequest.Raw != nil {
				reqRaw = pocResult.ResultRequest.Raw
			}
			if pocResult != nil && pocResult.ResultResponse != nil && pocResult.ResultResponse.Raw != nil {
				respRaw = pocResult.ResultResponse.Raw
			}
			responseText := utils.Str2UTF8(string(respRaw))
			pocList = append(pocList, db2.PocResult{
				FullTarget: pocResult.FullTarget,
				Request:    string(reqRaw),
				Response:   responseText,
				Other:      db2.Other{Latency: pocResult.ResultResponse.GetLatency()},
			})
		}
	}
	resultJSON, _ := json.Marshal(pocList)

	extractorBytes, _ := json.Marshal(r.Extractor)
	fingerBytes, _ := json.Marshal(r.FingerResult)

	// 生成主键 id（SnowFlake）
	id := db2.SnowFlake.NextID()

	// 为单次写入设置整体超时，防止长期阻塞；并在锁冲突时重试
	c := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := dbx.ExecContext(ctx, insertSQL, id, db2.TaskID, r.PocInfo.Id, r.PocInfo.Info.Name, r.Target, r.FullTarget, r.PocInfo.Info.Severity, pocBytes, resultJSON, createdTime, fingerBytes, extractorBytes)
		cancel()
		if err != nil {
			if strings.Contains(err.Error(), "database is locked") && c < 5 {
				c++
				randutil.RandSleep(1000)
				continue
			}
			return 0, err
		}
		break
	}

	return id, nil
}

func InsertResultWithTaskID(r *result.Result, taskID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}

	insertSQL := "INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	currentTime := time.Now()
	createdTime := currentTime.Format("2006-01-02 15:04:05")

	pocBytes, _ := json.Marshal(r.PocInfo)

	pocList := []db2.PocResult{}
	if len(r.AllPocResult) > 0 {
		for _, pocResult := range r.AllPocResult {
			var reqRaw []byte
			var respRaw []byte
			if pocResult != nil && pocResult.ResultRequest != nil && pocResult.ResultRequest.Raw != nil {
				reqRaw = pocResult.ResultRequest.Raw
			}
			if pocResult != nil && pocResult.ResultResponse != nil && pocResult.ResultResponse.Raw != nil {
				respRaw = pocResult.ResultResponse.Raw
			}
			responseText := utils.Str2UTF8(string(respRaw))
			pocList = append(pocList, db2.PocResult{
				FullTarget: pocResult.FullTarget,
				Request:    string(reqRaw),
				Response:   responseText,
				Other:      db2.Other{Latency: pocResult.ResultResponse.GetLatency()},
			})
		}
	}
	resultJSON, _ := json.Marshal(pocList)

	extractorBytes, _ := json.Marshal(r.Extractor)
	fingerBytes, _ := json.Marshal(r.FingerResult)

	id := db2.SnowFlake.NextID()

	c := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := dbx.ExecContext(ctx, insertSQL, id, taskID, r.PocInfo.Id, r.PocInfo.Info.Name, r.Target, r.FullTarget, r.PocInfo.Info.Severity, pocBytes, resultJSON, createdTime, fingerBytes, extractorBytes)
		cancel()
		if err != nil {
			if strings.Contains(err.Error(), "database is locked") && c < 5 {
				c++
				randutil.RandSleep(1000)
				continue
			}
			return 0, err
		}
		break
	}

	return id, nil
}

func InsertWebProbeSummary(taskID, vulID, vulName, target, fullTarget string, fingerprint any) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}

	insertSQL := "INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	currentTime := time.Now()
	createdTime := currentTime.Format("2006-01-02 15:04:05")

	fingerBytes, err := json.Marshal(fingerprint)
	if err != nil {
		return 0, err
	}
	id := db2.SnowFlake.NextID()

	c := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := dbx.ExecContext(ctx, insertSQL, id, taskID, vulID, vulName, target, fullTarget, "info", "", "", createdTime, fingerBytes, "")
		cancel()
		if err != nil {
			if strings.Contains(err.Error(), "database is locked") && c < 5 {
				c++
				randutil.RandSleep(1000)
				continue
			}
			return 0, err
		}
		break
	}

	return id, nil
}

func SelectX(severity, keyword, page string) ([]db2.ResultData, error) {

	var err error
	var query string
	var data []db2.ResultData

	// 计算 OFFSET，即从哪一行开始
	pageSize, err := strconv.Atoi(db2.LIMIT)
	if err != nil {
		pageSize = 100
	}
	pageInt, err := strconv.Atoi(page)
	if err != nil {
		pageInt = 1
	}
	offset := (pageInt - 1) * pageSize

	// 查询设置超时，避免慢查阻塞
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(keyword) == 0 && len(severity) == 0 {
		query := "SELECT * FROM " + db2.TableName + " ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
		err = dbx.SelectContext(ctx, &data, query, offset)
		if err != nil {
			return nil, err
		}
	} else if len(keyword) > 0 && len(severity) == 0 {
		query = "SELECT * FROM " + db2.TableName + " WHERE vulid LIKE ? OR vulname LIKE ? ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
		err = dbx.SelectContext(ctx, &data, query, "%"+keyword+"%", "%"+keyword+"%", offset)
		if err != nil {
			return nil, err
		}
	} else if len(keyword) > 0 && len(severity) > 0 {
		list := strings.Split(severity, ",")
		if len(list) == 1 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity = ? AND (vulid LIKE ? OR vulname LIKE ?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], "%"+keyword+"%", "%"+keyword+"%", offset)
		} else if len(list) == 2 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?) AND (vulid LIKE ? OR vulname LIKE ?)  ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], "%"+keyword+"%", "%"+keyword+"%", offset)
		} else if len(list) == 3 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?) AND (vulid LIKE ? OR vulname LIKE ?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], list[2], "%"+keyword+"%", "%"+keyword+"%", offset)
		} else if len(list) == 4 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?,?) AND (vulid LIKE ? OR vulname LIKE ?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], list[2], list[3], "%"+keyword+"%", "%"+keyword+"%", offset)
		} else if len(list) == 5 {
			query = "SELECT * FROM " + db2.TableName + " ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, offset)
		}
		if err != nil {
			return nil, err
		}
	} else if len(keyword) == 0 && len(severity) > 0 {
		list := strings.Split(severity, ",")
		if len(list) == 1 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity = ? ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], offset)
		} else if len(list) == 2 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], offset)
		} else if len(list) == 3 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], list[2], offset)
		} else if len(list) == 4 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?,?) ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, list[0], list[1], list[2], list[3], offset)
		} else if len(list) == 5 {
			query = "SELECT * FROM " + db2.TableName + " ORDER BY id DESC LIMIT " + db2.LIMIT + " OFFSET ?"
			err = dbx.SelectContext(ctx, &data, query, offset)
		}
		if err != nil {
			return nil, err
		}
	}

	for key, item := range data {
		data[key].Severity = strings.ToUpper(item.Severity)

		json.Unmarshal([]byte(item.Result), &data[key].ResultList)
		for i := range data[key].ResultList {
			data[key].ResultList[i].Response = utils.Str2UTF8(data[key].ResultList[i].Response)
		}
		data[key].Result = ""

		po := poc.Poc{}
		json.Unmarshal([]byte(item.Poc), &po)

		po.Info.Description = strings.TrimSpace(po.Info.Description)
		data[key].PocInfo = po

	}

	return data, nil
}

// 调整：分页查询（支持 page/pageSize、大小写不敏感的 severity；按需展开大字段）
func SelectPage(severity, keyword string, page, pageSize int, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	where, args := severityKeywordFilters(severity, keyword)
	return selectResultPage(where, args, page, pageSize, expandPoc, expandResult)
}

// SelectPageScoped 在 SelectPage 之上再叠加「按任务」过滤，
// 供「查看某次扫描（含计划扫描）的结果」使用：计划任务同样按 taskid 入库。
func SelectPageScoped(taskID, severity, keyword string, page, pageSize int, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	where, args := reportFilters(taskID, severity, keyword)
	return selectResultPage(where, args, page, pageSize, expandPoc, expandResult)
}

// reportFilters 在「严重级别 + 关键字」之上叠加 taskid 条件。
func reportFilters(taskID, severity, keyword string) ([]string, []interface{}) {
	where, args := severityKeywordFilters(severity, keyword)
	if tid := strings.TrimSpace(taskID); tid != "" {
		where = append([]string{"taskid = ?"}, where...)
		args = append([]interface{}{tid}, args...)
	}
	return where, args
}

// selectResultPage 是分页查询的公共实现，where/args 由调用方组装。
func selectResultPage(where []string, args []interface{}, page, pageSize int, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	offset := (page - 1) * pageSize

	query := "SELECT * FROM " + db2.TableName
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT " + strconv.Itoa(pageSize) + " OFFSET " + strconv.Itoa(offset)

	return runResultQuery(query, args, expandPoc, expandResult)
}

// severityKeywordFilters 组装「严重级别 + 关键字」的过滤条件，列表/计数/导出共用。
func severityKeywordFilters(severity, keyword string) ([]string, []interface{}) {
	var where []string
	var args []interface{}

	if kw := strings.TrimSpace(keyword); kw != "" {
		where = append(where, "(vulid LIKE ? OR vulname LIKE ?)")
		args = append(args, "%"+kw+"%", "%"+kw+"%")
	}

	sev := strings.TrimSpace(severity)
	if sev != "" {
		var holders []string
		for _, s := range strings.Split(sev, ",") {
			t := strings.ToLower(strings.TrimSpace(s))
			if t == "" {
				continue
			}
			holders = append(holders, "?")
			args = append(args, t)
		}
		// 5 个及以上视为全选
		if len(holders) > 0 && len(holders) < 5 {
			where = append(where, "LOWER(severity) IN ("+strings.Join(holders, ",")+")")
		}
	}

	return where, args
}

// ExportRowLimit 限制单次导出的最大行数：报告是给人看的，
// 超大结果集既不实用，也会把内存和产物文件撑爆。
// 查询结果达到该上限时，调用方应提示用户报告可能不完整。
const ExportRowLimit = 20000

// runExportQuery 执行「全量」导出查询，统一套用 ExportRowLimit 上限。
func runExportQuery(from string, where []string, args []interface{}, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	query := "SELECT " + from
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY " + db2.TableName + ".id DESC LIMIT " + strconv.Itoa(ExportRowLimit)

	return runResultQuery(query, args, expandPoc, expandResult)
}

// SelectAllByTask 返回某个任务的全部命中，供报告导出使用。
func SelectAllByTask(taskID, severity string, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, fmt.Errorf("task id is required")
	}
	where, args := taskResultFilters(taskID, severity)
	return runExportQuery(db2.TableName+".* FROM "+db2.TableName, where, args, expandPoc, expandResult)
}

// SelectAllFiltered 返回按「严重级别 + 关键字」筛选后的全部命中（跨任务）。
func SelectAllFiltered(severity, keyword string, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	where, args := severityKeywordFilters(severity, keyword)
	return runExportQuery(db2.TableName+".* FROM "+db2.TableName, where, args, expandPoc, expandResult)
}

// SelectAllByProject 返回某个项目下全部任务的命中。
func SelectAllByProject(projectID, severity string, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("project id is required")
	}
	where, args := severityKeywordFilters(severity, "")
	where = append([]string{"tp.project_id = ?"}, where...)
	args = append([]interface{}{projectID}, args...)

	from := db2.TableName + ".* FROM " + db2.TableName +
		" JOIN task_project tp ON tp.taskid = " + db2.TableName + ".taskid"
	return runExportQuery(from, where, args, expandPoc, expandResult)
}

// SelectPageByTask 是按任务筛选的分页查询，供控制面 GetResults 使用。
func SelectPageByTask(taskID, severity string, page, pageSize int, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	offset := (page - 1) * pageSize

	where, args := taskResultFilters(taskID, severity)
	query := "SELECT * FROM " + db2.TableName
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT " + strconv.Itoa(pageSize) + " OFFSET " + strconv.Itoa(offset)

	return runResultQuery(query, args, expandPoc, expandResult)
}

// CountByTask 统计某个任务的命中数（可按 severity 过滤）。
func CountByTask(taskID, severity string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	where, args := taskResultFilters(taskID, severity)
	query := "SELECT COUNT(*) FROM " + db2.TableName
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var total int64
	if err := dbx.GetContext(ctx, &total, query, args...); err != nil {
		return 0, err
	}
	return total, nil
}

// taskResultFilters 组装「按任务 + 严重级别」的过滤条件，分页与计数共用。
func taskResultFilters(taskID, severity string) ([]string, []interface{}) {
	where := []string{"taskid = ?"}
	args := []interface{}{strings.TrimSpace(taskID)}

	sev := strings.TrimSpace(severity)
	if sev == "" {
		return where, args
	}
	var holders []string
	for _, s := range strings.Split(sev, ",") {
		t := strings.ToLower(strings.TrimSpace(s))
		if t == "" {
			continue
		}
		holders = append(holders, "?")
		args = append(args, t)
	}
	if len(holders) > 0 && len(holders) < 5 {
		where = append(where, "LOWER(severity) IN ("+strings.Join(holders, ",")+")")
	}
	// 5 个或以上视为全选
	return where, args
}

// runResultQuery 执行结果查询并统一做展示层归一化（severity 大写、按需展开 JSON）。
func runResultQuery(query string, args []interface{}, expandPoc, expandResult bool) ([]db2.ResultData, error) {
	// 查询设置超时
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var data []db2.ResultData
	if err := dbx.SelectContext(ctx, &data, query, args...); err != nil {
		return nil, err
	}

	// 统一处理：Severity 大写；按需展开 JSON
	for key, item := range data {
		data[key].Severity = strings.ToUpper(item.Severity)

		if expandResult {
			_ = json.Unmarshal([]byte(item.Result), &data[key].ResultList)
			for i := range data[key].ResultList {
				data[key].ResultList[i].Response = utils.Str2UTF8(data[key].ResultList[i].Response)
			}
		}
		data[key].Result = ""

		if expandPoc {
			var po poc.Poc
			_ = json.Unmarshal([]byte(item.Poc), &po)
			po.Info.Description = strings.TrimSpace(po.Info.Description)
			data[key].PocInfo = po
		}
	}

	return data, nil
}

// SelectRawResultsByTask 原样返回某个任务的全部命中（含 result / poc / fingerprint /
// extractor 原文），供集群把执行节点上的命中回填到发起端。
//
// 与报表查询的区别：这里不做任何展示层归一化，也不清空大字段——回填要的是可原样
// 落库的完整数据，否则本地报告会缺证据、AI 研判也拿不到请求响应。
func SelectRawResultsByTask(taskID string, limit int) ([]db2.ResultData, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is required")
	}
	if limit <= 0 || limit > ExportRowLimit {
		limit = ExportRowLimit
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out := []db2.ResultData{}
	query := "SELECT * FROM " + db2.TableName + " WHERE taskid = ? ORDER BY id ASC LIMIT ?"
	if err := dbx.SelectContext(ctx, &out, query, taskID, limit); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteResultsByTask 删除某个任务在本地 result 表里的命中，供回填重放前清场。
func DeleteResultsByTask(taskID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return 0, fmt.Errorf("task id is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := dbx.ExecContext(ctx, "DELETE FROM "+db2.TableName+" WHERE taskid = ?", taskID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertRawResults 把一批「在别处生成」的命中写进本地 result 表。
//
// 用于远程命中回填：taskid 用发起端的影子任务号（发起端的一切报告/台账都按它组织），
// node 记录来源执行节点名，其余字段原样搬运。主键一律由本机 SnowFlake 重新分配，
// 避免与本地既有行撞主键。
func InsertRawResults(taskID, node string, rows []db2.ResultData) (int, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return 0, fmt.Errorf("task id is required")
	}
	if len(rows) == 0 {
		return 0, nil
	}

	insertSQL := "INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor, node) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	tx, err := dbx.Beginx()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	fallbackCreated := time.Now().Format("2006-01-02 15:04:05")
	n := 0
	for _, r := range rows {
		created := strings.TrimSpace(r.Created)
		if created == "" {
			created = fallbackCreated
		}
		if _, err := tx.Exec(insertSQL, db2.SnowFlake.NextID(), taskID, r.VulID, r.VulName,
			r.Target, r.FullTarget, r.Severity, r.Poc, r.Result, created,
			r.FingerPrint, r.Extractor, strings.TrimSpace(node)); err != nil {
			return n, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

// 新增：统计筛选后的总数（保持不变）
// func CountFiltered(...) 已存在

// 新增：按ID查询报告详情，按需展开
func GetByID(id string, expandPoc, expandResult bool) (db2.ResultData, error) {
	var row db2.ResultData
	if dbx == nil {
		return row, fmt.Errorf("sqlite not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	q := "SELECT * FROM " + db2.TableName + " WHERE id = ?"

	if err := dbx.GetContext(ctx, &row, q, id); err != nil {
		return row, err
	}

	row.Severity = strings.ToUpper(row.Severity)

	if expandResult {
		_ = json.Unmarshal([]byte(row.Result), &row.ResultList)
		for i := range row.ResultList {
			row.ResultList[i].Response = utils.Str2UTF8(row.ResultList[i].Response)
		}
	}
	row.Result = ""

	if expandPoc {
		var po poc.Poc
		_ = json.Unmarshal([]byte(row.Poc), &po)
		po.Info.Description = strings.TrimSpace(po.Info.Description)
		row.PocInfo = po
	}

	return row, nil
}

func Count() int64 {
	var count int64
	query := "SELECT COUNT(*) FROM " + db2.TableName

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := dbx.GetContext(ctx, &count, query)
	if err != nil {
		return 0
	}
	return count
}

func CountFiltered(severity, keyword string) (int64, error) {
	where, args := severityKeywordFilters(severity, keyword)
	return countResults(where, args)
}

// CountScoped 统计叠加「按任务」过滤后的命中数，与 SelectPageScoped 口径一致。
func CountScoped(taskID, severity, keyword string) (int64, error) {
	where, args := reportFilters(taskID, severity, keyword)
	return countResults(where, args)
}

// countResults 是计数查询的公共实现，where/args 由调用方组装。
func countResults(where []string, args []interface{}) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}

	q := "SELECT COUNT(*) FROM " + db2.TableName
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var count int64
	if err := dbx.GetContext(ctx, &count, q, args...); err != nil {
		return 0, err
	}
	return count, nil
}

// -----------------------
// 漏洞台账
// -----------------------

// ledgerDDL 是台账的状态覆盖表：result 表回答「发现了什么」，本表只保存人工维护的
// 状态 / 备注 / 所属项目，两者按 (vulid, target, fulltarget) 关联。
const ledgerDDL = `CREATE TABLE IF NOT EXISTS "vuln_ledger" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"vulid" TEXT NOT NULL DEFAULT '',
	"target" TEXT NOT NULL DEFAULT '',
	"fulltarget" TEXT NOT NULL DEFAULT '',
	"status" TEXT NOT NULL DEFAULT 'pending',
	"note" TEXT NOT NULL DEFAULT '',
	"updated_at" TEXT NOT NULL DEFAULT '',
	UNIQUE("vulid", "target", "fulltarget")
  );
  CREATE INDEX IF NOT EXISTS "idx_ledger_key"
	ON "vuln_ledger" ("vulid", "target", "fulltarget");
  CREATE INDEX IF NOT EXISTS "idx_ledger_status"
	ON "vuln_ledger" ("status");
  CREATE TABLE IF NOT EXISTS "task_project" (
	"taskid" TEXT PRIMARY KEY,
	"project_id" TEXT NOT NULL DEFAULT '',
	"created_at" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_task_project_project"
	ON "task_project" ("project_id");`

// ledgerGroupedSelect 把 result 按「PoC + 目标」聚合，再左连台账叠加人工状态，
// 并通过 task_project 关联到项目（归属判定基于任务，CIDR/域名等目标形态不受影响）。
var ledgerGroupedSelect = `SELECT
	r.vulid AS vulid,
	MAX(r.vulname) AS vulname,
	r.target AS target,
	r.fulltarget AS fulltarget,
	MAX(r.severity) AS severity,
	MIN(r.created) AS first_seen,
	MAX(r.created) AS last_seen,
	COUNT(*) AS hit_count,
	COALESCE(l.status, 'pending') AS status,
	COALESCE(l.note, '') AS note,
	MAX(COALESCE(tp.project_id, '')) AS project_id,
	COALESCE(l.updated_at, '') AS updated_at,
	MAX(r.node) AS node
  FROM ` + db2.TableName + ` r
  LEFT JOIN vuln_ledger l
	ON l.vulid = r.vulid AND l.target = r.target AND l.fulltarget = r.fulltarget
  LEFT JOIN task_project tp ON tp.taskid = r.taskid
  GROUP BY r.vulid, r.target, r.fulltarget`

// LedgerFilter 是台账列表的筛选条件。
type LedgerFilter struct {
	Status   []string
	Severity []string
	Project  string
	Keyword  string
	Page     int
	PageSize int
}

// LedgerPage 是台账分页结果，附带各状态数量分布。
type LedgerPage struct {
	Items    []db2.LedgerRow `json:"items"`
	Total    int64           `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
	Stats    db2.LedgerStats `json:"stats"`
}

// normalizeList 归一化筛选值：小写、去空白、丢弃空项。
func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if t := strings.ToLower(strings.TrimSpace(v)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ledgerConditions 组装台账筛选条件；withStatus=false 用于统计各状态数量。
func ledgerConditions(f LedgerFilter, withStatus bool) ([]string, []interface{}) {
	var where []string
	var args []interface{}

	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		where = append(where, "(t.vulid LIKE ? OR t.vulname LIKE ? OR t.target LIKE ? OR t.fulltarget LIKE ?)")
		like := "%" + kw + "%"
		args = append(args, like, like, like, like)
	}
	// 项目筛选对列表与统计都生效（统计只忽略状态筛选本身）
	if pid := strings.TrimSpace(f.Project); pid != "" {
		where = append(where, "t.project_id = ?")
		args = append(args, pid)
	}
	if sevs := normalizeList(f.Severity); len(sevs) > 0 && len(sevs) < 5 {
		holders := make([]string, 0, len(sevs))
		for _, s := range sevs {
			holders = append(holders, "?")
			args = append(args, s)
		}
		where = append(where, "LOWER(t.severity) IN ("+strings.Join(holders, ",")+")")
	}
	if withStatus {
		if sts := normalizeList(f.Status); len(sts) > 0 && len(sts) < 4 {
			holders := make([]string, 0, len(sts))
			for _, s := range sts {
				holders = append(holders, "?")
				args = append(args, s)
			}
			where = append(where, "t.status IN ("+strings.Join(holders, ",")+")")
		}
	}
	return where, args
}

// SelectLedgerPage 返回台账分页数据与状态分布。
func SelectLedgerPage(f LedgerFilter) (*LedgerPage, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 50
	}
	if f.PageSize > 500 {
		f.PageSize = 500
	}
	offset := (f.Page - 1) * f.PageSize

	where, args := ledgerConditions(f, true)

	listSQL := "SELECT * FROM (" + ledgerGroupedSelect + ") t"
	countSQL := "SELECT COUNT(*) FROM (" + ledgerGroupedSelect + ") t"
	if len(where) > 0 {
		clause := " WHERE " + strings.Join(where, " AND ")
		listSQL += clause
		countSQL += clause
	}
	listSQL += " ORDER BY t.last_seen DESC LIMIT " + strconv.Itoa(f.PageSize) + " OFFSET " + strconv.Itoa(offset)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	page := &LedgerPage{Page: f.Page, PageSize: f.PageSize, Items: []db2.LedgerRow{}}
	if err := dbx.SelectContext(ctx, &page.Items, listSQL, args...); err != nil {
		return nil, err
	}
	for i := range page.Items {
		page.Items[i].Severity = strings.ToUpper(page.Items[i].Severity)
	}
	if err := dbx.GetContext(ctx, &page.Total, countSQL, args...); err != nil {
		return nil, err
	}

	// 状态分布忽略状态筛选本身，其余筛选保持一致。
	statsWhere, statsArgs := ledgerConditions(f, false)
	statsSQL := "SELECT t.status AS status, COUNT(*) AS n FROM (" + ledgerGroupedSelect + ") t"
	if len(statsWhere) > 0 {
		statsSQL += " WHERE " + strings.Join(statsWhere, " AND ")
	}
	statsSQL += " GROUP BY t.status"

	var rows []struct {
		Status string `db:"status"`
		N      int64  `db:"n"`
	}
	if err := dbx.SelectContext(ctx, &rows, statsSQL, statsArgs...); err != nil {
		return nil, err
	}
	for _, r := range rows {
		switch strings.ToLower(strings.TrimSpace(r.Status)) {
		case "confirmed":
			page.Stats.Confirmed = r.N
		case "false_positive":
			page.Stats.FalsePositive = r.N
		case "fixed":
			page.Stats.Fixed = r.N
		default:
			page.Stats.Pending += r.N
		}
	}

	return page, nil
}

// UpsertLedgerStatus 写入/更新一条台账的人工状态与备注。
func UpsertLedgerStatus(vulid, target, fulltarget, status, note string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := dbx.ExecContext(ctx,
		`INSERT OR REPLACE INTO vuln_ledger(vulid, target, fulltarget, status, note, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		vulid, target, fulltarget, status, note, now)
	return err
}

// LinkTaskProject 记录任务所属项目，供台账按项目聚合与「项目扫描历史」使用。
// 同一个任务重复登记时以最后一次为准。
func LinkTaskProject(taskID, projectID string) error {
	taskID = strings.TrimSpace(taskID)
	projectID = strings.TrimSpace(projectID)
	if dbx == nil || taskID == "" || projectID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dbx.ExecContext(ctx,
		`INSERT OR REPLACE INTO task_project(taskid, project_id, created_at) VALUES(?, ?, ?)`,
		taskID, projectID, time.Now().Format("2006-01-02 15:04:05"))
	return err
}

// CountTasksByProject 返回项目下的扫描任务数。
func CountTasksByProject(projectID string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM task_project WHERE project_id = ?`, projectID)
	return n, err
}

// SelectProjectTaskIDs 返回项目下的任务 ID（按创建时间升序），供项目报告标注扫描范围。
func SelectProjectTaskIDs(projectID string) ([]string, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids := make([]string, 0, 16)
	err := dbx.SelectContext(ctx, &ids,
		`SELECT taskid FROM task_project WHERE project_id = ? ORDER BY created_at ASC, rowid ASC`,
		projectID)
	return ids, err
}

// -----------------------
// 菜单 badge 计数
// -----------------------

// CountResultsSince 统计 created 不早于 since 的命中行数，供「今日新增」badge 使用。
// since 用与 result.created 相同的 "2006-01-02 15:04:05" 本地时间格式，
// 避免依赖 sqlite 的 UTC now() 造成跨时区偏差。
func CountResultsSince(since string) (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM `+db2.TableName+` WHERE created >= ?`, strings.TrimSpace(since))
	return n, err
}

// CountLedgerPending 统计台账中「待确认」的条目数（与台账页 stats 同一聚合口径）。
func CountLedgerPending() (int64, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var n int64
	err := dbx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM (`+ledgerGroupedSelect+`) t WHERE t.status = 'pending'`)
	return n, err
}

// -----------------------
// 扫描差异对比
// -----------------------

// SelectTaskFindings 返回某个任务的命中集合，按「PoC + 目标」聚合。
// 差异对比以该粒度为最小单元：URL 上的查询参数差异不影响判定。
func SelectTaskFindings(taskID string) ([]db2.TaskFinding, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	items := make([]db2.TaskFinding, 0, 128)
	err := dbx.SelectContext(ctx, &items, `SELECT
		r.vulid AS vulid,
		MAX(r.vulname) AS vulname,
		r.target AS target,
		MAX(r.fulltarget) AS fulltarget,
		MAX(r.severity) AS severity,
		COUNT(*) AS hit_count
	  FROM `+db2.TableName+` r
	  WHERE r.taskid = ?
	  GROUP BY r.vulid, r.target`, taskID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Severity = strings.ToUpper(items[i].Severity)
	}
	return items, nil
}

// SelectTaskProject 返回任务所属项目 ID，未归属时返回空串。
func SelectTaskProject(taskID string) (string, error) {
	if dbx == nil {
		return "", fmt.Errorf("sqlite not initialized")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var projectID string
	err := dbx.GetContext(ctx, &projectID,
		`SELECT project_id FROM task_project WHERE taskid = ?`, taskID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return projectID, nil
}

// SelectPreviousProjectTask 返回同一项目下、早于给定任务的最近一次任务 ID。
func SelectPreviousProjectTask(projectID, taskID string) (string, error) {
	if dbx == nil {
		return "", fmt.Errorf("sqlite not initialized")
	}
	projectID = strings.TrimSpace(projectID)
	taskID = strings.TrimSpace(taskID)
	if projectID == "" || taskID == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var prev string
	err := dbx.GetContext(ctx, &prev, `
		SELECT taskid FROM task_project
		 WHERE project_id = ? AND taskid <> ?
		   AND created_at <= (SELECT created_at FROM task_project WHERE taskid = ?)
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT 1`, projectID, taskID, taskID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return prev, nil
}
