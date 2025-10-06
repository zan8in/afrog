package sqlite

import (
	"context"
	"encoding/json"
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
	dsn := "file:" + db2.DbName() + "?cache=shared&mode=rwc&_journal_mode=WAL&_busy_timeout=5000"
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

	return dbx.Ping()
}

func CloseX() {
	// 安全关闭任务通道并等待 worker 退出
	if insertChannel != nil {
		close(insertChannel)
		insertChannel = nil
	}

	wg.Wait()

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
			pocList = append(pocList, db2.PocResult{
				FullTarget: pocResult.FullTarget,
				Request:    string(reqRaw),
				Response:   string(respRaw),
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
			pocList = append(pocList, db2.PocResult{
				FullTarget: pocResult.FullTarget,
				Request:    string(reqRaw),
				Response:   string(respRaw),
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

	// 构建过滤条件
	var where []string
	var args []interface{}

	kw := strings.TrimSpace(keyword)
	if kw != "" {
		where = append(where, "(vulid LIKE ? OR vulname LIKE ?)")
		args = append(args, "%"+kw+"%", "%"+kw+"%")
	}

	sev := strings.TrimSpace(severity)
	if sev != "" {
		list := strings.Split(sev, ",")
		var holders []string
		for _, s := range list {
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
		// 5个或以上视为全选
	}

	query := "SELECT * FROM " + db2.TableName
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT " + strconv.Itoa(pageSize) + " OFFSET " + strconv.Itoa(offset)

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
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}

	var where []string
	var args []interface{}

	kw := strings.TrimSpace(keyword)
	if kw != "" {
		where = append(where, "(vulid LIKE ? OR vulname LIKE ?)")
		args = append(args, "%"+kw+"%", "%"+kw+"%")
	}

	sev := strings.TrimSpace(severity)
	if sev != "" {
		list := strings.Split(sev, ",")
		var holders []string
		for _, s := range list {
			t := strings.ToLower(strings.TrimSpace(s))
			if t == "" {
				continue
			}
			holders = append(holders, "?")
			args = append(args, t)
		}
		// 如果传入的 severity 值数量在 1~4 个之间，则做 IN 过滤；5 个或以上视为全选（不过滤）
		if len(holders) > 0 && len(holders) < 5 {
			where = append(where, "LOWER(severity) IN ("+strings.Join(holders, ",")+")")
		}
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
