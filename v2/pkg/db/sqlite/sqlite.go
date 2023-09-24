package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	db2 "github.com/zan8in/afrog/v2/pkg/db"
	"github.com/zan8in/afrog/v2/pkg/result"
	"github.com/zan8in/gologger"
)

var db *sql.DB

var insertChannel chan *result.Result
var wg sync.WaitGroup

func Init() error {
	err := initDB()
	if err != nil || db == nil {
		return fmt.Errorf("error initializing database: %v", err)
	}

	err = createTable()
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("error creating table: %v", err)
	}

	//设置新的缓存大小（以页为单位）
	cacheSize := 5000 // 设置为你想要的缓存大小
	_, err = db.Exec(fmt.Sprintf("PRAGMA cache_size = %d;", cacheSize))
	if err != nil {
		return fmt.Errorf("error set cache_size: %v", err)
	}

	insertChannel = make(chan *result.Result)

	wg.Add(1)
	go saveToDatabase()

	return nil
}

func Close() {
	if insertChannel != nil {
		close(insertChannel)
	}
	if db != nil {
		db.Close()
	}
	wg.Wait()
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", db2.DBName+".db")
	if err != nil {
		return err
	}

	return db.Ping()
}

func createTable() error {
	_, err := db.Exec(db2.SqliteCreate)
	return err
}

func SetResult(result *result.Result) {
	insertChannel <- result
}

func saveToDatabase() {
	defer wg.Done()

	for result := range insertChannel {
		if err := add(result); err != nil {
			gologger.Error().Msgf("Error inserting result into database: %v\n", err)
		}
	}
}

func add(r *result.Result) error {
	stmt, err := db.Prepare("INSERT INTO result(taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

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
				Request:  string(reqRaw),
				Response: string(respRaw),
			})
		}
	}
	result, _ := json.Marshal(pocList)

	extractor, _ := json.Marshal(r.Extractor)

	finger, _ := json.Marshal(r.FingerResult)

	_, err = stmt.Exec(db2.TaskID, r.PocInfo.Id, r.PocInfo.Info.Name, r.Target, r.FullTarget, r.PocInfo.Info.Severity, poc, result, createdTime, finger, extractor)
	if err != nil {
		return err
	}

	return nil
}

func Select(severity, keyword string) ([]db2.ResultData, error) {

	var rows *sql.Rows
	var err error
	var query string

	if len(keyword) == 0 && len(severity) == 0 {
		query := "SELECT * FROM " + db2.TableName + " LIMIT " + db2.LIMIT
		rows, err = db.Query(query)
		if err != nil {
			return nil, err
		}
	} else if len(keyword) > 0 && len(severity) == 0 {
		query = "SELECT * FROM " + db2.TableName + " WHERE vulid LIKE ? OR vulname LIKE ? LIMIT " + db2.LIMIT
		rows, err = db.Query(query, "%"+keyword+"%", "%"+keyword+"%")
		if err != nil {
			return nil, err
		}
	} else if len(keyword) > 0 && len(severity) > 0 {
		list := strings.Split(severity, ",")
		if len(list) == 1 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity = ? AND (vulid LIKE ? OR vulname LIKE ?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], "%"+keyword+"%", "%"+keyword+"%")
		} else if len(list) == 2 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?) AND (vulid LIKE ? OR vulname LIKE ?)  LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1], "%"+keyword+"%", "%"+keyword+"%")
		} else if len(list) == 3 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?) AND (vulid LIKE ? OR vulname LIKE ?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1], list[2], "%"+keyword+"%", "%"+keyword+"%")
		} else if len(list) == 4 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?,?) AND (vulid LIKE ? OR vulname LIKE ?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1], list[2], list[3], "%"+keyword+"%", "%"+keyword+"%")
		} else if len(list) == 5 {
			query = "SELECT * FROM " + db2.TableName + " LIMIT " + db2.LIMIT
			rows, err = db.Query(query)
		}
		if err != nil {
			return nil, err
		}
	} else if len(keyword) == 0 && len(severity) > 0 {
		list := strings.Split(severity, ",")
		if len(list) == 1 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity = ? LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0])
		} else if len(list) == 2 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1])
		} else if len(list) == 3 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1], list[2])
		} else if len(list) == 4 {
			query = "SELECT * FROM " + db2.TableName + " WHERE severity in (?,?,?,?) LIMIT " + db2.LIMIT
			rows, err = db.Query(query, list[0], list[1], list[2], list[3])
		} else if len(list) == 5 {
			query = "SELECT * FROM " + db2.TableName + " LIMIT " + db2.LIMIT
			rows, err = db.Query(query)
		}
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	// 创建一个数据切片来存储查询结果
	var data []db2.ResultData

	// 遍历查询结果
	for rows.Next() {
		var item db2.ResultData
		err := rows.Scan(&item.ID, &item.TaskID, &item.VulID, &item.VulName, &item.Target, &item.FullTarget, &item.Severity, &item.Poc, &item.Result, &item.Created, &item.FingerPrint, &item.Extractor /* ... */)
		if err != nil {
			return data, err
		}

		item.Result = strings.ReplaceAll(item.Result, "\n", "<br>")
		item.Severity = strings.ToUpper(item.Severity)

		json.Unmarshal([]byte(item.Result), &item.ResultList)
		item.Result = ""

		data = append(data, item)
	}

	if err := rows.Err(); err != nil {
		return data, err
	}

	return data, nil
}
