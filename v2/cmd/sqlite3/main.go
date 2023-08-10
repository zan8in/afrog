package main

import (
	"fmt"

	"github.com/remeh/sizedwaitgroup"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type User struct {
	ID   uint
	Name string
}

var (
	numWorkers    = 100 // 并发写入的协程数量
	numIterations = 10  // 每个协程写入的次数
)

func writeToSQLite(db *gorm.DB, workerID int, wg *sizedwaitgroup.SizedWaitGroup) {
	defer wg.Done()

	for i := 0; i < numIterations; i++ {
		data := fmt.Sprintf("Worker %d - Data %d", workerID, i)

		err := db.Transaction(func(tx *gorm.DB) error {
			user := User{Name: data}
			result := tx.Create(&user)
			return result.Error
		})
		if err != nil {
			fmt.Printf("failed to write data: %v\n", err)
		}

		// // 执行写入操作
		// _, err := db.Exec("INSERT INTO your_table (column_name) VALUES (?)", data)
		// if err != nil {
		// 	fmt.Printf("Error writing data for worker %d: %v\n", workerID, err)
		// 	return
		// }
	}
}

func main() {
	// 创建 SQLite3 数据库连接
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic("failed to connect database")
	}
	db.Exec("PRAGMA journal_mode=WAL;")

	// 设置连接池大小
	sqlDB, err := db.DB()
	if err != nil {
		panic("failed to set database pool size")
	}
	defer sqlDB.Close()
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	// 自动迁移 User 模型对应的表
	err = db.AutoMigrate(&User{})
	if err != nil {
		panic("failed to migrate table")
	}

	swg := sizedwaitgroup.New(10)

	// 启动并发写入协程
	for i := 0; i < numWorkers; i++ {
		swg.Add()
		go writeToSQLite(db, i, &swg)
	}

	// 等待所有协程执行完毕
	swg.Wait()

	// // 并发写入 1000 条数据
	// for i := 0; i < 1000; i++ {
	// 	go func(i int) {
	// 		err := db.Transaction(func(tx *gorm.DB) error {
	// 			user := User{Name: fmt.Sprintf("user_%d", i)}
	// 			result := tx.Create(&user)
	// 			return result.Error
	// 		})
	// 		if err != nil {
	// 			fmt.Printf("failed to write data: %v\n", err)
	// 		}
	// 	}(i)
	// }

	// 并发读取数据
	swg1 := sizedwaitgroup.New(10)
	for i := 0; i < 1000; i++ {
		swg1.Add()
		go func() {
			defer swg1.Done()
			var users []User
			db.Transaction(func(tx *gorm.DB) error {
				result := tx.Find(&users)
				return result.Error
			})
			if err != nil {
				fmt.Printf("failed to read data: %v\n", err)
			} else {
				// fmt.Printf("read %d records\n", len(users))
			}
		}()
	}
	swg1.Wait()

	// 等待 10 秒钟，以便所有的写入和读取操作都完成
	// time.Sleep(10 * time.Second)
}
