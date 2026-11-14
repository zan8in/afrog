package web

import (
	"encoding/json"
	"net/http"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// dbDiagnosticsHandler 暴露数据库连接池与慢查询指标。
//
// 用途只有一个：判断「界面卡顿、命中延迟落库」到底是连接池在排队，还是查询本身慢。
// 当前 SQLite 只有一条连接（NewWebSqliteDB 里 SetMaxOpenConns(1)），读与写共用；
// 若 WaitCount / WaitDurationMs 长期为 0，说明瓶颈不在连接池，改读写分离没有意义。
func dbDiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: sqlite.PoolStats()})
}
