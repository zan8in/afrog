package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
)

// evidenceDetailHandler 下发一条命中的可重放证据。
//
// 路径参数既可以是 result 主键（数字），也可以是证据的内容寻址 id（evd_ 前缀）。
// 后者让 Agent 之间可以直接传递引用，不必先知道对方库里的自增主键。
func evidenceDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少证据ID"})
		return
	}

	var (
		ev  *evidence.Evidence
		err error
	)
	if strings.HasPrefix(id, "evd_") {
		ev, err = sqlite.SelectEvidenceByID(id)
	} else {
		resultID, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "证据ID不合法"})
			return
		}
		ev, err = sqlite.SelectEvidenceByResultID(resultID)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取证据失败"})
		return
	}
	if ev == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "未找到证据"})
		return
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "success", Data: ev})
}
