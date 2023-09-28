//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/zan8in/afrog/v2/pkg/db/sqlite"
)

func main() {

	err := sqlite.InitX()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	http.HandleFunc("/list", listHandler)

	// 启动HTTP服务器并监听端口
	http.ListenAndServe(":8080", nil)

}

func listHandler(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	keyword := r.URL.Query().Get("keyword")
	severity := r.URL.Query().Get("severity")
	page := r.URL.Query().Get("page")

	data, err := sqlite.SelectX(severity, keyword, page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 解析模板文件
	tmpl, err := template.ParseFiles("./template/List.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 渲染模板并将结果写入响应
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
