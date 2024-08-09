package web

import (
	"embed"
	"net/http"
	"text/template"

	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/gologger"
)

//go:embed template/*.html static/*
var temp embed.FS

func StartServer(addr string) error {

	err := sqlite.InitX()
	if err != nil {
		return err
	}

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", listHandler)

	http.Handle("/static/", http.FileServer(http.FS(temp)))

	// 启动HTTP服务器并监听端口
	gologger.Info().Msg("Serving HTTP on :: port " + addr[1:] + " (http://[::]" + addr + "/) ...")
	return http.ListenAndServe(addr, nil)

}

type User struct {
	Password string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	password := r.PostFormValue("password")
	if len(password) == 0 {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}

	tmpl, err := template.ParseFiles("template/Login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

	count := sqlite.Count()

	// 解析模板文件
	tmpl, err := template.ParseFS(temp, "template/List.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respData := struct {
		DataList         []db.ResultData
		CurrentDataCount int
		TotalDataCount   int64
	}{
		DataList:         data,
		CurrentDataCount: len(data),
		TotalDataCount:   count,
	}

	// 渲染模板并将结果写入响应
	err = tmpl.Execute(w, respData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
