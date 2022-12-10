package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	// 创建路由器
	mux := http.NewServeMux()
	// 设置路由规则
	mux.HandleFunc("/hello", sayHello)

	// 创建服务器
	server := &http.Server{
		Addr:         ":1210",
		WriteTimeout: time.Second * 3,
		Handler:      mux,
	}

	// 监听端口并提供服务
	log.Println("starting httpserver at http:localhost:1210")
	log.Fatal(server.ListenAndServe())

}

func sayHello(w http.ResponseWriter, r *http.Request) {
	time.Sleep(100 * time.Second)
	w.Write([]byte("hello hello, this is httpserver"))
}
