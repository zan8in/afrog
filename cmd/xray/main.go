package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/protocols/http"
)

var configInfo *config.Config
var err error

func main() {
	url := "http://192.168.66.168/redirect.php"
	url2 := "http://example.com"
	http.HTTPRequest(url, false)
	fmt.Println("-----------", url, url2)
	//poc.SendGetRequest("http://192.168.66.168/redirect.php")
	// log.Log().Info("Zap info")
	// utils.Fatal("这是Zap日志框架Fatal模式", zap.String("ERROR", "not nil"))

	// utils.Panic("这是Zap日志框架Panic模式", zap.String("ERROR", "not nil"))
	//var c config.Config
	// c.ConfigVersion = "1.0"
	// configHttp := c.ConfigHttp
	// configHttp.Proxy = ""
	// configHttp.ReadTimeout = "500ms"
	// configHttp.ReadTimeout = "500ms"
	// configHttp.MaxIdle = "1h"
	// configHttp.Concurrency = 4096
	// configHttp.MaxResponseBodySize = 1024 * 1024 * 2
	// c.ConfigHttp = configHttp

	//config.WriteConfiguration(&c)

	// if configInfo, err = config.ReadConfiguration(); err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	// fmt.Println(configInfo)

	// paths := []string{}
	// paths = append(paths, "./pocs/demo1.yaml")
	// c := catalog.New("./")
	// files := c.GetPocsPath(paths)
	// for k, v := range files {
	// 	fmt.Println(k, v)

	// }

	// fs, err := catalog.GetFiles("./pocs")
	// if err != nil {
	// 	fmt.Println("fs :", err.Error())
	// }
	// fmt.Println(fs)

	// pathinfo, err := catalog.NewPathInfo("./pocs")
	// if err != nil {
	// 	fmt.Println("pathinfo :", err.Error())
	// }
	// fmt.Println(pathinfo)

	// paths2, err := pathinfo.Paths()
	// if err != nil {
	// 	fmt.Println("paths2 :", err.Error())
	// }
	// fmt.Println(paths2)

	// home := catalog.HomeDirOrDefault("./pocs")
	// fmt.Println(home)

	// a1 := config.Version
	// config.ReadConfiguration()
}
