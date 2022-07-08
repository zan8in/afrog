package main

import (
	"fmt"
	"net"
	"time"
)

var (
	mysqlips = []string{"217.21.93.39:3306", "58.152.168.153:3306"}
)

func testDial() {
	timeout := time.Duration(6) * time.Second
	conn, err := net.DialTimeout("tcp", "217.21.93.39:3306", timeout)
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Println(conn.LocalAddr().String(), conn.RemoteAddr().String())
}

func main() {
	testDial()
	// r, err := utils.Tcp("58.152.168.153:3306", []byte("GET /r.html HTTP/1.0\r\n\r\n"))
	// fmt.Println(string(r), err)
}
