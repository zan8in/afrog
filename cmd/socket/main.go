package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	mysqlips = []string{"217.21.93.39:3306", "58.152.168.153:3306"}
)

func testDialHost(ip string) {
	timeout := time.Duration(3) * time.Second
	conn, err := net.DialTimeout("tcp", ip, timeout)
	if err != nil {
		// fmt.Println("err:", err.Error())
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Println(conn.LocalAddr().String(), conn.RemoteAddr().String())
}

func multiTest() {
	rand.Seed(time.Now().UnixNano())

	swg := sizedwaitgroup.New(500)
	for i := 1; i < 65535; i++ {
		swg.Add()
		go func(i int) {
			defer swg.Done()
			testDialHost("60.10.116.10:" + strconv.Itoa(i))
		}(i)
	}

	swg.Wait()
}

func testDialHttp(ip string) {
	r, err := utils.Tcp(ip, []byte("GET / HTTP/1.0\r\n\r\n"))
	if err != nil {
		// fmt.Println(err.Error())
		return
	}
	if bytes.Contains(r, []byte("HTTP/1.0")) {
		fmt.Println(string(r))
		fmt.Println(ip)
	}
}

func multiTestHttp() {
	rand.Seed(time.Now().UnixNano())

	swg := sizedwaitgroup.New(500)
	for i := 1; i < 65535; i++ {
		swg.Add()
		go func(i int) {
			defer swg.Done()
			testDialHttp("60.10.116.10:" + strconv.Itoa(i))
		}(i)
	}

	swg.Wait()
}

func main() {
	// multiTestHttp()
	// testDialHost("47.254.87.212:873")

	r, err := utils.Tcp("47.254.87.212:873", []byte("info\r\n"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(string(r))

	// r, err := utils.Tcp("58.152.168.153:3306", []byte("GET /r.html HTTP/1.0\r\n\r\n"))
	// fmt.Println(string(r), err)
}
