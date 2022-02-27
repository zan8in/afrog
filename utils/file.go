package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime/debug"
)

func ReadFileLineByLine(filename string) ([]string, error) {
	var result []string
	fp, err := os.Open(filename)
	if err != nil {
		return result, err
	}
	buf := bufio.NewScanner(fp)
	for {
		if !buf.Scan() {
			break //文件读完了,退出for
		}
		line := buf.Text() //获取每一行
		result = append(result, line)
	}
	return result, err
}

func ReadFromFile(filename string) ([]byte, error) {
	if !Exists(filename) {
		return nil, errors.New(filename + "文件不存在")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err != nil {
		log.Println("读取文件失败: ", err)
		return nil, err
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("读取文件失败: ", err)
		return nil, err
	}
	return data, nil
}

func OpenFile(fileName string) *os.File {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		fmt.Printf("create file error: %s, file_name: %s\n", err.Error(), fileName)
		debug.PrintStack()
		return nil
	}
	return file
}

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		return os.IsExist(err)
	}
	return true
}
