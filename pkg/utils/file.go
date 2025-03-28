package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
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

	data, err := io.ReadAll(file)
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

func WriteFile(filename string, data []byte) error {
	os.MkdirAll(path.Dir(filename), os.ModePerm)
	return os.WriteFile(filename, data, 0655)
}

func BufferWriteAppend(filename string, param string) error {
	fileHandle, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0660)
	if err != nil {
		return err
	}
	defer fileHandle.Close()
	// NewWriter 默认缓冲区大小是 4096
	// 需要使用自定义缓冲区的writer 使用 NewWriterSize()方法
	buf := bufio.NewWriter(fileHandle)
	// 字节写入
	//buf.Write([]byte(param))
	// 字符串写入
	buf.WriteString(param + "\n")
	// 将缓冲中的数据写入
	return buf.Flush()
}

const (
	NEW_FILE_PERM = 0666
)

// AppendString appends the contents of the string to filename.
func AppendString(filename, content string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, NEW_FILE_PERM)
	if err != nil {
		return err
	}
	data := []byte(content)
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
		// fmt.Println(err)
	}
	if err1 := f.Close(); err == nil {
		err = err1
		// fmt.Println(err)
	}
	return err
}

// 获取基础文件名（去除路径和扩展名）
func GetFilename(path string) string {
	// 获取系统兼容的文件名
	filename := filepath.Base(path)

	// 处理多扩展名情况
	for {
		ext := filepath.Ext(filename)
		if ext == "" {
			break
		}
		filename = filename[:len(filename)-len(ext)]
	}
	return filename
}
