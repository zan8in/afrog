package utils

import (
	"bufio"
	"os"
	"sync"
)

type Syncfile struct {
	sync.RWMutex
	iohandler *os.File
}

func NewSyncfile(filename string) (*Syncfile, error) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &Syncfile{iohandler: f}, nil
}

func (sf *Syncfile) Write(content string) {
	sf.Lock()
	defer sf.Unlock()

	wbuf := bufio.NewWriterSize(sf.iohandler, len(content))
	wbuf.WriteString(content)
	wbuf.Flush()
}
