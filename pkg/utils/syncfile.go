package utils

import (
	"bufio"
	"os"
	"sync"
)

type Syncfile struct {
	mutex     *sync.Mutex
	iohandler *os.File
}

func NewSyncfile(filename string) (*Syncfile, error) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &Syncfile{mutex: &sync.Mutex{}, iohandler: f}, nil
}

func (sf *Syncfile) Write(content string) {
	sf.mutex.Lock()

	wbuf := bufio.NewWriterSize(sf.iohandler, len(content))
	wbuf.WriteString(content)
	wbuf.Flush()

	RandSleep(1000)

	sf.mutex.Unlock()
}
