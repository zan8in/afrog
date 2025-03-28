package runner

import (
	"os"
	"strings"
	"sync"

	fileutil "github.com/zan8in/pins/file"
)

var PoCScanProgress []string

type ScanProgress struct {
	progress       []string
	resumeProgress []string
	mutex          sync.Mutex
	saveMutex      sync.Mutex // 新增文件保存专用锁
}

func NewScanProgress(resume string) (*ScanProgress, error) {
	progress := make([]string, 0)
	resumeProgress := make([]string, 0)

	if len(resume) > 0 {
		if rsChan, err := fileutil.ReadFile(resume); err != nil {
			return nil, err
		} else {
			for r := range rsChan {
				list := strings.Split(r, ",")
				resumeProgress = append(resumeProgress, list...)
			}
		}
	}

	return &ScanProgress{
		progress:       progress,
		resumeProgress: resumeProgress,
	}, nil
}

func (p *ScanProgress) Increment(id string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.progress = append(p.progress, id)
}

func (p *ScanProgress) Contains(id string) bool {
	for _, item := range p.resumeProgress {
		if item == id {
			return true
		}
	}
	return false
}

func (p *ScanProgress) String() string {
	return strings.Join(p.progress, ",")
}

// 新增方法：原子化保存到指定文件
func (p *ScanProgress) AtomicSave(filename string) error {
	// 获取进度数据快照
	p.mutex.Lock()
	data := strings.Join(p.progress, ",")
	p.mutex.Unlock()

	// 空数据不保存
	if len(data) == 0 {
		return nil
	}

	// 文件操作专用锁
	p.saveMutex.Lock()
	defer p.saveMutex.Unlock()

	// 使用临时文件保证原子性
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(data), 0666); err != nil {
		return err
	}

	// 原子替换文件
	return os.Rename(tmpFile, filename)
}
