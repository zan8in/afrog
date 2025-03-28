package runner

import (
	"os"
	"strings"
	"sync"

	fileutil "github.com/zan8in/pins/file"
)

var PoCScanProgress []string

type ScanProgress struct {
	mergedProgress  map[string]struct{} // 合并后的完整进度
	resumeProgress  []string            // 原始恢复文件中的进度
	currentProgress []string            // 当前扫描新增进度
	mutex           sync.Mutex
	saveMutex       sync.Mutex
}

func NewScanProgress(resume string) (*ScanProgress, error) {
	sp := &ScanProgress{
		mergedProgress:  make(map[string]struct{}),
		resumeProgress:  make([]string, 0),
		currentProgress: make([]string, 0),
	}

	if len(resume) > 0 {
		if rsChan, err := fileutil.ReadFile(resume); err == nil {
			for r := range rsChan {
				list := strings.Split(r, ",")
				for _, id := range list {
					sp.mergedProgress[id] = struct{}{}
					sp.resumeProgress = append(sp.resumeProgress, id)
				}
			}
		}
	}

	return sp, nil
}

func (p *ScanProgress) Increment(id string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if _, exists := p.mergedProgress[id]; !exists {
		p.mergedProgress[id] = struct{}{}
		p.currentProgress = append(p.currentProgress, id)
	}
}

func (p *ScanProgress) Contains(id string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, exists := p.mergedProgress[id]
	return exists
}

// func (p *ScanProgress) String() string {
// 	return strings.Join(p.progress, ",")
// }

// 新增方法：原子化保存到指定文件
func (p *ScanProgress) AtomicSave(filename string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 合并历史进度和当前进度
	fullProgress := append(p.resumeProgress, p.currentProgress...)
	data := strings.Join(fullProgress, ",")

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
